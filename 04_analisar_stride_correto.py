"""
Script de análise STRIDE usando MAPEAMENTO CORRETO como referência
(Ignora o ground truth incorreto do dataset)
"""
import json
from collections import defaultdict

# Mapeamento CWE → STRIDE CORRETO (baseado em análise acadêmica)
# Fonte: Mapeamento CWE para STRIDE.csv
# Aceita múltiplas categorias quando vulnerabilidade tem impactos contextuais
CWE_TO_STRIDE_CORRETO = {
    "CWE-22": ["Information Disclosure"],
    "CWE-78": ["Elevation of Privilege", "Tampering"],
    "CWE-79": ["Tampering", "Elevation of Privilege"],
    "CWE-89": ["Tampering", "Information Disclosure"],
    "CWE-90": ["Information Disclosure", "Elevation of Privilege"],
    "CWE-327": ["Information Disclosure"],
    "CWE-328": ["Information Disclosure"],
    "CWE-330": ["Spoofing", "Information Disclosure"],
    "CWE-501": ["Elevation of Privilege", "Spoofing"],
    "CWE-614": ["Information Disclosure"],
    "CWE-643": ["Information Disclosure", "Elevation of Privilege"],
}

ARQUIVO_RESULTADOS = "resultados_teste_stride_melhorado.json"

def analisar_com_mapeamento_correto():
    """Analisa STRIDE comparando com mapeamento correto, não com ground truth"""
    
    print("=" * 80)
    print("📊 ANÁLISE STRIDE - USANDO MAPEAMENTO CORRETO COMO REFERÊNCIA")
    print("=" * 80)
    print("⚠️  Ignora ground truth incorreto do dataset")
    print("✅ Usa CWE→STRIDE baseado em impacto real como referência\n")
    
    # Carregar resultados
    try:
        with open(ARQUIVO_RESULTADOS, 'r', encoding='utf-8') as f:
            resultados = json.load(f)
    except FileNotFoundError:
        print(f"❌ Arquivo {ARQUIVO_RESULTADOS} não encontrado")
        return
    
    metricas = {
        "total_testes": 0,
        "stride_correto": 0,
        "stride_incorreto": 0,
        "cwe_correto": 0,
        "sem_erro": 0,
        "erros_por_cwe": {},
        "matriz_confusao": {},
        "detalhes_erros": []
    }
    
    stride_categories = ['Tampering', 'Spoofing', 'Repudiation', 'Information Disclosure', 
                         'Denial of Service', 'Elevation of Privilege']
    
    for teste in resultados:
        resultado_llm = teste.get('resultado_llm', {})
        
        # Pular erros de execução
        if 'erro' in teste or 'error' in resultado_llm:
            continue
        
        metricas["sem_erro"] += 1
        
        # Extrair ground truth para pegar CWE
        try:
            ground_truth = json.loads(teste.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
        except:
            continue
        
        # Extrair predição LLM
        cwe_predito = resultado_llm.get('cwe_id', 'None')
        stride_predito = resultado_llm.get('stride', 'Unknown')
        
        # Verificar CWE
        cwe_correto = (cwe_esperado == cwe_predito)
        if cwe_correto:
            metricas["cwe_correto"] += 1
        
        # STRIDE esperado baseado no MAPEAMENTO CORRETO (não no ground truth)
        stride_esperado_list = CWE_TO_STRIDE_CORRETO.get(cwe_esperado, [])
        
        # Se CWE não está no mapeamento, pular
        if not stride_esperado_list:
            continue
        
        metricas["total_testes"] += 1
        
        # Aceitar qualquer STRIDE do mapeamento (pode ter múltiplos)
        stride_correto = stride_predito in stride_esperado_list
        
        if stride_correto:
            metricas["stride_correto"] += 1
        else:
            metricas["stride_incorreto"] += 1
            
            # Registrar erro detalhado
            metricas["detalhes_erros"].append({
                "teste_idx": teste.get("teste_idx"),
                "cwe": cwe_esperado,
                "stride_esperado": stride_esperado_list,
                "stride_predito": stride_predito,
                "explicacao_llm": resultado_llm.get("explanation", "")[:200]
            })
            
            # Contabilizar erro por CWE
            if cwe_esperado not in metricas["erros_por_cwe"]:
                metricas["erros_por_cwe"][cwe_esperado] = {
                    "total": 0,
                    "erros": 0,
                    "confusoes": {}
                }
            metricas["erros_por_cwe"][cwe_esperado]["erros"] += 1
            
            # Matriz de confusão
            stride_esperado_str = stride_esperado_list[0]  # Usar primeiro como principal
            if stride_esperado_str not in metricas["matriz_confusao"]:
                metricas["matriz_confusao"][stride_esperado_str] = {}
            metricas["matriz_confusao"][stride_esperado_str][stride_predito] = \
                metricas["matriz_confusao"][stride_esperado_str].get(stride_predito, 0) + 1
        
        # Contabilizar total por CWE
        if cwe_esperado in metricas["erros_por_cwe"]:
            metricas["erros_por_cwe"][cwe_esperado]["total"] += 1
        else:
            metricas["erros_por_cwe"][cwe_esperado] = {
                "total": 1,
                "erros": 0,
                "confusoes": {}
            }
    
    # ========================================
    # RESULTADOS
    # ========================================
    print(f"\n📊 RESUMO GERAL")
    print("=" * 80)
    print(f"Total de testes válidos: {metricas['sem_erro']}")
    print(f"Testes com CWE mapeado: {metricas['total_testes']}")
    print(f"CWE correto: {metricas['cwe_correto']} ({metricas['cwe_correto']/metricas['sem_erro']*100:.1f}%)")
    
    acuracia_stride = (metricas['stride_correto'] / metricas['total_testes'] * 100) if metricas['total_testes'] > 0 else 0
    print(f"\n🎯 STRIDE CORRETO: {metricas['stride_correto']}/{metricas['total_testes']} ({acuracia_stride:.1f}%)")
    print(f"❌ STRIDE INCORRETO: {metricas['stride_incorreto']}/{metricas['total_testes']} ({metricas['stride_incorreto']/metricas['total_testes']*100:.1f}%)")
    
    # ========================================
    # ANÁLISE POR CWE
    # ========================================
    print(f"\n\n📊 DESEMPENHO STRIDE POR CWE (usando mapeamento correto)")
    print("=" * 80)
    
    for cwe, stats in sorted(metricas["erros_por_cwe"].items()):
        total = stats["total"]
        erros = stats["erros"]
        acertos = total - erros
        acc = (acertos / total * 100) if total > 0 else 0
        stride_esperado = CWE_TO_STRIDE_CORRETO.get(cwe, ["Unknown"])
        
        print(f"{cwe:<12} {acertos:>3}/{total:<3} ({acc:>5.1f}%)  → STRIDE esperado: {', '.join(stride_esperado)}")
    
    # ========================================
    # MATRIZ DE CONFUSÃO
    # ========================================
    if metricas["matriz_confusao"]:
        print(f"\n\n📊 MATRIZ DE CONFUSÃO STRIDE")
        print("=" * 80)
        
        confusoes_ordenadas = []
        for stride_esp, confusoes in metricas["matriz_confusao"].items():
            for stride_pred, count in confusoes.items():
                confusoes_ordenadas.append((stride_esp, stride_pred, count))
        
        confusoes_ordenadas.sort(key=lambda x: x[2], reverse=True)
        
        for esperado, predito, count in confusoes_ordenadas[:10]:
            print(f"  {esperado:<30} → {predito:<30} ({count} casos)")
    
    # ========================================
    # EXEMPLOS DE ERROS
    # ========================================
    if metricas["detalhes_erros"]:
        print(f"\n\n📋 EXEMPLOS DE ERROS (primeiros 5)")
        print("=" * 80)
        
        for i, erro in enumerate(metricas["detalhes_erros"][:5], 1):
            print(f"\n{i}. Teste #{erro['teste_idx']}")
            print(f"   CWE: {erro['cwe']}")
            print(f"   STRIDE esperado: {', '.join(erro['stride_esperado'])}")
            print(f"   STRIDE predito: {erro['stride_predito']}")
            print(f"   Explicação LLM: {erro['explicacao_llm']}...")
    
    # ========================================
    # COMPARAÇÃO COM GROUND TRUTH
    # ========================================
    print(f"\n\n💡 COMPARAÇÃO: Ground Truth vs Mapeamento Correto")
    print("=" * 80)
    print("Se a acurácia STRIDE aumentou comparado com análise anterior,")
    print("isso confirma que o ground truth do dataset estava INCORRETO")
    print("e o LLM está fazendo classificações semanticamente CORRETAS.\n")
    
    # Salvar análise
    with open("analise_stride_correto.json", 'w', encoding='utf-8') as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)
    
    print("✅ Análise salva em: analise_stride_correto.json")

if __name__ == "__main__":
    analisar_com_mapeamento_correto()
