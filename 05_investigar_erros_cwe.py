"""
Script para investigar erros específicos de CWE
Foca nos casos onde o LLM errou a classificação
"""
import json

ARQUIVO_RESULTADOS = "resultados_teste_stride_melhorado.json"

def investigar_erros_cwe():
    print("=" * 80)
    print("🔍 INVESTIGAÇÃO DETALHADA DE ERROS CWE")
    print("=" * 80)
    
    # Carregar resultados
    try:
        with open(ARQUIVO_RESULTADOS, 'r', encoding='utf-8') as f:
            resultados = json.load(f)
    except FileNotFoundError:
        print(f"❌ Arquivo {ARQUIVO_RESULTADOS} não encontrado")
        return
    
    erros_por_cwe = {}
    
    for teste in resultados:
        resultado_llm = teste.get('resultado_llm', {})
        
        # Pular erros de execução
        if 'erro' in teste or 'error' in resultado_llm:
            continue
        
        # Extrair ground truth
        try:
            ground_truth = json.loads(teste.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
            cwe_nome = ground_truth.get('weakness', {}).get('name', '')
        except:
            continue
        
        # Extrair predição LLM
        cwe_predito = resultado_llm.get('cwe_id', 'None')
        explicacao = resultado_llm.get('explanation', '')
        stride_predito = resultado_llm.get('stride', 'Unknown')
        
        # Registrar erros
        if cwe_esperado != cwe_predito:
            if cwe_esperado not in erros_por_cwe:
                erros_por_cwe[cwe_esperado] = {
                    'nome': cwe_nome,
                    'casos': []
                }
            
            erros_por_cwe[cwe_esperado]['casos'].append({
                'teste_idx': teste.get('teste_idx'),
                'cwe_predito': cwe_predito,
                'stride_predito': stride_predito,
                'explicacao': explicacao[:300],
                'codigo_trecho': teste.get('codigo_input', '')[:400]
            })
    
    # Mostrar erros
    if not erros_por_cwe:
        print("\n✅ Nenhum erro de CWE encontrado!")
        return
    
    for cwe, dados in sorted(erros_por_cwe.items()):
        print(f"\n{'='*80}")
        print(f"❌ {cwe}: {dados['nome']}")
        print(f"{'='*80}")
        print(f"Total de erros: {len(dados['casos'])}\n")
        
        for i, caso in enumerate(dados['casos'], 1):
            print(f"--- Erro #{i} (Teste #{caso['teste_idx']}) ---")
            print(f"CWE Esperado: {cwe}")
            print(f"CWE Predito:  {caso['cwe_predito']}")
            print(f"STRIDE:       {caso['stride_predito']}")
            print(f"\nExplicação LLM:")
            print(f"{caso['explicacao']}...")
            print(f"\nTrecho do código:")
            print(f"{caso['codigo_trecho']}...")
            print()
    
    # Estatísticas gerais
    print("\n" + "="*80)
    print("📊 RESUMO DE ERROS CWE")
    print("="*80)
    
    total_erros = sum(len(d['casos']) for d in erros_por_cwe.values())
    print(f"\nTotal de erros: {total_erros}")
    print(f"CWEs com erros: {len(erros_por_cwe)}\n")
    
    for cwe, dados in sorted(erros_por_cwe.items(), key=lambda x: len(x[1]['casos']), reverse=True):
        print(f"{cwe:<12} {len(dados['casos'])} erro(s) - {dados['nome'][:50]}")
    
    # Análise de confusão CWE
    print("\n" + "="*80)
    print("🔄 MATRIZ DE CONFUSÃO CWE (Esperado → Predito)")
    print("="*80)
    
    confusao = {}
    for cwe, dados in erros_por_cwe.items():
        for caso in dados['casos']:
            chave = f"{cwe} → {caso['cwe_predito']}"
            confusao[chave] = confusao.get(chave, 0) + 1
    
    for conf, count in sorted(confusao.items(), key=lambda x: x[1], reverse=True):
        print(f"{conf}: {count} caso(s)")

if __name__ == "__main__":
    investigar_erros_cwe()
