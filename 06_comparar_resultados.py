"""
Script para comparar resultados antes e depois da melhoria do prompt STRIDE
"""
import json
from collections import Counter, defaultdict

ARQUIVO_ANTIGO = "resultados_teste.json"
ARQUIVO_NOVO = "resultados_teste_stride_melhorado.json"

def extrair_stride(resultado_llm):
    """Extrai categoria STRIDE da resposta do LLM"""
    if isinstance(resultado_llm, dict):
        # Tentar raw_response se houver erro
        if 'error' in resultado_llm and 'raw_response' in resultado_llm:
            try:
                resposta_texto = resultado_llm['raw_response'].strip()
                if resposta_texto.startswith("```json"):
                    resposta_texto = resposta_texto.split("```json")[1].split("```")[0]
                elif resposta_texto.startswith("```"):
                    resposta_texto = resposta_texto.split("```")[1]
                    if resposta_texto.startswith("json"):
                        resposta_texto = resposta_texto[4:]
                    resposta_texto = resposta_texto.split("```")[0]
                
                resultado_llm = json.loads(resposta_texto.strip())
            except:
                return 'Unknown'
        
        return resultado_llm.get('stride', 'Unknown')
    return 'Unknown'

def extrair_stride_gt(ground_truth_str):
    """Extrai STRIDE do ground truth"""
    try:
        gt_data = json.loads(ground_truth_str)
        stride_list = gt_data.get('threat_model', {}).get('stride_categories', [])
        return stride_list[0] if stride_list else 'Unknown'
    except:
        return 'Unknown'

def comparar_resultados():
    print("=" * 80)
    print("📊 COMPARAÇÃO: ANTES vs DEPOIS - Melhoria STRIDE")
    print("=" * 80)
    
    # Carregar arquivos
    try:
        with open(ARQUIVO_ANTIGO, 'r', encoding='utf-8') as f:
            resultados_antigos = json.load(f)
        print(f"\n✓ Resultados ANTIGOS carregados: {len(resultados_antigos)} testes")
    except FileNotFoundError:
        print(f"\n❌ Arquivo {ARQUIVO_ANTIGO} não encontrado")
        return
    
    try:
        with open(ARQUIVO_NOVO, 'r', encoding='utf-8') as f:
            resultados_novos = json.load(f)
        print(f"✓ Resultados NOVOS carregados: {len(resultados_novos)} testes")
    except FileNotFoundError:
        print(f"\n❌ Arquivo {ARQUIVO_NOVO} não encontrado")
        print("Execute primeiro: python 05_retreinar_stride.py")
        return
    
    # Análise STRIDE
    print("\n" + "=" * 80)
    print("ANÁLISE DE STRIDE")
    print("=" * 80)
    
    # Contadores
    stride_antigo = Counter()
    stride_novo = Counter()
    stride_gt = Counter()
    
    # Matrizes de confusão
    matriz_antiga = defaultdict(lambda: defaultdict(int))
    matriz_nova = defaultdict(lambda: defaultdict(int))
    
    # Acertos
    acertos_antigos = 0
    acertos_novos = 0
    total_casos = 0
    
    melhorias = []
    pioras = []
    
    for idx, (item_antigo, item_novo) in enumerate(zip(resultados_antigos, resultados_novos)):
        gt_str = item_antigo.get('ground_truth', '{}')
        stride_verdadeiro = extrair_stride_gt(gt_str)
        
        if stride_verdadeiro == 'Unknown':
            continue
        
        total_casos += 1
        stride_gt[stride_verdadeiro] += 1
        
        stride_pred_antigo = extrair_stride(item_antigo.get('resultado_llm', {}))
        stride_pred_novo = extrair_stride(item_novo.get('resultado_llm', {}))
        
        stride_antigo[stride_pred_antigo] += 1
        stride_novo[stride_pred_novo] += 1
        
        matriz_antiga[stride_verdadeiro][stride_pred_antigo] += 1
        matriz_nova[stride_verdadeiro][stride_pred_novo] += 1
        
        # Verificar acertos
        acertou_antigo = (stride_verdadeiro == stride_pred_antigo)
        acertou_novo = (stride_verdadeiro == stride_pred_novo)
        
        if acertou_antigo:
            acertos_antigos += 1
        if acertou_novo:
            acertos_novos += 1
        
        # Detectar melhorias/pioras
        if not acertou_antigo and acertou_novo:
            melhorias.append({
                'idx': idx,
                'gt': stride_verdadeiro,
                'antigo': stride_pred_antigo,
                'novo': stride_pred_novo
            })
        elif acertou_antigo and not acertou_novo:
            pioras.append({
                'idx': idx,
                'gt': stride_verdadeiro,
                'antigo': stride_pred_antigo,
                'novo': stride_pred_novo
            })
    
    # Relatório
    print(f"\nTotal de casos analisados: {total_casos}")
    
    print("\n--- DISTRIBUIÇÃO GROUND TRUTH ---")
    for stride, count in stride_gt.most_common():
        print(f"  {stride:<30} {count:>3} casos ({count/total_casos*100:.1f}%)")
    
    print("\n--- PREDIÇÕES ANTIGAS ---")
    acuracia_antiga = (acertos_antigos / total_casos * 100) if total_casos > 0 else 0
    print(f"Acurácia: {acuracia_antiga:.1f}% ({acertos_antigos}/{total_casos})")
    for stride, count in stride_antigo.most_common():
        print(f"  {stride:<30} {count:>3} predições")
    
    print("\n--- PREDIÇÕES NOVAS ---")
    acuracia_nova = (acertos_novos / total_casos * 100) if total_casos > 0 else 0
    print(f"Acurácia: {acuracia_nova:.1f}% ({acertos_novos}/{total_casos})")
    for stride, count in stride_novo.most_common():
        print(f"  {stride:<30} {count:>3} predições")
    
    # Comparação
    print("\n" + "=" * 80)
    print("📈 COMPARAÇÃO DE DESEMPENHO")
    print("=" * 80)
    
    delta_acuracia = acuracia_nova - acuracia_antiga
    delta_acertos = acertos_novos - acertos_antigos
    
    if delta_acuracia > 0:
        emoji = "📈 ✅"
        print(f"\n{emoji} MELHORIA: +{delta_acuracia:.1f}% ({delta_acertos:+d} acertos)")
    elif delta_acuracia < 0:
        emoji = "📉 ⚠️"
        print(f"\n{emoji} PIORA: {delta_acuracia:.1f}% ({delta_acertos:+d} acertos)")
    else:
        emoji = "➡️"
        print(f"\n{emoji} SEM MUDANÇA: {delta_acuracia:.1f}%")
    
    print(f"\nAcurácia Antiga: {acuracia_antiga:.1f}%")
    print(f"Acurácia Nova:   {acuracia_nova:.1f}%")
    
    # Detalhamento de mudanças
    if melhorias:
        print(f"\n🎯 CASOS QUE MELHORARAM: {len(melhorias)}")
        analise_melhorias = Counter([m['gt'] for m in melhorias])
        for stride, count in analise_melhorias.most_common():
            print(f"  {stride}: {count} casos agora corretos")
    
    if pioras:
        print(f"\n⚠️  CASOS QUE PIORARAM: {len(pioras)}")
        analise_pioras = Counter([p['gt'] for p in pioras])
        for stride, count in analise_pioras.most_common():
            print(f"  {stride}: {count} casos agora errados")
    
    # Análise por categoria STRIDE
    print("\n" + "=" * 80)
    print("📊 DESEMPENHO POR CATEGORIA STRIDE")
    print("=" * 80)
    
    print(f"\n{'Categoria':<30} {'Antigo':<15} {'Novo':<15} {'Mudança'}")
    print("-" * 75)
    
    for stride in sorted(stride_gt.keys()):
        total_stride = stride_gt[stride]
        acertos_ant = matriz_antiga[stride][stride]
        acertos_nov = matriz_nova[stride][stride]
        
        acc_ant = (acertos_ant / total_stride * 100) if total_stride > 0 else 0
        acc_nov = (acertos_nov / total_stride * 100) if total_stride > 0 else 0
        delta = acc_nov - acc_ant
        
        delta_str = f"{delta:+.1f}%"
        if delta > 0:
            delta_str = f"✅ {delta_str}"
        elif delta < 0:
            delta_str = f"❌ {delta_str}"
        else:
            delta_str = f"➡️  {delta_str}"
        
        print(f"{stride:<30} {acc_ant:>5.1f}% ({acertos_ant}/{total_stride})   "
              f"{acc_nov:>5.1f}% ({acertos_nov}/{total_stride})   {delta_str}")
    
    # Matriz de confusão resumida
    print("\n" + "=" * 80)
    print("🔄 PRINCIPAIS CONFUSÕES (NOVO)")
    print("=" * 80)
    
    print("\nCasos onde o modelo errou:")
    for stride_real in sorted(stride_gt.keys()):
        erros = [(pred, count) for pred, count in matriz_nova[stride_real].items() 
                 if pred != stride_real and count > 0]
        if erros:
            erros_sorted = sorted(erros, key=lambda x: x[1], reverse=True)
            print(f"\n{stride_real}:")
            for pred, count in erros_sorted:
                print(f"  → confundiu com {pred}: {count} casos")
    
    print("\n" + "=" * 80)
    print("✅ ANÁLISE CONCLUÍDA")
    print("=" * 80)

if __name__ == "__main__":
    comparar_resultados()
