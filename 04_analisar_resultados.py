# 04_analisar_resultados.py
import json
import os
from collections import defaultdict, Counter
from typing import Dict, List, Tuple

# --- CONFIGURAÇÕES ---
ARQUIVO_RESULTADOS = "resultados_teste.json"
ARQUIVO_DATASET_TESTE = "dataset_teste_reservado.jsonl"

def extrair_cwe_do_ground_truth(ground_truth_str: str) -> str:
    """Extrai o CWE ID do ground truth (que vem como string JSON)"""
    try:
        gt_data = json.loads(ground_truth_str)
        return gt_data.get('weakness', {}).get('id', 'Unknown')
    except (json.JSONDecodeError, AttributeError):
        return 'Unknown'

def extrair_cwe_do_llm(resultado_llm: dict) -> str:
    """Extrai o CWE ID da resposta do LLM"""
    # Se tem erro mas tem raw_response, tenta extrair JSON de dentro de markdown
    if 'error' in resultado_llm and 'raw_response' in resultado_llm:
        try:
            raw = resultado_llm['raw_response']
            # Remover blocos de código markdown
            if '```json' in raw:
                raw = raw.split('```json')[1].split('```')[0].strip()
            elif '```' in raw:
                raw = raw.split('```')[1].split('```')[0].strip()
            
            parsed = json.loads(raw)
            return parsed.get('cwe_id', 'None')
        except:
            return 'Error'
    
    if 'error' in resultado_llm and 'raw_response' not in resultado_llm:
        return 'Error'
    
    return resultado_llm.get('cwe_id', 'None')

def extrair_verdict_do_ground_truth(ground_truth_str: str) -> str:
    """Extrai o verdict do ground truth"""
    try:
        gt_data = json.loads(ground_truth_str)
        return gt_data.get('verdict', 'Unknown')
    except (json.JSONDecodeError, AttributeError):
        return 'Unknown'

def extrair_verdict_do_llm(resultado_llm: dict) -> str:
    """Extrai o verdict da resposta do LLM"""
    # Se tem erro mas tem raw_response, tenta extrair JSON de dentro de markdown
    if 'error' in resultado_llm and 'raw_response' in resultado_llm:
        try:
            raw = resultado_llm['raw_response']
            # Remover blocos de código markdown
            if '```json' in raw:
                raw = raw.split('```json')[1].split('```')[0].strip()
            elif '```' in raw:
                raw = raw.split('```')[1].split('```')[0].strip()
            
            parsed = json.loads(raw)
            return parsed.get('verdict', 'Unknown')
        except:
            return 'Error'
    
    if 'error' in resultado_llm and 'raw_response' not in resultado_llm:
        return 'Error'
    
    return resultado_llm.get('verdict', 'Unknown')

def extrair_stride_do_ground_truth(ground_truth_str: str) -> str:
    """Extrai o STRIDE do ground truth"""
    try:
        gt_data = json.loads(ground_truth_str)
        stride_list = gt_data.get('threat_model', {}).get('stride_categories', [])
        return stride_list[0] if stride_list else 'Unknown'
    except (json.JSONDecodeError, AttributeError, IndexError):
        return 'Unknown'

def extrair_stride_do_llm(resultado_llm: dict) -> str:
    """Extrai o STRIDE da resposta do LLM"""
    # Se tem erro mas tem raw_response, tenta extrair JSON de dentro de markdown
    if 'error' in resultado_llm and 'raw_response' in resultado_llm:
        try:
            raw = resultado_llm['raw_response']
            if '```json' in raw:
                raw = raw.split('```json')[1].split('```')[0].strip()
            elif '```' in raw:
                raw = raw.split('```')[1].split('```')[0].strip()
            
            parsed = json.loads(raw)
            return parsed.get('stride', 'Unknown')
        except:
            return 'Unknown'
    
    if 'error' in resultado_llm and 'raw_response' not in resultado_llm:
        return 'Unknown'
    
    return resultado_llm.get('stride', 'Unknown')

def calcular_metricas_por_cwe(resultados: List[dict]) -> Dict:
    """Calcula métricas detalhadas para cada CWE"""
    
    # Estrutura: {CWE_ID: {TP, FP, FN, TN, total_casos}}
    metricas_cwe = defaultdict(lambda: {
        'TP': 0,  # True Positive: previu correto E é vulnerável
        'FP': 0,  # False Positive: previu vulnerável mas é safe
        'FN': 0,  # False Negative: previu safe mas é vulnerável
        'TN': 0,  # True Negative: previu safe E é safe
        'total_gt': 0,  # Total de casos com esse CWE no ground truth
        'total_pred': 0,  # Total de casos previstos como esse CWE
        'acertos': 0,  # Acertos exatos (CWE correto + Verdict correto)
        'acertos_cwe_isolado': 0,  # Acertos de CWE independente do verdict
    })
    
    # Métricas gerais de VERDICT (VULNERABLE vs SAFE)
    metricas_verdict = {
        'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0
    }
    
    # Métricas de STRIDE
    metricas_stride = defaultdict(lambda: {'corretos': 0, 'total': 0})
    matriz_confusao_stride = defaultdict(lambda: defaultdict(int))
    
    total_testes = 0
    total_erros = 0
    
    for item in resultados:
        total_testes += 1
        
        ground_truth_str = item.get('ground_truth', '{}')
        resultado_llm = item.get('resultado_llm', {})
        
        # Verificar se há erro REAL (não conseguiu extrair nada)
        if 'erro' in item:
            total_erros += 1
            continue
        
        if not isinstance(resultado_llm, dict):
            total_erros += 1
            continue
            
        # Se resultado_llm tem 'error' MAS tem raw_response, tenta processar
        # Se não tem nem raw_response, é erro real
        if 'error' in resultado_llm and 'raw_response' not in resultado_llm:
            total_erros += 1
            continue
        
        # Extrair dados
        cwe_gt = extrair_cwe_do_ground_truth(ground_truth_str)
        cwe_pred = extrair_cwe_do_llm(resultado_llm)
        verdict_gt = extrair_verdict_do_ground_truth(ground_truth_str)
        verdict_pred = extrair_verdict_do_llm(resultado_llm)
        stride_gt = extrair_stride_do_ground_truth(ground_truth_str)
        stride_pred = extrair_stride_do_llm(resultado_llm)
        
        if cwe_gt == 'Unknown' or verdict_gt == 'Unknown':
            continue
        
        # Métricas de VERDICT (binário: VULNERABLE vs SAFE)
        if verdict_gt == 'VULNERABLE' and verdict_pred == 'VULNERABLE':
            metricas_verdict['TP'] += 1
        elif verdict_gt == 'SAFE' and verdict_pred == 'VULNERABLE':
            metricas_verdict['FP'] += 1
        elif verdict_gt == 'VULNERABLE' and verdict_pred == 'SAFE':
            metricas_verdict['FN'] += 1
        elif verdict_gt == 'SAFE' and verdict_pred == 'SAFE':
            metricas_verdict['TN'] += 1
        
        # Métricas por CWE (apenas para casos VULNERABLE no GT)
        if verdict_gt == 'VULNERABLE':
            metricas_cwe[cwe_gt]['total_gt'] += 1
            
            # Acerto de CWE ISOLADO (independente do verdict)
            if cwe_pred == cwe_gt:
                metricas_cwe[cwe_gt]['acertos_cwe_isolado'] += 1
            
            if verdict_pred == 'VULNERABLE':
                if cwe_pred == cwe_gt:
                    metricas_cwe[cwe_gt]['TP'] += 1
                    metricas_cwe[cwe_gt]['acertos'] += 1
                else:
                    # Previu vulnerável mas CWE errado
                    metricas_cwe[cwe_gt]['FP'] += 1
                    metricas_cwe[cwe_pred]['FP'] += 1
            else:
                # Previu SAFE quando era VULNERABLE
                metricas_cwe[cwe_gt]['FN'] += 1
        
        # Contar predições por CWE
        if verdict_pred == 'VULNERABLE' and cwe_pred != 'None':
            metricas_cwe[cwe_pred]['total_pred'] += 1
        
        # Métricas de STRIDE
        if verdict_gt == 'VULNERABLE' and stride_gt != 'Unknown':
            metricas_stride[stride_gt]['total'] += 1
            matriz_confusao_stride[stride_gt][stride_pred] += 1
            
            if stride_gt == stride_pred:
                metricas_stride[stride_gt]['corretos'] += 1
    
    return metricas_cwe, metricas_verdict, metricas_stride, matriz_confusao_stride, total_testes, total_erros

def calcular_metricas_finais(tp: int, fp: int, fn: int, tn: int) -> Dict:
    """Calcula precisão, recall, F1 dados TP, FP, FN, TN"""
    
    # Precisão: dos que previu como positivo, quantos realmente são?
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    
    # Recall: dos positivos reais, quantos identificou?
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    
    # F1-Score: média harmônica
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    
    # Acurácia: total de acertos / total de casos
    accuracy = ((tp + tn) / (tp + fp + fn + tn) * 100) if (tp + fp + fn + tn) > 0 else 0.0
    
    return {
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'accuracy': accuracy,
        'TP': tp,
        'FP': fp,
        'FN': fn,
        'TN': tn
    }

def analisar_distribuicao_dataset(resultados: List[dict]) -> Dict:
    """Analisa a distribuição de CWEs no dataset"""
    distribuicao = Counter()
    
    for item in resultados:
        ground_truth_str = item.get('ground_truth', '{}')
        try:
            gt_data = json.loads(ground_truth_str)
            verdict = gt_data.get('verdict', 'Unknown')
            
            if verdict == 'VULNERABLE':
                cwe = gt_data.get('weakness', {}).get('id', 'Unknown')
                distribuicao[cwe] += 1
        except:
            continue
    
    return dict(distribuicao)

def carregar_resultados(arquivo: str) -> List[dict]:
    """Carrega resultados dos testes"""
    with open(arquivo, 'r', encoding='utf-8') as f:
        return json.load(f)

def gerar_relatorio(arquivo_resultados: str = 'resultados_teste.json'):
    """Gera relatório completo com todas as análises"""
    
    print("=" * 80)
    print("RELATÓRIO COMPLETO DE ANÁLISE DE RESULTADOS")
    print("=" * 80)
    
    # Carregar resultados
    print("\n1. Carregando resultados...")
    resultados = carregar_resultados(arquivo_resultados)
    print(f"   ✓ {len(resultados)} testes carregados")
    
    # Análise de distribuição do dataset
    print("\n2. Analisando distribuição do dataset...")
    distribuicao = analisar_distribuicao_dataset(resultados)
    
    # Calcular métricas completas
    print("\n3. Calculando métricas...")
    metricas_cwe, metricas_verdict, metricas_stride, matriz_confusao_stride, total_testes, total_erros = calcular_metricas_por_cwe(resultados)
    
    metricas_finais = {}
    metricas_cwe_isolado = {}
    
    # Calcular métricas finais para cada CWE
    for cwe, valores in metricas_cwe.items():
        metricas_finais[cwe] = calcular_metricas_finais(
            valores['TP'], 
            valores['FP'], 
            valores['FN'], 
            valores['TN']
        )
        metricas_finais[cwe]['total_gt'] = valores['total_gt']
        metricas_finais[cwe]['total_pred'] = valores['total_pred']
        metricas_finais[cwe]['acertos'] = valores['acertos']
        
        # Métricas de CWE isolado (reconhecimento independente do verdict)
        if valores['total_gt'] > 0:
            acuracia_cwe = (valores['acertos_cwe_isolado'] / valores['total_gt']) * 100
        else:
            acuracia_cwe = 0
        
        metricas_cwe_isolado[cwe] = {
            'acertos': valores['acertos_cwe_isolado'],
            'total': valores['total_gt'],
            'acuracia': acuracia_cwe
        }
    
    # Calcular métricas de VERDICT isolado
    metricas_verdict_finais = calcular_metricas_finais(
        metricas_verdict['TP'],
        metricas_verdict['FP'],
        metricas_verdict['FN'],
        metricas_verdict['TN']
    )
    
    # Calcular métricas de STRIDE
    metricas_stride_finais = {}
    for stride, valores in metricas_stride.items():
        if valores['total'] > 0:
            acuracia = (valores['corretos'] / valores['total']) * 100
        else:
            acuracia = 0
        
        metricas_stride_finais[stride] = {
            'corretos': valores['corretos'],
            'total': valores['total'],
            'acuracia': acuracia
        }
    
    # ============================================================================
    # RELATÓRIO - DISTRIBUIÇÃO DO DATASET
    # ============================================================================
    print("\n" + "=" * 80)
    print("DISTRIBUIÇÃO DO DATASET DE TESTE")
    print("=" * 80)
    print(f"\nTotal de testes: {total_testes}")
    print(f"Testes processados com sucesso: {total_testes - total_erros}")
    print(f"Erros: {total_erros}")
    print(f"\nDistribuição por CWE:")
    print(f"{'CWE':<15} {'Quantidade':<12} {'Percentual'}")
    print("-" * 50)
    
    dist_sorted = sorted(distribuicao.items(), key=lambda x: x[1], reverse=True)
    for cwe, qtd in dist_sorted:
        percentual = (qtd / sum(distribuicao.values())) * 100 if sum(distribuicao.values()) > 0 else 0
        print(f"{cwe:<15} {qtd:<12} {percentual:>6.1f}%")
    
    # ============================================================================
    # RELATÓRIO - ANÁLISE 1: RECONHECIMENTO DE CWE (ISOLADO)
    # ============================================================================
    print("\n" + "=" * 80)
    print("ANÁLISE 1: RECONHECIMENTO DE CWE (Independente do Verdict)")
    print("=" * 80)
    print("\nMede a capacidade do modelo de identificar CORRETAMENTE o tipo de CWE,")
    print("independente de classificar como VULNERABLE ou SAFE.\n")
    
    print(f"{'CWE':<15} {'Acertos':<10} {'Total':<10} {'Acurácia'}")
    print("-" * 55)
    
    cwe_isolado_sorted = sorted(metricas_cwe_isolado.items(), 
                                 key=lambda x: x[1]['acuracia'], 
                                 reverse=True)
    
    total_acertos_cwe = sum(v['acertos'] for v in metricas_cwe_isolado.values())
    total_casos_cwe = sum(v['total'] for v in metricas_cwe_isolado.values())
    
    for cwe, valores in cwe_isolado_sorted:
        print(f"{cwe:<15} {valores['acertos']:<10} {valores['total']:<10} {valores['acuracia']:>6.1f}%")
    
    print("-" * 55)
    acuracia_geral_cwe = (total_acertos_cwe / total_casos_cwe * 100) if total_casos_cwe > 0 else 0
    print(f"{'TOTAL':<15} {total_acertos_cwe:<10} {total_casos_cwe:<10} {acuracia_geral_cwe:>6.1f}%")
    
    # ============================================================================
    # RELATÓRIO - ANÁLISE 2: CLASSIFICAÇÃO DE VERDICT (ISOLADO)
    # ============================================================================
    print("\n" + "=" * 80)
    print("ANÁLISE 2: CLASSIFICAÇÃO DE VERDICT (VULNERABLE vs SAFE)")
    print("=" * 80)
    print("\nMede a capacidade do modelo de distinguir código vulnerável de código seguro,")
    print("independente de identificar corretamente o tipo de CWE.\n")
    
    print(f"Precisão:  {metricas_verdict_finais['precision']:.1f}%")
    print(f"Recall:    {metricas_verdict_finais['recall']:.1f}%")
    print(f"F1-Score:  {metricas_verdict_finais['f1_score']:.1f}%")
    print(f"Acurácia:  {metricas_verdict_finais['accuracy']:.1f}%")
    
    print(f"\nMatriz de Confusão:")
    print(f"  TP (Vulnerável → Vulnerável): {metricas_verdict['TP']}")
    print(f"  FP (Safe → Vulnerável):        {metricas_verdict['FP']}")
    print(f"  FN (Vulnerável → Safe):        {metricas_verdict['FN']}")
    print(f"  TN (Safe → Safe):              {metricas_verdict['TN']}")
    
    # ============================================================================
    # RELATÓRIO - ANÁLISE 3: CWE + VERDICT (COMBINADO)
    # ============================================================================
    print("\n" + "=" * 80)
    print("ANÁLISE 3: CWE + VERDICT (Análise Combinada)")
    print("=" * 80)
    print("\nMede a capacidade do modelo de SIMULTANEAMENTE identificar o CWE correto")
    print("E classificar corretamente como VULNERABLE.\n")
    
    print(f"{'CWE':<15} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Acurácia':<12}")
    print("-" * 70)
    
    # Categorizar desempenho
    alto_desempenho = []
    medio_desempenho = []
    baixo_desempenho = []
    
    metricas_sorted = sorted(metricas_finais.items(), 
                            key=lambda x: x[1]['f1_score'], 
                            reverse=True)
    
    for cwe, valores in metricas_sorted:
        print(f"{cwe:<15} {valores['precision']:>6.1f}%      {valores['recall']:>6.1f}%      "
              f"{valores['f1_score']:>6.1f}%      {valores['accuracy']:>6.1f}%")
        
        # Categorizar
        if valores['f1_score'] >= 80:
            alto_desempenho.append(cwe)
        elif valores['f1_score'] >= 50:
            medio_desempenho.append(cwe)
        else:
            baixo_desempenho.append(cwe)
    
    # Métricas gerais (ponderadas pelo número de casos)
    total_tp = sum(metricas_cwe[cwe]['TP'] for cwe in metricas_cwe)
    total_fp = sum(metricas_cwe[cwe]['FP'] for cwe in metricas_cwe)
    total_fn = sum(metricas_cwe[cwe]['FN'] for cwe in metricas_cwe)
    total_tn = sum(metricas_cwe[cwe]['TN'] for cwe in metricas_cwe)
    
    metricas_gerais = calcular_metricas_finais(total_tp, total_fp, total_fn, total_tn)
    
    print("-" * 70)
    print(f"{'GERAL':<15} {metricas_gerais['precision']:>6.1f}%      {metricas_gerais['recall']:>6.1f}%      "
          f"{metricas_gerais['f1_score']:>6.1f}%      {metricas_gerais['accuracy']:>6.1f}%")
    
    print(f"\nCategorização de Desempenho:")
    print(f"  Alto (F1 ≥ 80%):   {len(alto_desempenho)} CWEs - {alto_desempenho}")
    print(f"  Médio (50-80%):    {len(medio_desempenho)} CWEs - {medio_desempenho}")
    print(f"  Baixo (< 50%):     {len(baixo_desempenho)} CWEs - {baixo_desempenho}")
    
    # ============================================================================
    # RELATÓRIO - ANÁLISE 4: STRIDE (Modelo de Ameaças)
    # ============================================================================
    print("\n" + "=" * 80)
    print("ANÁLISE 4: STRIDE (Modelo de Ameaças)")
    print("=" * 80)
    print("\nMede a capacidade do modelo de classificar corretamente a categoria STRIDE")
    print("das vulnerabilidades detectadas.\n")
    
    print(f"{'STRIDE':<30} {'Acertos':<10} {'Total':<10} {'Acurácia'}")
    print("-" * 65)
    
    stride_sorted = sorted(metricas_stride_finais.items(), 
                           key=lambda x: x[1]['acuracia'], 
                           reverse=True)
    
    total_acertos_stride = sum(v['corretos'] for v in metricas_stride_finais.values())
    total_casos_stride = sum(v['total'] for v in metricas_stride_finais.values())
    
    for stride, valores in stride_sorted:
        print(f"{stride:<30} {valores['corretos']:<10} {valores['total']:<10} {valores['acuracia']:>6.1f}%")
    
    print("-" * 65)
    acuracia_geral_stride = (total_acertos_stride / total_casos_stride * 100) if total_casos_stride > 0 else 0
    print(f"{'TOTAL':<30} {total_acertos_stride:<10} {total_casos_stride:<10} {acuracia_geral_stride:>6.1f}%")
    
    # Matriz de Confusão STRIDE
    print(f"\nMatriz de Confusão STRIDE:")
    header_label = 'Ground Truth \\ Predito'
    print(f"{header_label:<30}", end="")
    
    # Cabeçalho
    stride_categories = sorted(set(list(matriz_confusao_stride.keys()) + 
                                   [k for v in matriz_confusao_stride.values() for k in v.keys()]))
    
    for cat in stride_categories:
        print(f"{cat[:15]:<20}", end="")
    print()
    print("-" * (30 + 20 * len(stride_categories)))
    
    # Linhas
    for gt_stride in stride_categories:
        print(f"{gt_stride:<30}", end="")
        for pred_stride in stride_categories:
            count = matriz_confusao_stride[gt_stride].get(pred_stride, 0)
            print(f"{count:<20}", end="")
        print()
    
    # ============================================================================
    # EXPORTAR JSON
    # ============================================================================
    relatorio_completo = {
        'distribuicao_dataset': distribuicao,
        'total_testes': total_testes,
        'total_erros': total_erros,
        'analise_1_reconhecimento_cwe': {
            'metricas_por_cwe': metricas_cwe_isolado,
            'acuracia_geral': acuracia_geral_cwe,
            'total_acertos': total_acertos_cwe,
            'total_casos': total_casos_cwe
        },
        'analise_2_verdict_isolado': {
            'metricas': metricas_verdict_finais,
            'matriz_confusao': metricas_verdict
        },
        'analise_3_cwe_verdict_combinado': {
            'metricas_por_cwe': metricas_finais,
            'metricas_gerais': metricas_gerais,
            'categorias_desempenho': {
                'alto': alto_desempenho,
                'medio': medio_desempenho,
                'baixo': baixo_desempenho
            }
        },
        'analise_4_stride': {
            'metricas_por_categoria': metricas_stride_finais,
            'acuracia_geral': acuracia_geral_stride,
            'total_acertos': total_acertos_stride,
            'total_casos': total_casos_stride,
            'matriz_confusao': {k: dict(v) for k, v in matriz_confusao_stride.items()}
        }
    }
    
    # Salvar JSON
    with open('analise_completa.json', 'w', encoding='utf-8') as f:
        json.dump(relatorio_completo, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print("✓ Relatório completo salvo em: analise_completa.json")
    print("=" * 80)
    
    return relatorio_completo

if __name__ == "__main__":
    gerar_relatorio()

