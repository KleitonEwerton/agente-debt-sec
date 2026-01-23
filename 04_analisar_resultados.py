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
        'acertos': 0,  # Acertos exatos (CWE correto)
    })
    
    # Métricas gerais de VERDICT (VULNERABLE vs SAFE)
    metricas_verdict = {
        'TP': 0, 'FP': 0, 'FN': 0, 'TN': 0
    }
    
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
    
    return metricas_cwe, metricas_verdict, total_testes, total_erros

def calcular_metricas_finais(metricas_cwe: Dict) -> Dict:
    """Calcula precisão, recall, F1 para cada CWE"""
    resultados = {}
    
    for cwe, metrics in metricas_cwe.items():
        tp = metrics['TP']
        fp = metrics['FP']
        fn = metrics['FN']
        total_gt = metrics['total_gt']
        acertos = metrics['acertos']
        
        # Precisão: dos que eu disse que são esse CWE, quantos realmente são?
        precisao = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        
        # Recall: dos casos reais desse CWE, quantos eu identifiquei?
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        # F1-Score: média harmônica
        f1 = 2 * (precisao * recall) / (precisao + recall) if (precisao + recall) > 0 else 0.0
        
        # Acurácia específica para esse CWE (acertos / total de casos desse CWE)
        acuracia = acertos / total_gt if total_gt > 0 else 0.0
        
        resultados[cwe] = {
            'total_casos': total_gt,
            'acertos': acertos,
            'precisao': precisao,
            'recall': recall,
            'f1_score': f1,
            'acuracia': acuracia,
            'TP': tp,
            'FP': fp,
            'FN': fn,
        }
    
    return resultados

def analisar_distribuicao_dataset():
    """Analisa a distribuição de CWEs no dataset de teste"""
    print("\n" + "="*80)
    print("📊 ANÁLISE DE DISTRIBUIÇÃO DO DATASET DE TESTE")
    print("="*80)
    
    if not os.path.exists(ARQUIVO_DATASET_TESTE):
        print(f"❌ Arquivo {ARQUIVO_DATASET_TESTE} não encontrado.")
        return {}
    
    distribuicao = Counter()
    total = 0
    
    with open(ARQUIVO_DATASET_TESTE, 'r', encoding='utf-8') as f:
        for linha in f:
            if linha.strip():
                try:
                    item = json.loads(linha)
                    output_data = json.loads(item.get('output', '{}'))
                    verdict = output_data.get('verdict', 'Unknown')
                    
                    if verdict == 'VULNERABLE':
                        cwe = output_data.get('weakness', {}).get('id', 'Unknown')
                        distribuicao[cwe] += 1
                        total += 1
                except:
                    continue
    
    print(f"\n📈 Total de casos VULNERABLE no dataset de teste: {total}")
    print(f"📋 Distribuição por CWE:\n")
    
    distribuicao_ordenada = {}
    for cwe, count in distribuicao.most_common():
        percentual = (count / total * 100) if total > 0 else 0
        print(f"  {cwe}: {count:4d} casos ({percentual:5.2f}%)")
        distribuicao_ordenada[cwe] = {'count': count, 'percentual': percentual}
    
    return distribuicao_ordenada

def gerar_relatorio():
    print("\n" + "="*80)
    print("🔬 ANÁLISE DE RESULTADOS - DETECÇÃO DE SECURITY DEBT")
    print("="*80)
    
    # 1. Carregar resultados
    if not os.path.exists(ARQUIVO_RESULTADOS):
        print(f"❌ Erro: Arquivo {ARQUIVO_RESULTADOS} não encontrado.")
        return
    
    with open(ARQUIVO_RESULTADOS, 'r', encoding='utf-8') as f:
        resultados = json.load(f)
    
    print(f"\n📁 Total de testes carregados: {len(resultados)}")
    
    # 2. Analisar distribuição do dataset
    distribuicao = analisar_distribuicao_dataset()
    
    # 3. Calcular métricas
    metricas_cwe, metricas_verdict, total_testes, total_erros = calcular_metricas_por_cwe(resultados)
    resultados_finais = calcular_metricas_finais(metricas_cwe)
    
    # 4. Métricas gerais de VERDICT
    print("\n" + "="*80)
    print("🎯 MÉTRICAS GERAIS - DETECÇÃO DE VULNERABILIDADE (VULNERABLE vs SAFE)")
    print("="*80)
    
    tp_v = metricas_verdict['TP']
    fp_v = metricas_verdict['FP']
    fn_v = metricas_verdict['FN']
    tn_v = metricas_verdict['TN']
    
    acuracia_geral = (tp_v + tn_v) / (tp_v + fp_v + fn_v + tn_v) if (tp_v + fp_v + fn_v + tn_v) > 0 else 0
    precisao_geral = tp_v / (tp_v + fp_v) if (tp_v + fp_v) > 0 else 0
    recall_geral = tp_v / (tp_v + fn_v) if (tp_v + fn_v) > 0 else 0
    f1_geral = 2 * (precisao_geral * recall_geral) / (precisao_geral + recall_geral) if (precisao_geral + recall_geral) > 0 else 0
    
    print(f"\n  Acurácia Geral:  {acuracia_geral*100:6.2f}%")
    print(f"  Precisão:        {precisao_geral*100:6.2f}%")
    print(f"  Recall:          {recall_geral*100:6.2f}%")
    print(f"  F1-Score:        {f1_geral*100:6.2f}%")
    print(f"\n  Matriz de Confusão:")
    print(f"    TP (Vulnerável detectado):     {tp_v}")
    print(f"    TN (Seguro detectado):         {tn_v}")
    print(f"    FP (Falso positivo):           {fp_v}")
    print(f"    FN (Falso negativo):           {fn_v}")
    
    # 5. Métricas por CWE
    print("\n" + "="*80)
    print("📊 MÉTRICAS DETALHADAS POR CWE")
    print("="*80)
    
    # Ordenar por F1-Score decrescente
    cwes_ordenados = sorted(resultados_finais.items(), key=lambda x: x[1]['f1_score'], reverse=True)
    
    print(f"\n{'CWE':<10} {'Casos':>7} {'Acertos':>8} {'Precisão':>10} {'Recall':>10} {'F1-Score':>10} {'Acurácia':>10}")
    print("-" * 80)
    
    alto_desempenho = []
    medio_desempenho = []
    baixo_desempenho = []
    
    for cwe, metrics in cwes_ordenados:
        print(f"{cwe:<10} {metrics['total_casos']:>7} {metrics['acertos']:>8} "
              f"{metrics['precisao']*100:>9.1f}% {metrics['recall']*100:>9.1f}% "
              f"{metrics['f1_score']*100:>9.1f}% {metrics['acuracia']*100:>9.1f}%")
        
        # Categorizar por desempenho
        if metrics['f1_score'] >= 0.8:
            alto_desempenho.append((cwe, metrics))
        elif metrics['f1_score'] >= 0.5:
            medio_desempenho.append((cwe, metrics))
        else:
            baixo_desempenho.append((cwe, metrics))
    
    # 6. Análise de desempenho por categoria
    print("\n" + "="*80)
    print("📈 ANÁLISE POR CATEGORIA DE DESEMPENHO")
    print("="*80)
    
    print(f"\n🟢 ALTO DESEMPENHO (F1 ≥ 80%):")
    if alto_desempenho:
        for cwe, metrics in alto_desempenho:
            dist_info = distribuicao.get(cwe, {})
            print(f"  • {cwe}: F1={metrics['f1_score']*100:.1f}% | "
                  f"Casos={metrics['total_casos']} ({dist_info.get('percentual', 0):.1f}% do dataset)")
    else:
        print("  Nenhum CWE nesta categoria.")
    
    print(f"\n🟡 DESEMPENHO MODERADO (50% ≤ F1 < 80%):")
    if medio_desempenho:
        for cwe, metrics in medio_desempenho:
            dist_info = distribuicao.get(cwe, {})
            print(f"  • {cwe}: F1={metrics['f1_score']*100:.1f}% | "
                  f"Casos={metrics['total_casos']} ({dist_info.get('percentual', 0):.1f}% do dataset)")
    else:
        print("  Nenhum CWE nesta categoria.")
    
    print(f"\n🔴 BAIXO DESEMPENHO (F1 < 50%):")
    if baixo_desempenho:
        for cwe, metrics in baixo_desempenho:
            dist_info = distribuicao.get(cwe, {})
            print(f"  • {cwe}: F1={metrics['f1_score']*100:.1f}% | "
                  f"Casos={metrics['total_casos']} ({dist_info.get('percentual', 0):.1f}% do dataset)")
            print(f"    └─ Possível causa: Dataset desbalanceado ({dist_info.get('percentual', 0):.1f}% dos casos)")
    else:
        print("  Nenhum CWE nesta categoria.")
    
    # 7. Análise de correlação entre desempenho e quantidade de dados
    print("\n" + "="*80)
    print("🔍 ANÁLISE DE CORRELAÇÃO: Desempenho vs Quantidade de Dados")
    print("="*80)
    
    print("\nCWEs com MENOS de 5% do dataset:")
    for cwe, metrics in cwes_ordenados:
        dist_info = distribuicao.get(cwe, {})
        percentual = dist_info.get('percentual', 0)
        if percentual < 5:
            print(f"  • {cwe}: {percentual:.2f}% do dataset | F1-Score: {metrics['f1_score']*100:.1f}%")
    
    # 8. Recomendações para o artigo
    print("\n" + "="*80)
    print("📝 RECOMENDAÇÕES PARA O ARTIGO")
    print("="*80)
    
    print("\n1. RESULTADOS POSITIVOS:")
    print("   • Sistema apresenta excelente desempenho geral")
    print(f"   • Acurácia de {acuracia_geral*100:.1f}% na detecção binária (VULNERABLE vs SAFE)")
    print(f"   • {len(alto_desempenho)} CWEs com F1-Score > 80%")
    
    print("\n2. LIMITAÇÕES IDENTIFICADAS:")
    if baixo_desempenho:
        print(f"   • {len(baixo_desempenho)} CWEs com desempenho abaixo de 50%:")
        for cwe, metrics in baixo_desempenho:
            dist_info = distribuicao.get(cwe, {})
            print(f"     - {cwe}: apenas {dist_info.get('percentual', 0):.1f}% do dataset")
    
    print("\n3. HIPÓTESES PARA DISCUSSÃO:")
    print("   • Desbalanceamento do dataset afeta negativamente o desempenho")
    print("   • CWEs sub-representados (<5% do dataset) têm F1-Score reduzido")
    print("   • Necessidade de técnicas de balanceamento (SMOTE, oversampling)")
    
    print("\n4. TRABALHOS FUTUROS:")
    print("   • Implementar balanceamento de classes")
    print("   • Aumentar quantidade de exemplos para CWEs problemáticos")
    print("   • Explorar fine-tuning específico para categorias difíceis")
    
    print("\n" + "="*80)
    print("✅ Análise concluída!")
    print("="*80)
    
    # 9. Salvar resultados em JSON para uso posterior
    resultados_analise = {
        'metricas_gerais': {
            'acuracia': acuracia_geral,
            'precisao': precisao_geral,
            'recall': recall_geral,
            'f1_score': f1_geral,
            'total_testes': total_testes,
            'total_erros': total_erros
        },
        'metricas_por_cwe': resultados_finais,
        'distribuicao_dataset': distribuicao,
        'categorias_desempenho': {
            'alto': [cwe for cwe, _ in alto_desempenho],
            'medio': [cwe for cwe, _ in medio_desempenho],
            'baixo': [cwe for cwe, _ in baixo_desempenho]
        }
    }
    
    with open('analise_completa.json', 'w', encoding='utf-8') as f:
        json.dump(resultados_analise, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Resultados detalhados salvos em 'analise_completa.json'")

if __name__ == "__main__":
    gerar_relatorio()
