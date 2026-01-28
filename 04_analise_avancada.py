"""
Script de Análise Avançada - Métricas Detalhadas e Insights
Gera: Matriz de Confusão, Precision, Recall, F1-Score, Análise de Erros
"""
import json
import numpy as np
from collections import defaultdict, Counter
from typing import Dict, List, Tuple

ARQUIVO_RESULTADOS = "resultados_teste_stride_melhorado.json"
ARQUIVO_SAIDA = "analise_avancada_metricas.json"

# Mapeamento CWE → STRIDE (ground truth)
CWE_TO_STRIDE = {
    "CWE-22": ["Information Disclosure"],
    "CWE-78": ["Elevation of Privilege", "Tampering"],
    "CWE-79": ["Tampering", "Elevation of Privilege", "Information Disclosure"],
    "CWE-89": ["Tampering", "Information Disclosure"],
    "CWE-90": ["Information Disclosure", "Elevation of Privilege"],
    "CWE-327": ["Information Disclosure", "Spoofing"],
    "CWE-328": ["Information Disclosure", "Spoofing"],
    "CWE-330": ["Spoofing", "Information Disclosure"],
    "CWE-501": ["Elevation of Privilege", "Spoofing"],
    "CWE-614": ["Information Disclosure"],
    "CWE-643": ["Information Disclosure", "Elevation of Privilege"],
}

def carregar_resultados(arquivo: str) -> List[Dict]:
    """Carrega resultados do arquivo JSON"""
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Arquivo {arquivo} não encontrado")
        return []

def extrair_labels(resultados: List[Dict]) -> Tuple[List[str], List[str], List[Dict]]:
    """Extrai labels verdadeiros, preditos e casos válidos"""
    y_true = []
    y_pred = []
    casos_validos = []
    
    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        
        # Pular erros
        if 'erro' in item or 'error' in resultado_llm:
            continue
        
        # Extrair ground truth
        try:
            ground_truth = json.loads(item.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
        except:
            continue
        
        # Extrair predição
        if isinstance(resultado_llm, dict):
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
                    continue
            
            cwe_predito = resultado_llm.get('cwe_id', 'None')
        else:
            continue
        
        if cwe_esperado and cwe_predito != 'None':
            y_true.append(cwe_esperado)
            y_pred.append(cwe_predito)
            casos_validos.append({
                'esperado': cwe_esperado,
                'predito': cwe_predito,
                'item': item
            })
    
    return y_true, y_pred, casos_validos

def calcular_matriz_confusao(y_true: List[str], y_pred: List[str]) -> Dict:
    """Calcula matriz de confusão detalhada"""
    # Obter todas as classes únicas
    classes = sorted(set(y_true + y_pred))
    n_classes = len(classes)
    
    # Criar mapeamento classe → índice
    class_to_idx = {cls: idx for idx, cls in enumerate(classes)}
    
    # Inicializar matriz
    matriz = np.zeros((n_classes, n_classes), dtype=int)
    
    # Preencher matriz
    for true_label, pred_label in zip(y_true, y_pred):
        i = class_to_idx[true_label]
        j = class_to_idx[pred_label]
        matriz[i][j] += 1
    
    return {
        'matriz': matriz.tolist(),
        'classes': classes,
        'class_to_idx': class_to_idx
    }

def calcular_metricas_por_classe(y_true: List[str], y_pred: List[str]) -> Dict:
    """Calcula Precision, Recall, F1-Score, Support por classe"""
    classes = sorted(set(y_true))
    metricas = {}
    
    for classe in classes:
        # True Positives: corretamente identificados como classe
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == classe and p == classe)
        
        # False Positives: incorretamente identificados como classe
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != classe and p == classe)
        
        # False Negatives: não identificados como classe quando deveriam
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == classe and p != classe)
        
        # True Negatives: corretamente não identificados como classe
        tn = sum(1 for t, p in zip(y_true, y_pred) if t != classe and p != classe)
        
        # Support: número de ocorrências reais da classe
        support = sum(1 for t in y_true if t == classe)
        
        # Calcular métricas
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        
        metricas[classe] = {
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1_score, 4),
            'specificity': round(specificity, 4),
            'support': support,
            'tp': tp,
            'fp': fp,
            'fn': fn,
            'tn': tn
        }
    
    return metricas

def calcular_metricas_globais(metricas_por_classe: Dict, y_true: List[str]) -> Dict:
    """Calcula métricas macro e micro averaged"""
    classes = list(metricas_por_classe.keys())
    total_samples = len(y_true)
    
    # Macro Average (média simples)
    macro_precision = np.mean([m['precision'] for m in metricas_por_classe.values()])
    macro_recall = np.mean([m['recall'] for m in metricas_por_classe.values()])
    macro_f1 = np.mean([m['f1_score'] for m in metricas_por_classe.values()])
    
    # Micro Average (ponderado por support)
    total_tp = sum(m['tp'] for m in metricas_por_classe.values())
    total_fp = sum(m['fp'] for m in metricas_por_classe.values())
    total_fn = sum(m['fn'] for m in metricas_por_classe.values())
    
    micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    micro_f1 = 2 * (micro_precision * micro_recall) / (micro_precision + micro_recall) if (micro_precision + micro_recall) > 0 else 0.0
    
    # Weighted Average (ponderado por support)
    weighted_precision = sum(m['precision'] * m['support'] for m in metricas_por_classe.values()) / total_samples
    weighted_recall = sum(m['recall'] * m['support'] for m in metricas_por_classe.values()) / total_samples
    weighted_f1 = sum(m['f1_score'] * m['support'] for m in metricas_por_classe.values()) / total_samples
    
    # Acurácia global
    acuracia = total_tp / total_samples if total_samples > 0 else 0.0
    
    return {
        'acuracia': round(acuracia, 4),
        'macro_avg': {
            'precision': round(macro_precision, 4),
            'recall': round(macro_recall, 4),
            'f1_score': round(macro_f1, 4)
        },
        'micro_avg': {
            'precision': round(micro_precision, 4),
            'recall': round(micro_recall, 4),
            'f1_score': round(micro_f1, 4)
        },
        'weighted_avg': {
            'precision': round(weighted_precision, 4),
            'recall': round(weighted_recall, 4),
            'f1_score': round(weighted_f1, 4)
        },
        'total_samples': total_samples
    }

def analisar_erros(casos_validos: List[Dict]) -> Dict:
    """Analisa padrões de erro e confusões entre classes"""
    erros = []
    confusoes = defaultdict(lambda: defaultdict(int))
    
    for caso in casos_validos:
        esperado = caso['esperado']
        predito = caso['predito']
        
        if esperado != predito:
            erros.append(caso)
            confusoes[esperado][predito] += 1
    
    # Encontrar confusões mais comuns
    top_confusoes = []
    for esperado, predicoes in confusoes.items():
        for predito, count in predicoes.items():
            top_confusoes.append({
                'esperado': esperado,
                'predito': predito,
                'quantidade': count
            })
    
    top_confusoes = sorted(top_confusoes, key=lambda x: x['quantidade'], reverse=True)
    
    return {
        'total_erros': len(erros),
        'taxa_erro': round(len(erros) / len(casos_validos) * 100, 2) if casos_validos else 0,
        'top_10_confusoes': top_confusoes[:10],
        'todas_confusoes': dict(confusoes)
    }

def analisar_stride_detalhado(resultados: List[Dict]) -> Dict:
    """Análise detalhada de STRIDE com métricas de concordância"""
    stride_correto = 0
    stride_parcial = 0
    stride_incorreto = 0
    stride_analises = []
    
    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        
        if 'erro' in item or 'error' in resultado_llm:
            continue
        
        try:
            ground_truth = json.loads(item.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
        except:
            continue
        
        # Extrair STRIDE predito
        stride_predito = None
        if isinstance(resultado_llm, dict):
            if 'error' in resultado_llm and 'raw_response' in resultado_llm:
                try:
                    resposta_texto = resultado_llm['raw_response'].strip()
                    if resposta_texto.startswith("```json"):
                        resposta_texto = resposta_texto.split("```json")[1].split("```")[0]
                    resultado_llm = json.loads(resposta_texto.strip())
                except:
                    continue
            
            stride_predito = resultado_llm.get('stride')
        
        # Obter STRIDE esperado do CWE
        strides_esperados = CWE_TO_STRIDE.get(cwe_esperado, [])
        
        if stride_predito and strides_esperados:
            if stride_predito in strides_esperados:
                stride_correto += 1
                concordancia = 'correto'
            elif any(s in stride_predito for s in strides_esperados):
                stride_parcial += 1
                concordancia = 'parcial'
            else:
                stride_incorreto += 1
                concordancia = 'incorreto'
            
            stride_analises.append({
                'cwe': cwe_esperado,
                'stride_predito': stride_predito,
                'strides_esperados': strides_esperados,
                'concordancia': concordancia
            })
    
    total_analisado = stride_correto + stride_parcial + stride_incorreto
    
    return {
        'total_analisado': total_analisado,
        'stride_correto': stride_correto,
        'stride_parcial': stride_parcial,
        'stride_incorreto': stride_incorreto,
        'taxa_correto': round(stride_correto / total_analisado * 100, 2) if total_analisado > 0 else 0,
        'taxa_parcial': round(stride_parcial / total_analisado * 100, 2) if total_analisado > 0 else 0,
        'taxa_incorreto': round(stride_incorreto / total_analisado * 100, 2) if total_analisado > 0 else 0,
        'detalhes': stride_analises[:20]  # Primeiros 20 casos para visualização
    }

def calcular_distribuicao_classes(y_true: List[str], y_pred: List[str]) -> Dict:
    """Analisa distribuição e balanceamento das classes"""
    distribuicao_real = Counter(y_true)
    distribuicao_predita = Counter(y_pred)
    
    classes = sorted(set(y_true + y_pred))
    
    comparacao = {}
    for classe in classes:
        real = distribuicao_real.get(classe, 0)
        predita = distribuicao_predita.get(classe, 0)
        diferenca = predita - real
        
        comparacao[classe] = {
            'real': real,
            'predito': predita,
            'diferenca': diferenca,
            'taxa_predicao': round(predita / real, 2) if real > 0 else 0
        }
    
    return {
        'distribuicao_real': dict(distribuicao_real),
        'distribuicao_predita': dict(distribuicao_predita),
        'comparacao_por_classe': comparacao
    }

def gerar_relatorio_completo(resultados: List[Dict]) -> Dict:
    """Gera relatório completo com todas as análises"""
    print("=" * 80)
    print("📊 ANÁLISE AVANÇADA - MÉTRICAS DETALHADAS E INSIGHTS")
    print("=" * 80)
    
    # Extrair labels
    y_true, y_pred, casos_validos = extrair_labels(resultados)
    
    if not y_true:
        print("❌ Nenhum caso válido encontrado")
        return {}
    
    print(f"\n✓ {len(casos_validos)} casos válidos para análise")
    
    # 1. Matriz de Confusão
    print("\n" + "=" * 80)
    print("📋 1. MATRIZ DE CONFUSÃO")
    print("=" * 80)
    matriz_info = calcular_matriz_confusao(y_true, y_pred)
    print(f"Classes analisadas: {len(matriz_info['classes'])}")
    print(f"Classes: {', '.join(matriz_info['classes'])}")
    
    # 2. Métricas por Classe
    print("\n" + "=" * 80)
    print("📊 2. MÉTRICAS POR CLASSE")
    print("=" * 80)
    metricas_classe = calcular_metricas_por_classe(y_true, y_pred)
    
    print(f"{'CWE':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<10}")
    print("-" * 80)
    for classe, metricas in sorted(metricas_classe.items()):
        print(f"{classe:<12} {metricas['precision']:<12.4f} {metricas['recall']:<12.4f} "
              f"{metricas['f1_score']:<12.4f} {metricas['support']:<10}")
    
    # 3. Métricas Globais
    print("\n" + "=" * 80)
    print("🌍 3. MÉTRICAS GLOBAIS")
    print("=" * 80)
    metricas_globais = calcular_metricas_globais(metricas_classe, y_true)
    
    print(f"Acurácia Global: {metricas_globais['acuracia']:.4f}")
    print(f"\nMacro Average:")
    print(f"  Precision: {metricas_globais['macro_avg']['precision']:.4f}")
    print(f"  Recall:    {metricas_globais['macro_avg']['recall']:.4f}")
    print(f"  F1-Score:  {metricas_globais['macro_avg']['f1_score']:.4f}")
    print(f"\nMicro Average:")
    print(f"  Precision: {metricas_globais['micro_avg']['precision']:.4f}")
    print(f"  Recall:    {metricas_globais['micro_avg']['recall']:.4f}")
    print(f"  F1-Score:  {metricas_globais['micro_avg']['f1_score']:.4f}")
    print(f"\nWeighted Average:")
    print(f"  Precision: {metricas_globais['weighted_avg']['precision']:.4f}")
    print(f"  Recall:    {metricas_globais['weighted_avg']['recall']:.4f}")
    print(f"  F1-Score:  {metricas_globais['weighted_avg']['f1_score']:.4f}")
    
    # 4. Análise de Erros
    print("\n" + "=" * 80)
    print("❌ 4. ANÁLISE DE ERROS")
    print("=" * 80)
    analise_erros_resultado = analisar_erros(casos_validos)
    
    print(f"Total de Erros: {analise_erros_resultado['total_erros']}")
    print(f"Taxa de Erro: {analise_erros_resultado['taxa_erro']:.2f}%")
    print(f"\nTop 10 Confusões Mais Comuns:")
    print(f"{'Esperado':<12} {'Predito':<12} {'Quantidade':<10}")
    print("-" * 40)
    for conf in analise_erros_resultado['top_10_confusoes']:
        print(f"{conf['esperado']:<12} {conf['predito']:<12} {conf['quantidade']:<10}")
    
    # 5. Análise STRIDE Detalhada
    print("\n" + "=" * 80)
    print("🛡️  5. ANÁLISE STRIDE DETALHADA")
    print("=" * 80)
    stride_detalhado = analisar_stride_detalhado(resultados)
    
    print(f"Total Analisado: {stride_detalhado['total_analisado']}")
    print(f"STRIDE Correto: {stride_detalhado['stride_correto']} ({stride_detalhado['taxa_correto']:.2f}%)")
    print(f"STRIDE Parcial: {stride_detalhado['stride_parcial']} ({stride_detalhado['taxa_parcial']:.2f}%)")
    print(f"STRIDE Incorreto: {stride_detalhado['stride_incorreto']} ({stride_detalhado['taxa_incorreto']:.2f}%)")
    
    # 6. Distribuição de Classes
    print("\n" + "=" * 80)
    print("📈 6. DISTRIBUIÇÃO E BALANCEAMENTO")
    print("=" * 80)
    distribuicao = calcular_distribuicao_classes(y_true, y_pred)
    
    print(f"{'CWE':<12} {'Real':<10} {'Predito':<10} {'Diferença':<12} {'Taxa':<10}")
    print("-" * 60)
    for classe, info in sorted(distribuicao['comparacao_por_classe'].items()):
        print(f"{classe:<12} {info['real']:<10} {info['predito']:<10} "
              f"{info['diferenca']:+<12} {info['taxa_predicao']:<10.2f}")
    
    # Construir relatório JSON
    relatorio = {
        'resumo': {
            'total_testes': len(resultados),
            'casos_validos': len(casos_validos),
            'total_erros_llm': len(resultados) - len(casos_validos)
        },
        'matriz_confusao': matriz_info,
        'metricas_por_classe': metricas_classe,
        'metricas_globais': metricas_globais,
        'analise_erros': analise_erros_resultado,
        'analise_stride': stride_detalhado,
        'distribuicao_classes': distribuicao
    }
    
    # Salvar relatório
    with open(ARQUIVO_SAIDA, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print("✅ ANÁLISE AVANÇADA CONCLUÍDA!")
    print("=" * 80)
    print(f"\n📁 Relatório salvo em: {ARQUIVO_SAIDA}")
    
    return relatorio

def main():
    """Função principal"""
    resultados = carregar_resultados(ARQUIVO_RESULTADOS)
    
    if not resultados:
        return
    
    print(f"✓ Carregados {len(resultados)} resultados\n")
    
    gerar_relatorio_completo(resultados)

if __name__ == "__main__":
    main()
