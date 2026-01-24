"""
Script para análise completa dos resultados após melhoria STRIDE
Gera métricas detalhadas: CWE isolado, Verdict isolado, Combinado, e STRIDE
"""
import json
import re
from collections import defaultdict

ARQUIVO_RESULTADOS = "resultados_teste_stride_melhorado.json"
ARQUIVO_SAIDA = "analise_resultados_melhorados.json"

def extrair_stride_do_ground_truth(ground_truth_str):
    """Extrai STRIDE do ground truth (JSON string)"""
    try:
        gt_data = json.loads(ground_truth_str)
        stride_list = gt_data.get('threat_model', {}).get('stride_categories', [])
        return stride_list[0] if stride_list else 'Unknown'
    except:
        return 'Unknown'

def extrair_stride_do_llm(resultado_llm):
    """Extrai STRIDE da resposta do LLM (com tratamento de erros)"""
    if isinstance(resultado_llm, dict):
        # Tratar caso de erro com raw_response
        if 'error' in resultado_llm and 'raw_response' in resultado_llm:
            try:
                resposta_texto = resultado_llm['raw_response'].strip()
                
                # Remover markdown
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

def calcular_metricas_por_cwe(resultados):
    """Calcula métricas detalhadas para cada CWE"""
    metricas_cwe = {}
    metricas_verdict = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}
    metricas_stride = {'acertos': 0, 'erros': 0}
    
    # Matriz de confusão STRIDE
    stride_categories = ['Tampering', 'Spoofing', 'Repudiation', 'Information Disclosure', 
                         'Denial of Service', 'Elevation of Privilege']
    matriz_confusao_stride = {cat: {cat2: 0 for cat2 in stride_categories + ['Unknown']} 
                               for cat in stride_categories + ['Unknown']}
    
    total_testes = 0
    total_erros = 0
    
    for item in resultados:
        resultado_llm = item.get('resultado_llm', {})
        
        # Verificar se há erro
        if 'erro' in item or 'error' in resultado_llm:
            total_erros += 1
            continue
        
        total_testes += 1
        
        # Extrair ground truth
        try:
            ground_truth = json.loads(item.get('ground_truth', '{}'))
            cwe_esperado = ground_truth.get('weakness', {}).get('id', '')
            verdict_esperado = ground_truth.get('verdict', '')
        except:
            continue
        
        # Extrair predição LLM
        cwe_predito = resultado_llm.get('cwe_id', 'None')
        verdict_predito = resultado_llm.get('verdict', '')
        
        # Inicializar métricas por CWE se não existir
        if cwe_esperado not in metricas_cwe:
            metricas_cwe[cwe_esperado] = {
                'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0,
                'acertos_cwe': 0, 'total': 0
            }
        
        metricas_cwe[cwe_esperado]['total'] += 1
        
        # === ANÁLISE 1: CWE ISOLADO ===
        cwe_correto = (cwe_esperado == cwe_predito)
        if cwe_correto:
            metricas_cwe[cwe_esperado]['acertos_cwe'] += 1
        
        # === ANÁLISE 2: VERDICT ISOLADO ===
        if verdict_esperado == 'VULNERABLE' and verdict_predito == 'VULNERABLE':
            metricas_verdict['TP'] += 1
        elif verdict_esperado == 'SAFE' and verdict_predito == 'SAFE':
            metricas_verdict['TN'] += 1
        elif verdict_esperado == 'SAFE' and verdict_predito == 'VULNERABLE':
            metricas_verdict['FP'] += 1
        elif verdict_esperado == 'VULNERABLE' and verdict_predito == 'SAFE':
            metricas_verdict['FN'] += 1
        
        # === ANÁLISE 3: CWE + VERDICT COMBINADO ===
        acerto_combinado = (cwe_correto and verdict_esperado == verdict_predito)
        
        if verdict_esperado == 'VULNERABLE':
            if acerto_combinado:
                metricas_cwe[cwe_esperado]['TP'] += 1
            elif verdict_predito == 'SAFE':
                metricas_cwe[cwe_esperado]['FN'] += 1
            else:  # CWE errado mas marcou VULNERABLE
                metricas_cwe[cwe_esperado]['FN'] += 1
        else:  # SAFE
            if verdict_predito == 'SAFE':
                metricas_cwe[cwe_esperado]['TN'] += 1
            else:
                metricas_cwe[cwe_esperado]['FP'] += 1
        
        # === ANÁLISE 4: STRIDE ===
        stride_esperado = extrair_stride_do_ground_truth(item.get('ground_truth', '{}'))
        stride_predito = extrair_stride_do_llm(resultado_llm)
        
        # Pular casos com Unknown no ground truth
        if stride_esperado != 'Unknown':
            if stride_esperado == stride_predito:
                metricas_stride['acertos'] += 1
            else:
                metricas_stride['erros'] += 1
            
            # Atualizar matriz de confusão
            matriz_confusao_stride[stride_esperado][stride_predito] += 1
    
    return metricas_cwe, metricas_verdict, metricas_stride, matriz_confusao_stride, total_testes, total_erros

def gerar_relatorio(resultados):
    """Gera relatório completo com 4 análises"""
    print("=" * 80)
    print("📊 ANÁLISE COMPLETA - RESULTADOS MELHORADOS")
    print("=" * 80)
    
    metricas_cwe, metricas_verdict, metricas_stride, matriz_stride, total_testes, total_erros = calcular_metricas_por_cwe(resultados)
    
    relatorio = {
        "resumo_geral": {
            "total_testes": len(resultados),
            "testes_validos": total_testes,
            "erros": total_erros
        },
        "analises": {}
    }
    
    # ========================================
    # ANÁLISE 1: CWE ISOLADO
    # ========================================
    print("\n" + "=" * 80)
    print("📋 ANÁLISE 1: RECONHECIMENTO DE CWE (Isolado)")
    print("=" * 80)
    print("Métrica: Capacidade de identificar o tipo correto de vulnerabilidade")
    print("(Ignora se o veredito VULNERABLE/SAFE está correto)\n")
    
    analise_cwe = {}
    acertos_cwe_total = 0
    
    for cwe, metricas in sorted(metricas_cwe.items()):
        total_cwe = metricas['total']
        acertos_cwe = metricas['acertos_cwe']
        acertos_cwe_total += acertos_cwe
        
        acuracia = (acertos_cwe / total_cwe * 100) if total_cwe > 0 else 0
        
        analise_cwe[cwe] = {
            "acertos": acertos_cwe,
            "total": total_cwe,
            "acuracia": round(acuracia, 2)
        }
        
        print(f"{cwe:<10} {acertos_cwe:>3}/{total_cwe:<3} = {acuracia:>6.2f}%")
    
    acuracia_cwe_geral = (acertos_cwe_total / total_testes * 100) if total_testes > 0 else 0
    print(f"\n{'GERAL':<10} {acertos_cwe_total:>3}/{total_testes:<3} = {acuracia_cwe_geral:>6.2f}%")
    
    relatorio["analises"]["1_cwe_isolado"] = {
        "descricao": "Reconhecimento do tipo de CWE (ignorando veredito)",
        "metricas_por_cwe": analise_cwe,
        "acuracia_geral": round(acuracia_cwe_geral, 2),
        "total_acertos": acertos_cwe_total,
        "total_testes": total_testes
    }
    
    # ========================================
    # ANÁLISE 2: VERDICT ISOLADO
    # ========================================
    print("\n" + "=" * 80)
    print("⚖️  ANÁLISE 2: CLASSIFICAÇÃO VULNERABLE/SAFE (Isolado)")
    print("=" * 80)
    print("Métrica: Capacidade de distinguir código vulnerável de código seguro")
    print("(Ignora se identificou a CWE correta)\n")
    
    TP = metricas_verdict['TP']
    TN = metricas_verdict['TN']
    FP = metricas_verdict['FP']
    FN = metricas_verdict['FN']
    
    precisao = (TP / (TP + FP) * 100) if (TP + FP) > 0 else 0
    recall = (TP / (TP + FN) * 100) if (TP + FN) > 0 else 0
    f1 = (2 * precisao * recall / (precisao + recall)) if (precisao + recall) > 0 else 0
    acuracia_verdict = ((TP + TN) / total_testes * 100) if total_testes > 0 else 0
    
    print(f"True Positives (TP):  {TP:>3} (VULNERABLE detectado corretamente)")
    print(f"True Negatives (TN):  {TN:>3} (SAFE detectado corretamente)")
    print(f"False Positives (FP): {FP:>3} (SAFE marcado como VULNERABLE)")
    print(f"False Negatives (FN): {FN:>3} (VULNERABLE marcado como SAFE)")
    print(f"\nPrecisão: {precisao:.2f}%")
    print(f"Recall:   {recall:.2f}%")
    print(f"F1-Score: {f1:.2f}%")
    print(f"Acurácia: {acuracia_verdict:.2f}%")
    
    relatorio["analises"]["2_verdict_isolado"] = {
        "descricao": "Classificação VULNERABLE vs SAFE (ignorando CWE)",
        "matriz_confusao": {
            "TP": TP, "TN": TN, "FP": FP, "FN": FN
        },
        "metricas": {
            "precisao": round(precisao, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1, 2),
            "acuracia": round(acuracia_verdict, 2)
        }
    }
    
    # ========================================
    # ANÁLISE 3: CWE + VERDICT COMBINADO
    # ========================================
    print("\n" + "=" * 80)
    print("🎯 ANÁLISE 3: CWE + VERDICT COMBINADO")
    print("=" * 80)
    print("Métrica: Acerto completo (CWE correto E veredito correto simultaneamente)\n")
    
    analise_combinada = {}
    acertos_totais = 0
    
    for cwe, metricas in sorted(metricas_cwe.items()):
        TP = metricas['TP']
        TN = metricas['TN']
        FP = metricas['FP']
        FN = metricas['FN']
        total_cwe = metricas['total']
        
        acertos = TP + TN
        acertos_totais += acertos
        
        precisao = (TP / (TP + FP) * 100) if (TP + FP) > 0 else 0
        recall = (TP / (TP + FN) * 100) if (TP + FN) > 0 else 0
        f1 = (2 * precisao * recall / (precisao + recall)) if (precisao + recall) > 0 else 0
        acuracia = (acertos / total_cwe * 100) if total_cwe > 0 else 0
        
        analise_combinada[cwe] = {
            "TP": TP, "TN": TN, "FP": FP, "FN": FN,
            "total": total_cwe,
            "precisao": round(precisao, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1, 2),
            "acuracia": round(acuracia, 2)
        }
        
        print(f"{cwe:<10} Precisão: {precisao:>6.2f}%  Recall: {recall:>6.2f}%  F1: {f1:>6.2f}%  Acurácia: {acuracia:>6.2f}%")
    
    acuracia_combinada_geral = (acertos_totais / total_testes * 100) if total_testes > 0 else 0
    print(f"\n{'GERAL':<10} Acurácia: {acuracia_combinada_geral:>6.2f}% ({acertos_totais}/{total_testes})")
    
    relatorio["analises"]["3_combinado"] = {
        "descricao": "CWE correto E veredito correto (métrica mais rigorosa)",
        "metricas_por_cwe": analise_combinada,
        "acuracia_geral": round(acuracia_combinada_geral, 2),
        "total_acertos": acertos_totais,
        "total_testes": total_testes
    }
    
    # ========================================
    # ANÁLISE 4: STRIDE
    # ========================================
    print("\n" + "=" * 80)
    print("🛡️  ANÁLISE 4: CLASSIFICAÇÃO STRIDE")
    print("=" * 80)
    print("Métrica: Capacidade de mapear vulnerabilidades para categorias STRIDE\n")
    
    total_stride = metricas_stride['acertos'] + metricas_stride['erros']
    acuracia_stride = (metricas_stride['acertos'] / total_stride * 100) if total_stride > 0 else 0
    
    print(f"Acertos: {metricas_stride['acertos']}")
    print(f"Erros:   {metricas_stride['erros']}")
    print(f"Total:   {total_stride}")
    print(f"Acurácia: {acuracia_stride:.2f}%")
    
    # Métricas por categoria STRIDE
    print("\n--- Desempenho por Categoria STRIDE ---")
    stride_por_categoria = {}
    
    stride_categories = ['Tampering', 'Spoofing', 'Repudiation', 'Information Disclosure', 
                         'Denial of Service', 'Elevation of Privilege']
    
    for cat in stride_categories:
        total_cat = sum(matriz_stride[cat].values())
        if total_cat > 0:
            acertos_cat = matriz_stride[cat][cat]
            acc = (acertos_cat / total_cat * 100)
            stride_por_categoria[cat] = {
                "acertos": acertos_cat,
                "total": total_cat,
                "acuracia": round(acc, 2)
            }
            print(f"  {cat:<30} {acertos_cat:>3}/{total_cat:<3} = {acc:>6.2f}%")
    
    # Matriz de confusão resumida
    print("\n--- Principais Confusões ---")
    confusoes = []
    for stride_real in stride_categories:
        for stride_pred in stride_categories:
            if stride_real != stride_pred and matriz_stride[stride_real][stride_pred] > 0:
                count = matriz_stride[stride_real][stride_pred]
                confusoes.append((stride_real, stride_pred, count))
    
    confusoes_sorted = sorted(confusoes, key=lambda x: x[2], reverse=True)[:5]
    for real, pred, count in confusoes_sorted:
        print(f"  {real} → {pred}: {count} casos")
    
    relatorio["analises"]["4_stride"] = {
        "descricao": "Classificação de ameaças segundo modelo STRIDE",
        "acuracia_geral": round(acuracia_stride, 2),
        "total_acertos": metricas_stride['acertos'],
        "total_erros": metricas_stride['erros'],
        "total_testes_stride": total_stride,
        "metricas_por_categoria": stride_por_categoria,
        "matriz_confusao": {k: dict(v) for k, v in matriz_stride.items() if sum(v.values()) > 0}
    }
    
    # Salvar relatório
    with open(ARQUIVO_SAIDA, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print(f"✅ ANÁLISE CONCLUÍDA!")
    print("=" * 80)
    print(f"\n📁 Relatório salvo em: {ARQUIVO_SAIDA}")
    
    return relatorio

def main():
    # Carregar resultados
    try:
        with open(ARQUIVO_RESULTADOS, 'r', encoding='utf-8') as f:
            resultados = json.load(f)
        print(f"✓ Arquivo carregado: {len(resultados)} testes\n")
    except FileNotFoundError:
        print(f"❌ Arquivo {ARQUIVO_RESULTADOS} não encontrado")
        return
    
    # Gerar relatório
    gerar_relatorio(resultados)

if __name__ == "__main__":
    main()
