"""
Script para analisar a distribuição de STRIDE Unknown vs Válido no dataset de treino
"""

import json
from collections import Counter, defaultdict

# Carregar dataset de treino
with open("dataset_treino_mestrado.jsonl", "r", encoding="utf-8") as f:
    treino = [json.loads(line) for line in f]

print(f"📊 ANÁLISE DE STRIDE NO DATASET DE TREINO")
print(f"{'='*70}\n")

# Contadores
total_casos = len(treino)
casos_unknown = 0
casos_validos = 0
stride_counter = Counter()
cwe_unknown_counter = Counter()
cwe_valido_counter = defaultdict(Counter)

for caso in treino:
    ground_truth = json.loads(caso["ground_truth"])
    stride_categories = ground_truth.get("threat_model", {}).get("stride_categories", [])
    cwe_id = ground_truth.get("weakness", {}).get("id", "")
    
    if "Unknown" in stride_categories:
        casos_unknown += 1
        cwe_unknown_counter[cwe_id] += 1
    else:
        casos_validos += 1
        for stride in stride_categories:
            stride_counter[stride] += 1
            cwe_valido_counter[cwe_id][stride] += 1

# Resultados gerais
print(f"Total de casos no treino: {total_casos}")
print(f"Casos com STRIDE Unknown: {casos_unknown} ({casos_unknown/total_casos*100:.1f}%)")
print(f"Casos com STRIDE válido: {casos_validos} ({casos_validos/total_casos*100:.1f}%)")
print()

# Distribuição de CWEs com Unknown
print(f"📌 CWEs COM STRIDE UNKNOWN:")
print(f"{'-'*70}")
for cwe, count in sorted(cwe_unknown_counter.items(), key=lambda x: x[1], reverse=True):
    print(f"  {cwe}: {count} casos ({count/casos_unknown*100:.1f}% dos Unknown)")
print()

# Distribuição de STRIDE válidos
print(f"✅ DISTRIBUIÇÃO DE STRIDE VÁLIDOS:")
print(f"{'-'*70}")
for stride, count in stride_counter.most_common():
    print(f"  {stride}: {count} casos ({count/casos_validos*100:.1f}% dos válidos)")
print()

# CWE → STRIDE mapeamento atual (dos casos válidos)
print(f"🗺️  MAPEAMENTO CWE → STRIDE (DOS CASOS VÁLIDOS):")
print(f"{'-'*70}")
for cwe in sorted(set(list(cwe_unknown_counter.keys()) + list(cwe_valido_counter.keys()))):
    validos = cwe_valido_counter.get(cwe, {})
    unknown = cwe_unknown_counter.get(cwe, 0)
    
    if validos:
        stride_list = [f"{k}({v})" for k, v in validos.items()]
        print(f"  {cwe}:")
        print(f"    Válido: {', '.join(stride_list)}")
        if unknown:
            print(f"    Unknown: {unknown} casos")
    elif unknown:
        print(f"  {cwe}:")
        print(f"    Unknown: {unknown} casos (SEM MAPEAMENTO VÁLIDO!)")
print()

# Sugestão de mapeamento
print(f"💡 SUGESTÃO DE MAPEAMENTO CWE → STRIDE PARA UNKNOWN:")
print(f"{'-'*70}")

# Mapeamento baseado na natureza da CWE
CWE_TO_STRIDE = {
    "CWE-22": "Information Disclosure",  # Path Traversal expõe arquivos
    "CWE-78": "Tampering",               # Command Injection modifica sistema
    "CWE-79": "Tampering",               # XSS modifica página web
    "CWE-89": "Tampering",               # SQL Injection modifica dados
    "CWE-90": "Tampering",               # LDAP Injection modifica consultas
    "CWE-327": "Spoofing",               # Broken Crypto afeta autenticação
    "CWE-328": "Spoofing",               # Weak Hash afeta autenticação
    "CWE-330": "Spoofing",               # Weak Random afeta tokens/sessions
    "CWE-501": "Tampering",              # Trust Boundary mistura dados
    "CWE-614": "Information Disclosure", # Sensitive Cookie expõe informação
    "CWE-643": "Tampering",              # XPath Injection modifica consultas
}

for cwe in sorted(cwe_unknown_counter.keys()):
    unknown_count = cwe_unknown_counter[cwe]
    sugestao = CWE_TO_STRIDE.get(cwe, "???")
    validos = cwe_valido_counter.get(cwe, {})
    
    if validos:
        stride_dominante = max(validos.items(), key=lambda x: x[1])
        print(f"  {cwe}: {unknown_count} casos → Sugestão: '{sugestao}' (domina nos válidos: {stride_dominante[0]})")
    else:
        print(f"  {cwe}: {unknown_count} casos → Sugestão: '{sugestao}' (SEM DADOS VÁLIDOS)")

print()
print(f"{'='*70}")
print(f"✅ Análise concluída!")
