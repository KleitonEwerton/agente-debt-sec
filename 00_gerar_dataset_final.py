import csv
import json
import os
import re
import xml.etree.ElementTree as ET

# https://github.com/OWASP-Benchmark/BenchmarkJava

# ================= CONFIGURAÇÕES =================
# Caminhos relativos à raiz do repositório BenchmarkJava
PATH_CODE_DIR = os.path.join("src", "main", "java", "org", "owasp", "benchmark", "testcode")
PATH_CSV = "expectedresults-1.2.csv"
PATH_CWE_XML = "cwec_v4.18.xml"                     # Coloque este arquivo na raiz
PATH_CAPEC_XML = "capec_v3.9.xml"                   # Coloque este arquivo na raiz
OUTPUT_FILE = "dataset_treino_mestrado.jsonl"

# Mapeamento CWE → STRIDE baseado em análise acadêmica
# Fonte: Mapeamento CWE para STRIDE.csv
# Múltiplos STRIDE quando vulnerabilidade tem impactos diferentes dependendo do contexto
# NOTA: Este mapeamento NÃO é incluído no dataset (economiza tokens API)
CWE_TO_STRIDE_MAP = {
    "CWE-22": ["Information Disclosure"],                                   # Path Traversal
    "CWE-78": ["Elevation of Privilege", "Tampering"],                      # OS Command Injection
    "CWE-79": ["Tampering", "Elevation of Privilege", "Information Disclosure"],         # XSS
    "CWE-89": ["Tampering", "Information Disclosure"],                      # SQL Injection
    "CWE-90": ["Information Disclosure", "Elevation of Privilege"],         # LDAP Injection
    "CWE-327": ["Information Disclosure", "Spoofing"],                      # Broken Cryptographic Algorithm
    "CWE-328": ["Information Disclosure", "Spoofing"],                      # Reversible One-Way Hash
    "CWE-330": ["Spoofing", "Information Disclosure"],                      # Weak Random Values
    "CWE-501": ["Elevation of Privilege", "Spoofing"],                      # Trust Boundary Violation
    "CWE-614": ["Information Disclosure"],                                  # Sensitive Cookie without Secure
    "CWE-643": ["Information Disclosure", "Elevation of Privilege"],        # XPath Injection
}
# =================================================

def parse_mitre_definitions():
    print("📖 Carregando definições CWE e CAPEC...")
    cwe_map = {}
    capec_map = {}
    
    # 1. Ler CWE (Para pegar Nome e Descrição)
    try:
        tree = ET.parse(PATH_CWE_XML)
        root = tree.getroot()
        ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        for w in root.findall('.//cwe:Weakness', ns):
            cwe_id = f"CWE-{w.get('ID')}"
            desc = w.find('cwe:Description', ns)
            cwe_map[cwe_id] = {
                "name": w.get('Name'),
                "description": desc.text if desc is not None else ""
            }
    except Exception as e:
        print(f"⚠️ Erro ao ler CWE XML: {e}")

    # 2. Ler CAPEC (Para pegar a relação CWE -> CAPEC -> STRIDE implícito)
    # Nota: Vamos criar um mapa reverso CWE->CAPEC
    cwe_to_capec = {}
    try:
        tree = ET.parse(PATH_CAPEC_XML)
        root = tree.getroot()
        ns = {'capec': 'http://capec.mitre.org/capec-3'}
        
        for ap in root.findall('.//capec:Attack_Pattern', ns):
            capec_id = f"CAPEC-{ap.get('ID')}"
            name = ap.get('Name')
            
            # Tentar inferir STRIDE pelo nome do ataque
            stride = []
            name_lower = name.lower()
            if "spoof" in name_lower: stride.append("Spoofing")
            if "inject" in name_lower or "modify" in name_lower or "buffer" in name_lower: stride.append("Tampering")
            if "log" in name_lower or "audit" in name_lower: stride.append("Repudiation")
            if "read" in name_lower or "disclosure" in name_lower or "steal" in name_lower: stride.append("Information Disclosure")
            if "flood" in name_lower or "dos" in name_lower: stride.append("Denial of Service")
            if "privilege" in name_lower or "root" in name_lower: stride.append("Elevation of Privilege")
            
            # Relacionar com CWEs
            rel_weak = ap.find('capec:Related_Weaknesses', ns)
            if rel_weak is not None:
                for rw in rel_weak.findall('capec:Related_Weakness', ns):
                    target_cwe = f"CWE-{rw.get('CWE_ID')}"
                    if target_cwe not in cwe_to_capec:
                        cwe_to_capec[target_cwe] = []
                    cwe_to_capec[target_cwe].append({
                        "id": capec_id,
                        "name": name,
                        "inferred_stride": stride
                    })
    except Exception as e:
        print(f"⚠️ Erro ao ler CAPEC XML: {e}")

    return cwe_map, cwe_to_capec

def clean_code(code):
    # Remove licenças gigantes (comuns no Benchmark)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # Remove imports (opcional, economiza tokens)
    code = re.sub(r'^import\s+.*;', '', code, flags=re.MULTILINE)
    return "\n".join([line for line in code.splitlines() if line.strip()])

def main():
    cwe_db, cwe_to_capec_db = parse_mitre_definitions()
    
    print(f"🚀 Iniciando processamento do Benchmark em: {PATH_CODE_DIR}")
    dataset = []
    
    with open(PATH_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # CSV Columns: test name, category, real vulnerability, cwe
            filename = row['# test name'] + ".java"
            cwe_key = f"CWE-{row[' cwe']}"
            is_vuln = row[' real vulnerability'].lower() == 'true'
            
            # Ler arquivo Java
            filepath = os.path.join(PATH_CODE_DIR, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as jf:
                    raw_code = jf.read()
                
                # Montar Metadados Ricos
                cwe_info = cwe_db.get(cwe_key, {"name": "Unknown", "description": ""})
                threat_info = cwe_to_capec_db.get(cwe_key, [])
                
                # Coletar todos os STRIDEs possíveis para essa vulnerabilidade
                all_strides = set()
                for t in threat_info:
                    all_strides.update(t['inferred_stride'])
                
                # Se não conseguiu inferir do CAPEC, usar mapeamento direto CWE→STRIDE
                if not all_strides and cwe_key in CWE_TO_STRIDE_MAP:
                    all_strides = set(CWE_TO_STRIDE_MAP[cwe_key])
                
                # STRIDE NÃO é incluído no dataset (LLM infere via prompt)
                # Isso economiza tokens e evita "ensinar" mapeamentos incorretos
                # VERDICT removido: foco em detecção de padrões CWE, não em exploitabilidade
                entry = {
                    "instruction": f"Analyze the provided Java code snippet. Identify if it contains a CWE weakness pattern and classify according to STRIDE threat model.",
                    "input": clean_code(raw_code),
                    "output": json.dumps({
                        "weakness": {
                            "id": cwe_key,
                            "name": cwe_info['name'],
                            "description": cwe_info['description']
                        },
                        "threat_model": {
                            "related_capecs": [t['id'] for t in threat_info[:3]]  # Limitando a 3
                        }
                    })
                }
                dataset.append(entry)

    # Salvar
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
        for item in dataset:
            out.write(json.dumps(item) + "\n")
            
    print(f"✅ Concluído! {len(dataset)} exemplos salvos em {OUTPUT_FILE}")

if __name__ == "__main__":
    main()