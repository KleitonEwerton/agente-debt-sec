import os
import json
import time
import logging
from langchain_chroma.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURAÇÕES ---
CAMINHO_DB = "vectorstore_db"
MODELO_EMBEDDING = "sentence-transformers/all-MiniLM-L6-v2"
ARQUIVO_TESTE = "dataset_teste_reservado.jsonl"
ARQUIVO_RESULTADOS = "resultados_teste.json"
# Rate Limiting baseado nos limites do Groq (llama-3.3-70b-versatile):
# RPM: 30, TPM: 12K
# Pausa de 2s entre requisições (mínimo para RPM=30: 60/30=2s)
# Lote de 5 requisições com pausa de 15s (~12 req/min, abaixo do limite)
PAUSA_ENTRE_REQUISICOES = 2  # segundos
REQUISICOES_POR_LOTE = 5  # Pausa maior a cada lote
PAUSA_LOTE = 15  # segundos

# Configurar logging
logging.basicConfig(filename='teste_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Specialized Security Audit Prompt
prompt_template_security = """
You are a Software Security and Static Analysis (SAST) Expert.
Your task is to analyze the provided Java code for Technical Security Debt.

Use the retrieved context (similar examples from the dataset) to guide your decision.

RETRIEVED CONTEXT (Known similar cases):
{base_conhecimento}

---
TARGET CODE FOR ANALYSIS:
{codigo_alvo}
---

Response Instructions:
1. Identify if the code is VULNERABLE or SAFE.
2. If vulnerable, specify the most likely CWE ID exclusively from these CWEs (22, 78, 79, 89, 90, 327, 328, 330, 501, 614, or 643);
3. Briefly explain the flaw and associate it with the concept of Security Debt.
4. Classify the vulnerability according to STRIDE threat model (see detailed guidance below).

===== CWE CLASSIFICATION GUIDE =====
- CWE-327/328: Weak cryptography (MD5, SHA1, DES, RC4, weak AES configurations)
- CWE-89: SQL Injection (unsanitized input in SQL queries)
- CWE-79: Cross-Site Scripting/XSS (unsanitized input reflected in HTML/JavaScript)
- CWE-78: OS Command Injection (user input executed as shell commands)
- CWE-22: Path Traversal (file paths constructed from user input)
- CWE-90: LDAP Injection (unsanitized input in LDAP queries)
- CWE-330: Weak Random Number Generation (Math.random(), predictable seeds)
- CWE-501: Trust Boundary Violation (untrusted data treated as trusted)
- CWE-614: Insecure Cookie (sensitive cookies without Secure/HttpOnly flags)
- CWE-643: XPath Injection (unsanitized input in XPath queries)

===== STRIDE CLASSIFICATION GUIDE =====
Analyze the PRIMARY security impact and choose ONE category:

**Tampering** - Unauthorized modification of data or code:
- SQL/LDAP/XPath Injection that MODIFIES data (INSERT, UPDATE, DELETE)
- Command injection that CHANGES system state
- Path traversal that WRITES/MODIFIES files
- Example: SQL injection that deletes records, command injection that modifies files

**Spoofing** - Impersonation or identity falsification:
- Weak cryptography used for AUTHENTICATION (password hashing with MD5/SHA1)
- Weak random numbers for SESSION tokens, authentication tokens, or "remember me" keys
- Insecure cookies used for AUTHENTICATION without Secure/HttpOnly flags
- Trust boundary violations where attacker can IMPERSONATE legitimate users
- Example: MD5 password hashing, predictable session tokens

**Repudiation** - Denial of actions performed:
- Logging bypasses that allow attackers to hide their actions
- Path traversal affecting LOG files
- Weak cryptography for AUDIT trails or digital signatures
- Example: Command injection that deletes logs, path traversal that overwrites audit files

**Information Disclosure** - Exposure of confidential data:
- SQL/LDAP/XPath Injection that READS sensitive data (SELECT queries)
- Path traversal that READS sensitive files (passwords, configs, source code)
- XSS that STEALS cookies or session data
- Weak encryption of STORED sensitive data
- Example: SQL injection extracting passwords, path traversal reading configuration files

**Denial of Service** - Service disruption or resource exhaustion:
- Command injection causing system crashes
- SQL injection with resource-intensive queries
- Example: Shell fork bombs, infinite loop SQL queries

**Elevation of Privilege** - Gaining unauthorized permissions:
- Command injection executed with elevated privileges (root/admin)
- SQL injection bypassing access controls
- Path traversal accessing restricted system files
- Example: Command injection as root, SQL injection bypassing admin checks

CRITICAL DECISION RULES:
1. If vulnerability involves DATA MODIFICATION → Tampering
2. If involves AUTHENTICATION/IDENTITY → Spoofing  
3. If involves READING sensitive data → Information Disclosure
4. If involves HIDING attacker actions → Repudiation
5. If involves PRIVILEGE ESCALATION → Elevation of Privilege
6. If causes SERVICE DISRUPTION → Denial of Service

COMMON MAPPINGS:
- SQL Injection (SELECT) → Information Disclosure OR Tampering (if modifies data)
- SQL Injection (INSERT/UPDATE/DELETE) → Tampering
- XSS → Information Disclosure (steals data via JavaScript)
- Command Injection → Tampering OR Elevation of Privilege
- Path Traversal (read) → Information Disclosure
- Path Traversal (write) → Tampering
- Weak crypto for passwords → Spoofing
- Weak crypto for stored data → Information Disclosure
- Weak random for sessions → Spoofing
- Insecure auth cookies → Spoofing
- Trust boundary violation → Spoofing

Respond strictly in JSON format:
{{
  "verdict": "VULNERABLE" | "SAFE",
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "Explanatory text...",
  "stride": "Tampering" | "Spoofing" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege"
}}
"""

def testar_dataset():
    print("--- 🔬 Iniciando Teste do Dataset Reservado ---")

    # 1. Carregar Vector Store
    embedding_function = HuggingFaceEmbeddings(model_name=MODELO_EMBEDDING)
    if not os.path.exists(CAMINHO_DB):
        print("❌ Erro: Banco de vetores não encontrado. Rode o script 01 primeiro.")
        return

    db = Chroma(persist_directory=CAMINHO_DB, embedding_function=embedding_function)

    # 2. Carregar dados de teste
    if not os.path.exists(ARQUIVO_TESTE):
        print(f"❌ Erro: Arquivo {ARQUIVO_TESTE} não encontrado.")
        return

    dados_teste = []
    with open(ARQUIVO_TESTE, 'r', encoding='utf-8') as f:
        for linha in f:
            if linha.strip():
                try:
                    dados_teste.append(json.loads(linha))
                except json.JSONDecodeError:
                    logging.warning(f"Erro ao parsear linha: {linha[:100]}...")

    total_testes = len(dados_teste)
    print(f"📊 Total de testes a executar: {total_testes}")

    # 3. Inicializar LLM
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile")
    prompt = ChatPromptTemplate.from_template(prompt_template_security)
    chain = prompt | llm

    # 4. Carregar resultados existentes (se houver)
    resultados = []
    if os.path.exists(ARQUIVO_RESULTADOS):
        with open(ARQUIVO_RESULTADOS, 'r', encoding='utf-8') as f:
            try:
                resultados = json.load(f)
            except json.JSONDecodeError:
                logging.warning("Erro ao carregar resultados existentes. Iniciando do zero.")

    testes_executados = len(resultados)
    print(f"📈 Testes já executados: {testes_executados}")

    # 5. Executar testes restantes
    for idx, item in enumerate(dados_teste[testes_executados:], start=testes_executados):
        print(f"\n🔍 Processando teste {idx+1}/{total_testes}...")

        codigo_input = item.get('input', '')
        if not codigo_input.strip():
            logging.warning(f"Teste {idx+1}: Código vazio. Pulando.")
            continue

        try:
            # Buscar contexto similar
            resultados_similares = db.similarity_search(codigo_input, k=1)
            contexto_str = ""
            for doc in resultados_similares:
                contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"

            # Fazer análise
            resposta = chain.invoke({
                "codigo_alvo": codigo_input,
                "base_conhecimento": contexto_str
            })

            # Logar headers de rate limit se disponíveis
            if hasattr(resposta, 'response_metadata') and 'headers' in resposta.response_metadata:
                headers = resposta.response_metadata['headers']
                remaining_requests = headers.get('x-ratelimit-remaining-requests', 'N/A')
                remaining_tokens = headers.get('x-ratelimit-remaining-tokens', 'N/A')
                logging.info(f"Teste {idx+1} - Rate Limit: Remaining Requests: {remaining_requests}, Remaining Tokens: {remaining_tokens}")
                print(f"📊 Rate Limit: Req restantes: {remaining_requests}, Tokens restantes: {remaining_tokens}")
            else:
                logging.warning(f"Teste {idx+1} - Headers de rate limit não disponíveis na resposta.")

            # Parsear resposta JSON
            try:
                resultado_llm = json.loads(resposta.content.strip())
            except json.JSONDecodeError:
                logging.error(f"Erro ao parsear resposta JSON para teste {idx+1}: {resposta.content}")
                resultado_llm = {"error": "Resposta não é JSON válido", "raw_response": resposta.content}

            # Salvar resultado
            resultado_item = {
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo_input,
                "ground_truth": item.get('output', {}),
                "resultado_llm": resultado_llm
            }
            resultados.append(resultado_item)

            # Salvar incrementalmente
            with open(ARQUIVO_RESULTADOS, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)

            print(f"✅ Teste {idx+1} concluído.")

        except Exception as e:
            logging.error(f"Erro no teste {idx+1}: {str(e)}")
            # Salvar erro no resultado
            resultado_item = {
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo_input,
                "ground_truth": item.get('output', {}),
                "erro": str(e)
            }
            resultados.append(resultado_item)
            with open(ARQUIVO_RESULTADOS, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)

        # Rate limiting
        if (idx + 1) % REQUISICOES_POR_LOTE == 0:
            print(f"⏳ Pausa de lote ({PAUSA_LOTE}s) após {REQUISICOES_POR_LOTE} requisições...")
            time.sleep(PAUSA_LOTE)
        else:
            time.sleep(PAUSA_ENTRE_REQUISICOES)

    print(f"\n🎉 Teste completo! Resultados salvos em '{ARQUIVO_RESULTADOS}'")
    print(f"📊 Total de resultados: {len(resultados)}")

if __name__ == "__main__":
    testar_dataset()