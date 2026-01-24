"""
Script para re-executar testes com prompt STRIDE melhorado
Executa apenas os testes para gerar novos resultados e comparar
"""
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
ARQUIVO_RESULTADOS_NOVO = "resultados_teste_stride_melhorado.json"
ARQUIVO_RESULTADOS_ANTIGO = "resultados_teste.json"

# Rate Limiting
PAUSA_ENTRE_REQUISICOES = 2
REQUISICOES_POR_LOTE = 5
PAUSA_LOTE = 15

logging.basicConfig(filename='retreino_stride_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Prompt melhorado com guia STRIDE detalhado
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

def retreinar_stride():
    print("=" * 80)
    print("🔄 RE-EXECUÇÃO COM PROMPT STRIDE MELHORADO")
    print("=" * 80)

    # 1. Carregar Vector Store
    embedding_function = HuggingFaceEmbeddings(model_name=MODELO_EMBEDDING)
    if not os.path.exists(CAMINHO_DB):
        print("❌ Erro: Banco de vetores não encontrado.")
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
    print(f"\n📊 Total de testes: {total_testes}")

    # 3. Verificar se há resultados anteriores para continuar
    resultados = []
    teste_inicial = 0
    
    if os.path.exists(ARQUIVO_RESULTADOS_NOVO):
        print(f"\n⚠️  Arquivo {ARQUIVO_RESULTADOS_NOVO} já existe.")
        resposta = input("Deseja continuar de onde parou? (s/n): ")
        if resposta.lower() == 's':
            with open(ARQUIVO_RESULTADOS_NOVO, 'r', encoding='utf-8') as f:
                resultados = json.load(f)
                teste_inicial = len(resultados)
                print(f"✓ Continuando do teste {teste_inicial}")

    # 4. Inicializar LLM
    prompt = ChatPromptTemplate.from_template(prompt_template_security)
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile")
    chain = prompt | llm

    # 5. Executar testes
    print(f"\n🚀 Iniciando testes ({teste_inicial} até {total_testes})...\n")
    print("💾 Salvamento automático a cada 10 testes\n")
    
    for idx in range(teste_inicial, total_testes):
        item = dados_teste[idx]
        codigo = item.get('input', '')
        ground_truth = item.get('output', '{}')
        
        print(f"🔍 Teste {idx+1}/{total_testes}... ", end='', flush=True)
        
        try:
            # Buscar contexto RAG
            resultados_busca = db.similarity_search(codigo, k=1)
            contexto_str = ""
            for doc in resultados_busca:
                contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"
            
            # Consultar LLM
            resposta = chain.invoke({
                "codigo_alvo": codigo,
                "base_conhecimento": contexto_str
            })
            
            # Tentar parsear resposta JSON
            resposta_texto = resposta.content.strip()
            
            # Remover markdown se presente
            if resposta_texto.startswith("```json"):
                resposta_texto = resposta_texto.split("```json")[1]
                resposta_texto = resposta_texto.split("```")[0]
            elif resposta_texto.startswith("```"):
                resposta_texto = resposta_texto.split("```")[1]
                if resposta_texto.startswith("json"):
                    resposta_texto = resposta_texto[4:]
                resposta_texto = resposta_texto.split("```")[0]
            
            resposta_texto = resposta_texto.strip()
            
            try:
                resultado_llm = json.loads(resposta_texto)
            except json.JSONDecodeError:
                resultado_llm = {
                    "error": "Resposta não é JSON válido",
                    "raw_response": resposta_texto
                }
            
            resultados.append({
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo,
                "ground_truth": ground_truth,
                "resultado_llm": resultado_llm
            })
            
            logging.info(f"Teste {idx} concluído com sucesso")
            print("✅")
            
        except Exception as e:
            logging.error(f"Erro no teste {idx}: {str(e)}")
            resultados.append({
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo,
                "ground_truth": ground_truth,
                "erro": str(e)
            })
            print(f"❌ Erro: {str(e)[:50]}")
        
        # Rate limiting
        time.sleep(PAUSA_ENTRE_REQUISICOES)
        
        if (idx + 1) % REQUISICOES_POR_LOTE == 0:
            print(f"⏸️  Pausa de {PAUSA_LOTE}s (limite de taxa)...")
            time.sleep(PAUSA_LOTE)
        
        # Salvar incrementalmente a cada 10 testes
        if (idx + 1) % 10 == 0 or idx == total_testes - 1:
            with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)
            print(f"💾 Progresso salvo: {idx+1}/{total_testes} testes completos")

    print("\n\n" + "=" * 80)
    print("✅ RE-EXECUÇÃO CONCLUÍDA!")
    print("=" * 80)
    print(f"\n📁 Resultados salvos em: {ARQUIVO_RESULTADOS_NOVO}")
    print(f"📊 Total de testes executados: {len(resultados)}")
    
    # 6. Comparar com resultados anteriores
    if os.path.exists(ARQUIVO_RESULTADOS_ANTIGO):
        print("\n" + "=" * 80)
        print("📊 COMPARAÇÃO COM RESULTADOS ANTERIORES")
        print("=" * 80)
        
        with open(ARQUIVO_RESULTADOS_ANTIGO, 'r', encoding='utf-8') as f:
            resultados_antigos = json.load(f)
        
        print(f"\nResultados antigos: {len(resultados_antigos)} testes")
        print(f"Resultados novos:   {len(resultados)} testes")
        
        print("\n💡 Execute o script 04_analisar_resultados.py com os novos resultados:")
        print(f"   python 04_analisar_resultados.py")

if __name__ == "__main__":
    retreinar_stride()
