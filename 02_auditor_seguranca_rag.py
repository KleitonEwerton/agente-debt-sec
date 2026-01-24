# 02_auditor_seguranca_rag.py
import os
import json
from langchain_chroma.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURAÇÕES ---
CAMINHO_DB = "vectorstore_db"
MODELO_EMBEDDING = "sentence-transformers/all-MiniLM-L6-v2"

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

def auditoria_interativa():
    print("--- 🔐 Inicializando Auditor de Dívida de Segurança ---")
    
    # 1. Carregar Vector Store
    embedding_function = HuggingFaceEmbeddings(model_name=MODELO_EMBEDDING)
    if not os.path.exists(CAMINHO_DB):
        print("❌ Erro: Banco de vetores não encontrado. Rode o script 01 primeiro.")
        return

    db = Chroma(persist_directory=CAMINHO_DB, embedding_function=embedding_function)
    
    # 2. Loop de Interação
    while True:
        print("\n" + "="*50)
        print("Cole o código Java abaixo para análise (ou 'sair'):")
        # Leitura de múltiplas linhas para permitir colar código
        linhas = []
        while True:
            linha = input()
            if linha == "sair": return
            if linha == "FIM": break # Palavra chave para processar
            linhas.append(linha)
        
        codigo_input = "\n".join(linhas)
        
        if not codigo_input.strip(): continue

        print("🔍 Buscando casos similares na base de conhecimento...")
        # Recupera exemplos similares (Few-Shot Learning via RAG)
        resultados = db.similarity_search(codigo_input, k=1)
        
        contexto_str = ""
        for doc in resultados:
            contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"

        print("🤖 Consultando LLM (Groq)...")
        prompt = ChatPromptTemplate.from_template(prompt_template_security)
        
        try:
            # Usando Llama-3-70b ou similar (excelente para código)
            llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile")
            chain = prompt | llm
            
            resposta = chain.invoke({
                "codigo_alvo": codigo_input, 
                "base_conhecimento": contexto_str
            })
            
            print("\n📊 === RELATÓRIO DE AUDITORIA ===")
            print(resposta.content)
            
        except Exception as e:
            print(f"❌ Erro na API Groq: {e}")

if __name__ == "__main__":
    print("Dica: Digite 'FIM' em uma nova linha para enviar o código.")
    auditoria_interativa()