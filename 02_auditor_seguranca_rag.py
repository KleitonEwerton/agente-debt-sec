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
4. If possible, infer the STRIDE category based on the type of flaw.

IMPORTANT: Clearly distinguish between the CWEs:
- CWE-327 and CWE-328 are about weak or insecure cryptographic algorithms (e.g., MD5, SHA1, DES, AES with weak keys).
- CWE-89 is about SQL Injection, where unsanitized input is used in SQL queries.
- CWE-79 is about Cross-Site Scripting (XSS), where unsanitized input is reflected in HTML.
- CWE-78 is about OS Command Injection.
- CWE-22 is about Path Traversal.
- CWE-90 is about LDAP Injection.
- CWE-330 is about insufficiently random values.
- CWE-501 is about trust of untrusted input.
- CWE-614 is about insecure transport of credentials.
- CWE-643 is about XPath Injection.

Do not confuse weak cryptography (CWE-327/328) with SQL Injection (CWE-89), even if the code uses hashing for passwords.

Respond strictly in JSON format:
{{
  "verdict": "VULNERABLE" | "SAFE",
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "Explanatory text...",
  "stride": "Category"
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