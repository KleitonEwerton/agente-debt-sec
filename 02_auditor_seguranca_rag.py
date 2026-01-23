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

# Prompt Especializado para Mestrado
prompt_template_security = """
Você é um Especialista em Segurança de Software e Análise Estática (SAST).
Sua tarefa é analisar o código Java fornecido em busca de Dívida de Segurança Técnica.

Use o contexto recuperado (exemplos similares do dataset) para guiar sua decisão.

CONTEXTO RECUPERADO (Casos similares conhecidos):
{base_conhecimento}

---
CÓDIGO ALVO PARA ANÁLISE:
{codigo_alvo}
---

Instruções de Resposta:
1. Identifique se o código é VULNERABLE ou SAFE.
2. Se vulnerável, especifique o CWE ID mais provável esclusivamente dentre esses CWE (22, 78, 79, 89, 90, 327, 328, 330, 501, 614 ou 643);
3. Explique brevemente a falha e associe ao conceito de Dívida de Segurança.
4. Se possível, infira a categoria STRIDE baseada no tipo de falha.

Responda estritamente no formato JSON:
{{
  "verdict": "VULNERABLE" | "SAFE",
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "Texto explicativo...",
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
        resultados = db.similarity_search(codigo_input, k=3)
        
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