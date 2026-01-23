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