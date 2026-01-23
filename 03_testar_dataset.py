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
PAUSA_ENTRE_REQUISICOES = 2  # segundos
REQUISICOES_POR_LOTE = 10  # Pausa maior a cada lote
PAUSA_LOTE = 10  # segundos

# Configurar logging
logging.basicConfig(filename='teste_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
2. Se vulnerável, especifique o CWE ID mais provável exclusivamente dentre esses CWE (22, 78, 79, 89, 90, 327, 328, 330, 501, 614 ou 643);
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
            resultados_similares = db.similarity_search(codigo_input, k=3)
            contexto_str = ""
            for doc in resultados_similares:
                contexto_str += f"\n---\nExemplo Similar:\n{doc.page_content[:500]}...\n"

            # Fazer análise
            resposta = chain.invoke({
                "codigo_alvo": codigo_input,
                "base_conhecimento": contexto_str
            })

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