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
PAUSA_ENTRE_REQUISICOES = 2  # segundos
REQUISICOES_POR_LOTE = 5
PAUSA_LOTE = 15

logging.basicConfig(filename='retreino_stride_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Prompt melhorado com Foco em CWE + Contexto STRIDE
prompt_template_security = """
You are a Software Security Expert. Analyze the Java code for CWE patterns and STRIDE threats.

Reference Context (Use carefully, but prioritize the Explicit Patterns below):
{base_conhecimento}

---
TARGET CODE:
{codigo_alvo}
---

===== 1. CWE PATTERN DEFINITIONS (Primary Goal) =====
Look strictly for these syntax patterns. If none match, return CWE: "None".

- CWE-89 (SQL Injection): Unsanitized input concatenated into SQL (e.g., "SELECT..." + var).
- CWE-79 (XSS): Unsanitized input reflected in HTML/JSP/JS output.
- CWE-78 (Command Injection): User input in Runtime.exec(), ProcessBuilder.
- CWE-22 (Path Traversal): User input used to construct File/Path.
- CWE-327/328 (Weak Crypto): Usage of MD5, SHA1, DES, RC4, or "AES" without mode details.
- CWE-330 (Weak Random): Math.random() or java.util.Random for security critical contexts.
- CWE-90 (LDAP Injection): Unsanitized input in search filters.
- CWE-501 (Trust Boundary): Session attributes set with untrusted input.
- CWE-614 (Insecure Cookie): Cookie.setSecure(false) or missing HttpOnly.
- CWE-643 (XPath Injection): Unsanitized input in XPath expression.

===== 2. STRIDE LOGIC RULES (Secondary Goal) =====
Once a CWE is found, determine the specific threat based on the OPERATION:

Rule A: Analyze the Operation Verb
- INSERT, UPDATE, DELETE, MODIFY file -> Write Context
- SELECT, READ file, GET data -> Read Context
- EXECUTE process, RUN system command -> Execute Context

Rule B: Map to STRIDE
- IF Write Context (e.g., SQL INSERT) -> **Tampering**
- IF Read Context (e.g., SQL SELECT) -> **Information Disclosure**
- IF Execute Context as Root/Admin -> **Elevation of Privilege**
- IF Authentication Context (Passwords/Hashes/Cookies) -> **Spoofing**

===== RESPONSE FORMAT =====
Respond strictly in JSON format:
{{
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "1. Pattern: Detected [CWE Name] in variable 'x'. 2. Context: The code performs a [INSERT/SELECT/EXEC] operation. 3. Threat: Since it is a [Write/Read] operation, the STRIDE is [Category].",
  "stride": "Tampering" | "Spoofing" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege" | "None"
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
                # Encontrar o último teste_idx processado (não usa len, pois usuário pode ter apagado itens)
                if resultados:
                    teste_inicial = max(item['teste_idx'] for item in resultados) + 1
                print(f"✓ Continuando do teste {teste_inicial} (total de {len(resultados)} resultados salvos)")

    # 4. Inicializar LLM
    prompt = ChatPromptTemplate.from_template(prompt_template_security)
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile")
    chain = prompt | llm

    # 5. Executar testes
    print(f"\n🚀 Iniciando testes ({teste_inicial} até {total_testes})...\n")
    print("💾 Salvamento automático após cada resposta\n")
    
    for idx in range(teste_inicial, total_testes):
        item = dados_teste[idx]
        codigo = item.get('input', '')
        ground_truth = item.get('output', '{}')
        
        print(f"🔍 Teste {idx+1}/{total_testes}... ", end='', flush=True)
        
        try:
            # Buscar contexto RAG
            resultados_busca = db.similarity_search(codigo, k=3)
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
            
            # Salvar IMEDIATAMENTE após cada resposta (proteção contra rate limit)
            with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)
            
            logging.info(f"Teste {idx} concluído com sucesso")
            print(f"✅ (💾 {len(resultados)} salvos)")
            
        except Exception as e:
            logging.error(f"Erro no teste {idx}: {str(e)}")
            resultados.append({
                "teste_idx": idx,
                "id_original": item.get('id', f'teste_{idx}'),
                "codigo_input": codigo,
                "ground_truth": ground_truth,
                "erro": str(e)
            })
            
            # Salvar também em caso de erro
            with open(ARQUIVO_RESULTADOS_NOVO, 'w', encoding='utf-8') as f:
                json.dump(resultados, f, indent=2, ensure_ascii=False)
            
            print(f"❌ Erro: {str(e)[:50]}")
        
        # Rate limiting
        time.sleep(PAUSA_ENTRE_REQUISICOES)
        
        if (idx + 1) % REQUISICOES_POR_LOTE == 0:
            print(f"⏸️  Pausa de {PAUSA_LOTE}s (limite de taxa)...")
            time.sleep(PAUSA_LOTE)

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
        
        print("\n💡 Execute o script 03_comparar_resultados.py para comparar resultados:")
        print(f"   python 03_comparar_resultados.py")

if __name__ == "__main__":
    retreinar_stride()
