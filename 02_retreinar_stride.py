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
PAUSA_ENTRE_REQUISICOES = 4  # segundos
REQUISICOES_POR_LOTE = 5
PAUSA_LOTE = 20

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
1. Identify if code contains a CWE weakness PATTERN (22, 78, 79, 89, 90, 327, 328, 330, 501, 614, or 643).
2. If no weakness pattern detected, return "None" for cwe_id.
3. Briefly explain your decision.
4. If weakness detected, classify according to STRIDE threat model.

IMPORTANT: Focus on PATTERN DETECTION, not exploitability:
- SQL Injection pattern: User input concatenated in SQL query (even if using prepareCall)
- XSS pattern: User input reflected in HTML/JavaScript output
- Command Injection pattern: User input used in Runtime.exec() or ProcessBuilder
- Path Traversal pattern: User input used to construct file paths
- Weak Crypto pattern: MD5, SHA1, DES, RC4, or other deprecated algorithms

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
Choose ONE category by analyzing operation type:

**Tampering** (WRITE/MODIFY operations):
- SQL: INSERT/UPDATE/DELETE with user input
- Command injection modifying files/system
- Path traversal WRITING files

**Information Disclosure** (READ operations):
- SQL: SELECT with user input
- Path traversal READING files
- XSS stealing cookies
- Weak crypto for stored data

**Spoofing** (AUTHENTICATION context):
- Weak crypto for passwords (MD5, SHA1)
- Weak random for session tokens
- Insecure auth cookies

**Elevation of Privilege** (PRIVILEGE context):
- Command injection as root/admin
- SQL bypassing access controls
- Path traversal accessing system files

**Repudiation**: Log manipulation
**Denial of Service**: Resource exhaustion

Decision hierarchy:
1. AUTH + weak crypto/random → Spoofing
2. Root/admin execution → Elevation of Privilege
3. WRITE/MODIFY → Tampering
4. READ sensitive → Information Disclosure

Key examples:
- SELECT query → Information Disclosure
- INSERT/UPDATE/DELETE → Tampering
- Runtime.exec() as root → Elevation of Privilege
- MD5 password hash → Spoofing

Respond strictly in JSON format:
{{
  "cwe_id": "CWE-XXX" | "None",
  "explanation": "Explanatory text...",
  "stride": "Tampering" | "Spoofing" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege" | "None"
}}

Note: If no weakness pattern detected, then cwe_id="None" and stride="None".
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
