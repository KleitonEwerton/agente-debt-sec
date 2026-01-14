import os
import shutil
import json
import random
from langchain_core.documents import Document
from langchain_chroma.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

# --- CONFIGURAÇÕES ---
ARQUIVO_ENTRADA = "dataset_treino_mestrado.jsonl"
ARQUIVO_TESTE = "dataset_teste_reservado.jsonl"
CAMINHO_DB = "vectorstore_db"
MODELO_EMBEDDING = "sentence-transformers/all-MiniLM-L6-v2"
PERCENTUAL_TESTE = 0.20

def carregar_e_splitar_dados():
	print(f"--- 📂 Carregando Dataset: {ARQUIVO_ENTRADA} ---")
	
	if not os.path.exists(ARQUIVO_ENTRADA):
		print(f"❌ Erro: Arquivo {ARQUIVO_ENTRADA} não encontrado.")
		return []

	todos_registros = []
	
	with open(ARQUIVO_ENTRADA, 'r', encoding='utf-8') as f:
		for linha in f:
			if linha.strip():
				try:
					todos_registros.append(json.loads(linha))
				except json.JSONDecodeError:
					continue
	
	total = len(todos_registros)
	print(f"📊 Total de registros encontrados: {total}")

	random.seed(42)
	random.shuffle(todos_registros)

	qtd_teste = int(total * PERCENTUAL_TESTE)
	dados_teste = todos_registros[:qtd_teste]
	dados_treino = todos_registros[qtd_teste:]

	print(f"✂️  Split realizado: {len(dados_treino)} para Base de Conhecimento (RAG) | {len(dados_teste)} reservados para Teste.")

	with open(ARQUIVO_TESTE, 'w', encoding='utf-8') as f:
		for item in dados_teste:
			f.write(json.dumps(item) + "\n")
	print(f"💾 Dataset de teste salvo em: {ARQUIVO_TESTE}")

	return dados_treino

def transformar_em_documentos(dados_json):
	"""Converte o JSON bruto em objetos Document do LangChain"""
	docs = []
	for item in dados_json:
		# CORREÇÃO DO ERRO AQUI:
		# O campo 'output' vem como String (devido ao json.dumps na geração).
		# Precisamos converter de volta para Dict (json.loads).
		output_data = item.get('output', {})
		
		if isinstance(output_data, str):
			try:
				output_data = json.loads(output_data)
			except json.JSONDecodeError:
				# Se falhar, pula este registro ou usa um dict vazio
				print(f"⚠️ Erro de parse no ID: {item.get('id', 'unknown')}")
				continue
		
		# Agora output_data é um dicionário seguro, podemos acessar ['weakness']
		try:
			cwe_id = output_data['weakness']['id']
			verdict = output_data['verdict']
		except KeyError:
			cwe_id = "Unknown"
			verdict = "Unknown"

		conteudo_vetor = f"""
		INSTRUCTION: {item.get('instruction', '')}
		CODE SNIPPET:
		{item.get('input', '')}
		ANALYSIS (Ground Truth):
		{item.get('output', '')} 
		"""
		
		metadata = {
			"cwe_id": cwe_id,
			"verdict": verdict,
			"source": "OWASP Benchmark"
		}
		
		docs.append(Document(page_content=conteudo_vetor, metadata=metadata))
	
	return docs

def criar_vectorstore():
	dados_treino = carregar_e_splitar_dados()
	if not dados_treino: return

	documentos = transformar_em_documentos(dados_treino)

	text_splitter = RecursiveCharacterTextSplitter(
		chunk_size=2000,
		chunk_overlap=200
	)
	chunks = text_splitter.split_documents(documentos)
	print(f"📦 Total de chunks para vetorização: {len(chunks)}")

	if os.path.exists(CAMINHO_DB):
		shutil.rmtree(CAMINHO_DB)

	print(f"\n🧠 Inicializando Embeddings ({MODELO_EMBEDDING})...")
	embedding_model = HuggingFaceEmbeddings(model_name=MODELO_EMBEDDING)

	print("⚡ Vetorizando e persistindo no ChromaDB...")
	tamanho_lote = 100
	
	db = None
	for i in tqdm(range(0, len(chunks), tamanho_lote), desc="Processando Lotes"):
		lote = chunks[i:i + tamanho_lote]
		if db is None:
			db = Chroma.from_documents(lote, embedding_model, persist_directory=CAMINHO_DB)
		else:
			db.add_documents(lote)
			
	print(f"\n✅ Base de Conhecimento criada em '{CAMINHO_DB}'!")

if __name__ == "__main__":
	criar_vectorstore()