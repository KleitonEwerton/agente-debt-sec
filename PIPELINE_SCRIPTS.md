# 🔐 Agente de Análise de Security Debt com RAG + STRIDE

Sistema de análise automatizada de vulnerabilidades em código Java usando RAG (Retrieval-Augmented Generation) com classificação STRIDE.

---

## 📋 Pipeline de Execução (5 Scripts)

### **Script 00: Geração do Dataset**
📄 `00_gerar_dataset_final.py`

**Objetivo**: Gera dataset a partir do OWASP Benchmark Java com metadados CWE/CAPEC

**Entrada**: 
- Código-fonte OWASP Benchmark (`src/main/java/...`)
- `expectedresults-1.2.csv`
- `cwec_v4.18.xml`
- `capec_v3.9.xml`

**Saída**:
- `dataset_treino_mestrado.jsonl` (80% dos dados)
- `dataset_teste_reservado.jsonl` (20% dos dados)

**Características**:
- ✅ Inclui: CWE ID, nome, descrição, CAPEC IDs
- ❌ **NÃO inclui STRIDE** (economia de tokens + evita ensinar mapeamentos incorretos)
- Código limpo (remove licenças e imports desnecessários)

**Quando executar**: Apenas se você tiver o repositório OWASP Benchmark completo localmente

---

### **Script 01: Construção da Base de Conhecimento**
📄 `01_construir_base_conhecimento.py`

**Objetivo**: Vetoriza dataset de treino no ChromaDB para busca por similaridade (RAG)

**Entrada**:
- `dataset_treino_mestrado.jsonl`

**Saída**:
- `vectorstore_db/` (banco vetorial ChromaDB)

**Características**:
- Embedding: `sentence-transformers/all-MiniLM-L6-v2`
- Chunk size: 2000 tokens, overlap: 200
- Split estratificado 80/20 (se ainda não tiver dataset de teste)

**Quando executar**: 
- Após gerar/modificar dataset de treino
- Se deletou a pasta `vectorstore_db/`

---

### **Script 02: Execução dos Testes**
📄 `02_retreinar_stride.py`

**Objetivo**: Executa análise de segurança em todos os casos de teste usando LLM + RAG

**Entrada**:
- `dataset_teste_reservado.jsonl` (código a ser analisado)
- `vectorstore_db/` (exemplos similares via RAG)
- Prompt com **guia STRIDE detalhado** (85+ linhas)

**Saída**:
- `resultados_teste_stride_melhorado.json`

**Características**:
- LLM: Groq (Llama-3.3-70b-versatile, temperature=0)
- RAG: k=1 (busca 1 exemplo similar para few-shot learning)
- Rate limiting: 2s entre requests, 15s a cada 5 requests
- Salvamento incremental a cada 10 testes
- LLM **infere STRIDE** via prompt (não usa ground truth)

**Quando executar**:
- Após construir/atualizar base vetorial
- Quando modificar o prompt
- Para avaliar desempenho do sistema

---

### **Script 03: Análise Geral dos Resultados**
📄 `03_analisar_resultados.py`

**Objetivo**: Análise completa em 4 dimensões (CWE, Verdict, Combinado, STRIDE)

**Entrada**:
- `resultados_teste_stride_melhorado.json`

**Saída**:
- `analise_resultados_melhorados.json`
- Relatório console detalhado

**Métricas calculadas**:
1. **CWE Isolado**: Acurácia de reconhecimento do tipo de vulnerabilidade
2. **Verdict Isolado**: Precisão/Recall/F1 para VULNERABLE vs SAFE
3. **Combinado**: CWE correto E Verdict correto (mais rigoroso)
4. **STRIDE**: Classificação segundo modelo de ameaças STRIDE

**⚠️ ATENÇÃO**: Compara STRIDE com ground truth do dataset (que pode estar incorreto)

**Quando executar**: Após executar testes (script 02)

---

### **Script 04: Análise STRIDE com Mapeamento Correto** ⭐
📄 `04_analisar_stride_correto.py`

**Objetivo**: Valida STRIDE usando **mapeamento acadêmico correto**, não ground truth

**Entrada**:
- `resultados_teste_stride_melhorado.json`
- **Mapeamento CWE→STRIDE.csv** (fonte: análise acadêmica)

**Saída**:
- `analise_stride_correto.json`
- Relatório detalhado com matriz de confusão

**Diferença do Script 03**:
- ✅ Usa mapeamento baseado em análise técnica real
- ✅ Aceita **múltiplos STRIDE** por CWE (contexto importa!)
- ✅ Ignora ground truth potencialmente incorreto do dataset

**Mapeamento atual** (Fonte: CSV fornecido):
```python
CWE-89:  ["Tampering", "Information Disclosure"]  # SQL Injection
CWE-79:  ["Tampering", "Elevation of Privilege"]  # XSS
CWE-78:  ["Elevation of Privilege", "Tampering"]  # Command Injection
CWE-330: ["Spoofing", "Information Disclosure"]   # Weak Random
CWE-90:  ["Information Disclosure", "Elevation of Privilege"]  # LDAP Injection
CWE-643: ["Information Disclosure", "Elevation of Privilege"]  # XPath Injection
CWE-501: ["Elevation of Privilege", "Spoofing"]   # Trust Boundary
# ... demais CWEs com single/multiple STRIDE
```

**Quando executar**: 
- **Use ESTE ao invés do Script 03** para análise STRIDE confiável
- Após atualizar mapeamento CWE→STRIDE.csv

---

## 🎯 Fluxo Completo de Execução

```bash
# 1. Gerar dataset (apenas se tiver OWASP Benchmark local)
python 00_gerar_dataset_final.py

# 2. Construir base vetorial
python 01_construir_base_conhecimento.py

# 3. Executar testes (pode demorar ~15 min para 231 testes)
python 02_retreinar_stride.py

# 4. Analisar resultados com mapeamento CORRETO ⭐
python 04_analisar_stride_correto.py

# 5. (Opcional) Análise geral incluindo outras métricas
python 03_analisar_resultados.py
```

---

## 📊 Resultados Atuais

### ✅ Com Mapeamento Correto (Script 04)
- **CWE**: 83.3%
- **STRIDE**: **88.9%** 🎉

### ❌ Com Ground Truth Incorreto (Script 03)
- **CWE**: 83.3%
- **STRIDE**: 33.3% (baixo porque ground truth está errado)

---

## 💡 Decisões de Design

### Por que STRIDE não está no dataset?
1. **Economia de tokens**: Reduz custo da API Groq
2. **Evita ensinar errado**: Ground truth pode ter mapeamentos incorretos
3. **LLM infere melhor**: Prompt detalhado + RAG > memorização

### Por que múltiplos STRIDE por CWE?
O mesmo tipo de vulnerabilidade pode ter impactos diferentes:
- **SQL Injection SELECT** → Information Disclosure (lê dados)
- **SQL Injection UPDATE** → Tampering (modifica dados)
- **XSS roubar cookies** → Information Disclosure
- **XSS deface** → Tampering

### Por que Script 04 > Script 03?
O Script 03 compara com ground truth que foi gerado com mapeamento simplista. 
O Script 04 usa mapeamento validado academicamente que reflete impacto real.

---

## 📝 Arquivos de Configuração

### `.env`
```env
GROQ_API_KEY=your_groq_api_key_here
```

### `Mapeamento CWE para STRIDE.csv`
Contém mapeamento acadêmico validado com racional técnico para cada CWE.

---

## 🔄 Quando Re-executar Cada Script

| Cenário | Scripts a Executar |
|---------|-------------------|
| Primeira execução | 00 → 01 → 02 → 04 |
| Modificou prompt | 02 → 04 |
| Atualizou mapeamento STRIDE | Apenas 04 |
| Deletou vectorstore_db/ | 01 → 02 → 04 |
| Novo dataset | 00 → 01 → 02 → 04 |

---

## 📈 Próximos Passos

1. ✅ Validar CWE-328 e CWE-89 (2 erros restantes)
2. ✅ Documentar resultados para dissertação
3. ⬜ Expandir para outras linguagens (Python, JavaScript)
4. ⬜ Integrar com pipelines CI/CD

---

## 🎓 Contexto Acadêmico

Este sistema faz parte de pesquisa de mestrado sobre **Technical Security Debt** usando:
- **RAG (Retrieval-Augmented Generation)** para few-shot learning
- **STRIDE** para classificação de ameaças
- **CWE/CAPEC** para taxonomia de vulnerabilidades
- **LLM (Llama-3.3-70b)** para análise semântica de código

**Principais contribuições**:
1. Demonstração que ground truth pode estar incorreto (33% → 89% com mapeamento correto)
2. STRIDE contextual (múltiplas categorias por CWE)
3. RAG supera fine-tuning para análise de segurança (economia + flexibilidade)
