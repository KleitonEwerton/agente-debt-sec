# 🔄 Melhoria do Sistema STRIDE

## Problema Identificado

Análise inicial mostrou **viés extremo para "Tampering"**:
- Tampering: 94.4% ✅
- Spoofing: 0% ❌ (21/22 casos classificados como Tampering)
- Repudiation: 0% ❌ (10/11 casos classificados como Tampering)
- Acurácia geral STRIDE: 49.3%

## Solução Implementada

### 1. **Prompt Engineering Avançado**

Adicionado ao prompt:
- ✅ **Guia detalhado de STRIDE** com definições claras
- ✅ **Exemplos específicos** por categoria
- ✅ **Regras de decisão críticas** (árvore de decisão)
- ✅ **Mapeamentos comuns** (CWE → STRIDE)
- ✅ **Diferenciação explícita** entre categorias similares

### 2. **Distinções-Chave Adicionadas**

**Spoofing vs Tampering:**
- Spoofing: Falsificação de identidade (MD5 para senhas, tokens fracos)
- Tampering: Modificação de dados (SQL UPDATE/DELETE)

**Information Disclosure vs Tampering:**
- Info Disclosure: LEITURA de dados sensíveis (SQL SELECT)
- Tampering: MODIFICAÇÃO de dados (SQL INSERT/UPDATE/DELETE)

**Repudiation:**
- Ações que permitem negar responsabilidade (logs comprometidos)

### 3. **Regras de Decisão**

```
1. Modificação de dados → Tampering
2. Autenticação/Identidade → Spoofing
3. Leitura de dados sensíveis → Information Disclosure
4. Ocultação de ações → Repudiation
5. Escalação de privilégios → Elevation of Privilege
6. Interrupção de serviço → Denial of Service
```

## Como Executar a Melhoria

### Passo 1: Re-executar Testes com Novo Prompt

```bash
python 05_retreinar_stride.py
```

Este script:
- Usa o **prompt melhorado** com guia STRIDE detalhado
- Re-executa todos os 231 testes
- Salva resultados em `resultados_teste_stride_melhorado.json`
- Permite **continuar de onde parou** se interrompido
- Respeita **rate limiting** do Groq

**Tempo estimado:** ~25-30 minutos (231 testes com rate limiting)

### Passo 2: Comparar Resultados

```bash
python 06_comparar_resultados.py
```

Este script compara:
- ✅ Acurácia STRIDE antes vs depois
- ✅ Desempenho por categoria (Tampering, Spoofing, etc.)
- ✅ Casos que melhoraram/pioraram
- ✅ Matriz de confusão nova vs antiga
- ✅ Principais confusões restantes

### Passo 3: Analisar Novos Resultados

```bash
# Modifique 04_analisar_resultados.py para usar novo arquivo
python 04_analisar_resultados.py
```

Ou analise manualmente o JSON gerado.

## Melhorias Esperadas

**Spoofing** (atualmente 0%):
- MD5/SHA1 para senhas → deve reconhecer como Spoofing
- Tokens fracos (Math.random() para sessões) → Spoofing
- Cookies inseguros para autenticação → Spoofing

**Repudiation** (atualmente 0%):
- Path traversal em logs → Repudiation
- Command injection que apaga logs → Repudiation

**Information Disclosure**:
- SQL SELECT → não classificar mais como Tampering
- Path traversal (leitura) → Information Disclosure

**Tampering** (manter 94.4%):
- SQL INSERT/UPDATE/DELETE → continuar como Tampering
- Command injection que modifica sistema → Tampering

## Arquivos Modificados

1. ✅ `02_auditor_seguranca_rag.py` - Prompt melhorado
2. ✅ `03_testar_dataset.py` - Prompt melhorado
3. ✅ `05_retreinar_stride.py` - Script novo para re-execução
4. ✅ `06_comparar_resultados.py` - Script novo para comparação

## Próximos Passos

Após execução:

1. **Se melhoria for significativa (>60% acurácia STRIDE):**
   - Usar novos resultados no artigo
   - Documentar melhoria como contribuição metodológica

2. **Se melhoria for parcial (50-60%):**
   - Identificar categorias ainda problemáticas
   - Adicionar exemplos específicos no prompt para essas categorias

3. **Se não houver melhoria (<50%):**
   - Considerar fine-tuning do modelo
   - Analisar se problema está no dataset de treino (RAG)
   - Testar modelo diferente (GPT-4, Claude)

## Análise de Custo

- **231 testes** × **~2000 tokens/teste** = ~462K tokens
- Groq (Llama-3.3-70b): **GRATUITO** até 12K TPM
- Tempo com rate limiting: **~30 minutos**

## Backup

Resultados originais preservados em:
- `resultados_teste.json` (original)
- `resultados_teste_stride_melhorado.json` (novo)
- `analise_completa.json` (análise original)

---

**Status:** Pronto para execução  
**Próximo comando:** `python 05_retreinar_stride.py`
