# Guia 8 — Amazon Macie: Sensitive Data Discovery + Suppression Rules

**Depende de:** Guia 6 (contexto de exfiltração S3), S02 (integração Security Hub)  
**Próxima sessão:** Guia 9

---

## Objetivos da sessão

| # | Objetivo | Verificável |
|---|----------|-------------|
| O1 | Configurar um discovery job no Macie para varrer um bucket S3 específico | Job criado com status RUNNING/COMPLETE |
| O2 | Interpretar um sensitive data finding — tipo, localização exata do objeto, nível de confiança | Saber ler os campos `type`, `classificationDetails`, `occurrences` |
| O3 | Criar uma suppression rule que filtra falsos-positivos de um bucket de logs de aplicação | Regra com status `ACTIVE`, findings arquivados automaticamente |
| O4 | Descrever como o Macie envia findings ao Security Hub via ASFF e o custo proporcional ao volume | Tabela de custo por dimensão de cobrança |

---

## Parte 1 — Arquitetura do Macie: duas categorias de findings

### 1.1 O que o Macie detecta

 O Amazon Macie gera dois tipos de findings:

**Policy findings** — detectam problemas de segurança em **configurações de buckets S3**. Monitoramento contínuo. Gerados quando uma configuração muda para estado menos seguro *após* habilitação do Macie.

**Sensitive data findings** — detectam **dados sensíveis em objetos S3** individuais. Gerados por discovery jobs ou automated sensitive data discovery.

### 1.2 Policy findings — 6 tipos

| Tipo | O que detecta |
|------|--------------|
| `Policy:IAMUser/S3BlockPublicAccessDisabled` | Block Public Access desabilitado no bucket |
| `Policy:IAMUser/S3BucketEncryptionDisabled` | Default encryption resetada para SSE-S3 |
| `Policy:IAMUser/S3BucketPublic` | ACL ou policy permite acesso anônimo |
| `Policy:IAMUser/S3BucketReplicatedExternally` | Replicação para conta externa à org |
| `Policy:IAMUser/S3BucketSharedExternally` | Compartilhamento com conta externa |
| `Policy:IAMUser/S3BucketSharedWithCloudFront` | Compartilhamento com CloudFront OAI/OAC |

**Comportamento:** ocorrências subsequentes **atualizam** o finding existente. Retenção: 90 dias.

> **Armadilha:** O Macie gera policy finding apenas para mudanças **após** habilitação. Bucket já público antes não gera finding.

### 1.3 Sensitive data findings — 5 tipos

| Tipo | O que detecta |
|------|--------------|
| `SensitiveData:S3Object/Credentials` | AWS secret keys, chaves privadas |
| `SensitiveData:S3Object/CustomIdentifier` | Texto correspondente a custom data identifiers |
| `SensitiveData:S3Object/Financial` | Números de cartão, contas bancárias |
| `SensitiveData:S3Object/Multiple` | Mais de uma categoria no mesmo objeto |
| `SensitiveData:S3Object/Personal` | PII (passaportes, CNHs) ou PHI (dados médicos) |

**Comportamento:** cada detecção gera um finding **novo** (não atualiza anterior). Retenção: 90 dias.

---

## Parte 2 — Discovery Jobs (O1)

### 2.1 Dois modos de descoberta

**Automated Sensitive Data Discovery** (automático): amostra objetos em todos os buckets usando clustering. Cria perfil de sensibilidade por bucket.

**Sensitive Data Discovery Jobs** (targeted): varredura explícita de buckets específicos. Cobertura completa e determinística. Custo: $1,00/GB inspecionado.

### 2.2 Criação do job — 8 etapas no Console

```
Jobs → Create job
  Step 1: Choose S3 buckets (específicos ou por critérios)
  Step 2: Review selections
  Step 3: Schedule (One time | Daily | Weekly | Monthly) + scope (prefixos, tags, size)
  Step 4: Select managed data identifiers (All | Recommended | Specific | None)
  Step 5: Select custom data identifiers
  Step 6: Select allow lists
  Step 7: General settings (name, description)
  Step 8: Review and create
```

### 2.3 Via CLI

```bash
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "Auditoria-bucket-dados-pessoais-2026-05" \
  --s3-job-definition '{
    "bucketDefinitions": [
      {
        "accountId": "111122223333",
        "buckets": ["meu-bucket-dados-pessoais"]
      }
    ]
  }' \
  --managed-data-identifier-selector ALL

# Verificar status
aws macie2 describe-classification-job --job-id <JobId>
```

### 2.4 Dois tipos de saída

- **Sensitive data findings** — apenas para objetos com dados sensíveis detectados
- **Sensitive data discovery results** — para **cada objeto analisado** (inclusive limpos). Essenciais para auditoria de compliance.

---

## Parte 3 — Interpretando um Sensitive Data Finding (O2)

### 3.1 Estrutura principal

```
Finding
├── type                    — Ex: "SensitiveData:S3Object/Credentials"
├── severity (description + score)
├── resourcesAffected
│   ├── s3Bucket (name, arn, publicAccess, encryption)
│   └── s3Object (key, size, etag, encryption)
└── classificationDetails
    ├── originType          — "SENSITIVE_DATA_DISCOVERY_JOB" ou "AUTOMATED_SENSITIVE_DATA_DISCOVERY"
    └── result
        ├── mimeType
        └── sensitiveData[] → category, totalCount, detections[] → type, count, occurrences
```

### 3.2 O campo `occurrences` — localização exata

| Formato | Campo usado | Exemplo |
|---------|-------------|---------|
| Texto livre (`.txt`, `.log`) | `lineRanges` | `{"start": 42, "end": 42}` |
| CSV | `cells` | `{"row": 17, "column": 3, "columnName": "credit_card"}` |
| JSON / JSON Lines | `records` | `{"jsonPath": "$.users[5].ssn"}` |
| Apache Avro / Parquet | `records` | path para o campo no schema |

### 3.3 Nível de confiança

 Severidade baseada em: quantidade de ocorrências + tipo de dado. Managed identifiers usam regex + heurísticas de contexto + checksum (ex: Luhn para cartões).

- **High** — dados de alto impacto em alto volume
- **Medium** — dados moderados ou baixo volume de alto impacto
- **Low** — poucas ocorrências ou dados de impacto menor

### 3.4 Exemplo de finding

```json
{
  "type": "SensitiveData:S3Object/Credentials",
  "severity": {"description": "High", "score": 9},
  "resourcesAffected": {
    "s3Bucket": {"name": "meu-bucket-app-logs"},
    "s3Object": {"key": "deploys/2026/05/config-backup.json", "size": 4096}
  },
  "classificationDetails": {
    "result": {
      "mimeType": "application/json",
      "sensitiveData": [{
        "category": "CREDENTIALS",
        "totalCount": 3,
        "detections": [{
          "type": "AWS_CREDENTIALS",
          "count": 3,
          "occurrences": {
            "records": [
              {"jsonPath": "$.environments[0].aws_secret_key"},
              {"jsonPath": "$.environments[1].aws_secret_key"},
              {"jsonPath": "$.backup.credentials.secret"}
            ]
          }
        }]
      }]
    }
  }
}
```

---

## Parte 4 — Suppression Rules (O3)

### 4.1 O que acontece com findings suprimidos

 Quando uma suppression rule corresponde a um finding:
- Status alterado para **`archived`** automaticamente
- **Não aparece** na view padrão do Console
- **Não é publicado** no EventBridge nem no Security Hub
- **Continua armazenado** por 90 dias (consultável filtrando por `archived`)
- Discovery results correspondentes continuam sendo criados

### 4.2 Exemplo — suprimir PII de bucket de logs

```bash
aws macie2 create-findings-filter \
  --name "Falsos-positivos-bucket-app-logs" \
  --action ARCHIVE \
  --finding-criteria '{
    "criterion": {
      "type": {
        "eqExactMatch": ["SensitiveData:S3Object/Personal"]
      },
      "resourcesAffected.s3Bucket.name": {
        "startsWith": ["app-logs-production"]
      },
      "resourcesAffected.s3Bucket.publicAccess.effectivePermission": {
        "neq": ["PUBLIC"]
      }
    }
  }'
```

 `--action ARCHIVE` = suppression rule. `--action NOOP` = filtro de visualização apenas.

### 4.3 Multi-conta

- **Policy findings**: somente o Macie administrator pode criar suppression rules para a org
- **Sensitive data findings**: admin suprime findings de automated discovery; cada conta suprime findings dos seus próprios jobs

---

## Parte 5 — Integração com Security Hub e Custo (O4)

### 5.1 Publicação de findings

| Tipo de finding | Publicado por padrão? |
|-----------------|----------------------|
| Policy findings (novos e atualizações) | ✅ Sim |
| Sensitive data findings | ❌ Não — habilitar em Settings → Publication settings |

**Motivo:** sensitive data findings podem conter referências a dados sensíveis.

### 5.2 Modelo de custo — 3 dimensões

| Dimensão | Preço | O que cobre |
|----------|-------|-------------|
| Buckets avaliados (inventário) | $0,10/bucket/mês | Monitoramento contínuo + policy findings |
| Objetos monitorados (automated) | $0,01/100k objetos/mês | Rastreamento de amostragem |
| Dados inspecionados | $1,00/GB | Automated discovery (1 GB free) e targeted jobs |

**Free trial:** 30 dias (automated discovery + inventory). Targeted jobs não incluídos.

### 5.3 Exemplos de custo

- **15 buckets, sem jobs:** 15 × $0,10 = $1,50/mês
- **15 buckets + 150 GB automated:** $1,50 + $1,00 + $149,00 = $151,50/mês
- **+ targeted job 200 GB:** + $200,00 = $351,50/mês

---

## Checklist de conclusão

- [ ] **O1** — Consigo criar um discovery job via Console e CLI, e entendo a diferença entre automated discovery e targeted jobs
- [ ] **O2** — Consigo descrever os 5 tipos de sensitive data findings e os 6 de policy findings
- [ ] **O2** — Entendo o campo `occurrences` e como varia por formato (lineRanges vs cells vs records)
- [ ] **O3** — Consigo criar suppression rule via CLI (`--action ARCHIVE`) e sei que findings suprimidos não vão para Security Hub
- [ ] **O4** — Consigo preencher a tabela de 3 dimensões de custo sem consultar o guia
- [ ] **O4** — Sei que sensitive data findings não são publicados no Security Hub por padrão

---

## Exercício de reflexão

**Cenário:** Fintech com buckets:
- `payments-raw`: transações com números de cartão (80 GB)
- `app-logs`: logs HTTP com IPs e user agents (500 GB/mês)
- `ml-training-data`: CPFs sintéticos para testes
- `code-artifacts`: artefatos de build

**Perguntas:**
1. Qual bucket priorizar para targeted job? Qual schedule e tipo de finding esperado?
2. Macie gera `SensitiveData:S3Object/Personal` para `app-logs`. Quais critérios na suppression rule?
3. Para CPFs sintéticos em `ml-training-data`: suppression rule ou allow list? Por quê?
4. Custo mensal do targeted job em `payments-raw` (80 GB)?

**Respostas:**

**1.** `payments-raw` — dados de cartão = maior risco PCI. Schedule mensal. Esperado: `SensitiveData:S3Object/Financial`.

**2.** Critérios: `type` = Personal + `bucket.name` = `app-logs` (exato) + `publicAccess` ≠ PUBLIC.

**3.** **Allow list** — filtra na camada de detecção (antes do finding). Suppression rule suprimiria todos os Personal findings do bucket, arriscando ocultar dados reais futuros.

**4.** 80 GB × $1,00 = **$80,00/mês**.

---

## Referências primárias

- [Types of Macie findings (docs)](https://docs.aws.amazon.com/macie/latest/user/findings-types.html)
- [Creating a sensitive data discovery job (docs)](https://docs.aws.amazon.com/macie/latest/user/discovery-jobs-create.html)
- [Suppressing Macie findings (docs)](https://docs.aws.amazon.com/macie/latest/user/findings-suppression.html)
- [Evaluating Macie findings with Security Hub (docs)](https://docs.aws.amazon.com/macie/latest/user/securityhub-integration.html)
- [Amazon Macie pricing](https://aws.amazon.com/macie/pricing/)
