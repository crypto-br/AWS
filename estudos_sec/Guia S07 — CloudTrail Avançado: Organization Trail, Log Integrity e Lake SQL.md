# Guia S07 — CloudTrail Avançado: Organization Trail, Log Integrity e Lake SQL

**Depende de:** S03 (correlação CloudTrail), S06 (data events vs management events)  
**Próxima sessão:** S08

---

## ⚠️ Correção em relação ao plano original

> **Status [INCERTO] — verifique antes de estudar o Lake:**
>
> Durante a pesquisa para este guia, foi localizada uma página
> `cloudtrail-lake-service-availability-change.html` indicando que o
> **CloudTrail Lake estaria fechado para novos clientes a partir de 31/05/2026**.
> A migração recomendada seria para **Amazon CloudWatch + OpenSearch** (Logs QL / SQL / PPL).
>
> No entanto, a página de preços oficial (`aws.amazon.com/cloudtrail/pricing/`),
> consultada em 22/05/2026, continua descrevendo um período gratuito de 30 dias
> para novos clientes no Lake — sem menção a encerramento iminente.
>
> **O que fazer:** Verifique em
> `https://aws.amazon.com/cloudtrail/features/` e
> `https://aws.amazon.com/about-aws/whats-new/` se há anúncio de descontinuação.
>
> **Por que estudar o Lake mesmo assim?**
> Clientes existentes continuam usando normalmente. O modelo de consulta SQL
> ainda é valioso para entender event data stores, e a sintaxe é transferível
> para ferramentas similares (Athena, OpenSearch). As partes O1, O2 e O4
> não dependem do Lake em nada.

---

## Objetivos da sessão

| # | Objetivo | Verificável |
|---|----------|-------------|
| O1 | Criar uma Organization trail no Management Account que captura management events de todas as contas-membro | Trail visível nas contas-membro como read-only |
| O2 | Habilitar log file integrity validation e explicar o mecanismo de hash chain que garante integridade | Arquivo de digest em S3 + campo `previousDigestHashValue` |
| O3 | Escrever query SQL no CloudTrail Lake detectando `AssumeRole` com `errorCode = 'AccessDenied'` nas últimas 24h | Query retorna resultados ou conjunto vazio validado |
| O4 | Diferenciar management events vs. data events vs. Insights e o custo incremental de cada | Tabela de custo por tipo de evento |

---

## Alocação de tempo sugerida

| Bloco | Tema | Tempo |
|-------|------|-------|
| 1 | Organization Trail — pré-requisitos e criação | 20 min |
| 2 | Log File Integrity Validation — hash chain | 15 min |
| 3 | CloudTrail Lake — SQL e schema de eventos | 20 min |
| 4 | Tipos de evento e custo incremental | 15 min |
| Revisão | Exercício de reflexão + checklist | 5 min |

---

## Parte 1 — Organization Trail (O1)

### 1.1 O que é e por que importa

[FATO] Uma Organization trail é uma trail do CloudTrail criada no Management Account de uma AWS Organization que **replica automaticamente a configuração para todas as contas-membro**, garantindo captura centralizada de eventos. A trail fica visível em cada conta-membro, mas os membros **não podem modificá-la nem apagá-la**.

**Vantagens sobre trails individuais por conta:**
- Cobertura automática de contas novas adicionadas à org
- Logs centralizados em um único bucket do Management Account
- O Management Account é o único com acesso ao bucket por padrão

### 1.2 Pré-requisitos

[FATO] Antes de criar a organization trail, três condições devem ser satisfeitas:

**1. All Features habilitado na Organization:**
```bash
aws organizations enable-all-features
```

**2. Trusted access do CloudTrail habilitado:**
```bash
aws organizations enable-aws-service-access \
  --service-principal cloudtrail.amazonaws.com
```

**3. Permissões adequadas no Management Account:**
[FATO] O IAM principal que cria a trail precisa de `AWSCloudTrail_FullAccess` ou equivalente. Contas-membro não têm permissão para criar organization trails.

### 1.3 Bucket S3 — política necessária

[FATO] O bucket que receberá os logs precisa de uma política com **três statements** específicos para organization trails:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::MEU-BUCKET",
      "Condition": {
        "StringEquals": {
          "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:MGMT-ACCOUNT-ID:trail/minha-org-trail"
        }
      }
    },
    {
      "Sid": "AWSCloudTrailWriteManagementAccount",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::MEU-BUCKET/AWSLogs/MGMT-ACCOUNT-ID/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:MGMT-ACCOUNT-ID:trail/minha-org-trail"
        }
      }
    },
    {
      "Sid": "AWSCloudTrailWriteOrganization",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::MEU-BUCKET/AWSLogs/o-ORGANIZATION-ID/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:MGMT-ACCOUNT-ID:trail/minha-org-trail"
        }
      }
    }
  ]
}
```

**Por que três statements?**
- Statement 1: permite que o CloudTrail verifique o ACL do bucket antes de escrever
- Statement 2: path para logs do próprio Management Account (`AWSLogs/ACCOUNT-ID/`)
- Statement 3: path para logs das contas-membro (`AWSLogs/o-ORG-ID/MEMBER-ACCOUNT-ID/`)

### 1.4 Criação via CLI

```bash
# 1. Criar a trail (multi-region + organization)
aws cloudtrail create-trail \
  --name minha-org-trail \
  --s3-bucket-name meu-bucket-logs \
  --is-organization-trail \
  --is-multi-region-trail

# 2. Habilitar logging
aws cloudtrail start-logging --name minha-org-trail

# 3. Verificar status
aws cloudtrail get-trail-status --name minha-org-trail
```

### 1.5 Estrutura de paths no S3

[FATO] Os logs de contas-membro ficam sob um diretório com o ID da organization:

```
s3://MEU-BUCKET/
└── AWSLogs/
    ├── MGMT-ACCOUNT-ID/           ← logs da conta de gestão
    │   └── CloudTrail/us-east-1/2026/05/21/
    └── o-ORGANIZATION-ID/         ← logs de todas as contas-membro
        ├── MEMBER-ACCOUNT-1/
        │   └── CloudTrail/us-east-1/2026/05/21/
        └── MEMBER-ACCOUNT-2/
            └── CloudTrail/us-east-1/2026/05/21/
```

### 1.6 Service-linked role criada automaticamente

[FATO] Ao criar a organization trail pelo Console, a AWS cria automaticamente a service-linked role `AWSServiceRoleForCloudTrail`. Quando uma nova conta é adicionada à org, a organization trail e a service-linked role são adicionadas automaticamente. Quando uma conta é removida, a trail e a role são removidas — mas os logs gerados antes da remoção permanecem no bucket.

---

## Parte 2 — Log File Integrity Validation (O2)

### 2.1 O problema que o recurso resolve

[FATO] Os logs do CloudTrail ficam em um bucket S3. Por padrão, se um atacante comprometer uma conta com permissões suficientes, pode apagar ou modificar os arquivos de log para encobrir rastros. A **Log File Integrity Validation** resolve isso criando uma cadeia de assinaturas criptográficas verificável externamente.

### 2.2 Como funciona — os digest files

[FATO] Quando a validação está habilitada, o CloudTrail cria um arquivo chamado **digest file** a cada hora. Cada digest file:
- Lista todos os arquivos de log entregues no bucket durante aquela hora
- Contém o **hash SHA-256** de cada arquivo de log listado
- É **assinado digitalmente** usando SHA-256 com RSA (algoritmo `SHA256withRSA`)
- Contém o hash e a assinatura do digest file **anterior** → hash chain

### 2.3 Estrutura do digest file

```json
{
  "awsAccountId": "111122223333",
  "digestStartTime": "2026-05-21T14:00:00Z",
  "digestEndTime": "2026-05-21T15:00:00Z",
  "digestS3Bucket": "meu-bucket-logs",
  "digestSignatureAlgorithm": "SHA256withRSA",
  "previousDigestHashValue": "97fb791cf91ffc440d274f8190dbdd9aa09c34432aba82739df18b6d3c13df2d",
  "previousDigestHashAlgorithm": "SHA-256",
  "previousDigestSignature": "50887ccffad4c002b97caa37cc9dc626e3...",
  "logFiles": [
    {
      "s3Object": "AWSLogs/111122223333/CloudTrail/us-east-1/2026/05/21/...",
      "hashValue": "abc123...",
      "hashAlgorithm": "SHA-256"
    }
  ]
}
```

**Campos críticos para a chain:**
- `previousDigestHashValue` → hash SHA-256 do digest anterior
- `previousDigestSignature` → assinatura RSA do digest anterior

[FATO] Os digest files ficam em path separado: `s3://BUCKET/AWSLogs/ACCOUNT-ID/CloudTrail-Digest/REGION/YYYY/MM/DD/`

### 2.4 Por que a hash chain é difícil de falsificar

[FATO] Para adulterar um log sem detecção, um atacante precisaria:
1. Modificar o arquivo de log
2. Recalcular o hash SHA-256 correto
3. Atualizar o digest file com o novo hash
4. **Re-assinar** o digest file com a chave privada RSA da AWS (que o atacante não possui)
5. Atualizar todos os digest files posteriores (que referenciam este)

A chave privada **nunca sai da AWS**. Se um digest file for **apagado**, a chain fica quebrada e a validação detecta o gap.

### 2.5 Habilitando via CLI

```bash
# Habilitar ao criar nova trail
aws cloudtrail create-trail \
  --name minha-trail \
  --s3-bucket-name meu-bucket \
  --enable-log-file-validation

# Habilitar em trail existente
aws cloudtrail update-trail \
  --name minha-trail \
  --enable-log-file-validation

# Validar arquivos em um intervalo
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:111122223333:trail/minha-trail \
  --start-time 2026-05-20T00:00:00Z \
  --end-time 2026-05-21T23:59:59Z \
  --verbose
```

### 2.6 Hardening adicional

[CONSENSO] Para aumentar a proteção dos digest files:
- Habilitar **S3 MFA Delete** no bucket (impede exclusão sem MFA física)
- Configurar **S3 Object Lock** em modo COMPLIANCE (imutabilidade por período definido)
- Restringir permissões de `s3:DeleteObject` via SCPs para os caminhos `CloudTrail-Digest/`

---

## Parte 3 — CloudTrail Lake SQL (O3)

### 3.1 O que é o CloudTrail Lake

[FATO] O CloudTrail Lake é um repositório de eventos gerenciado (event data store) que permite armazenar e consultar eventos CloudTrail usando SQL. Diferente de trails que gravam em S3, o Lake mantém os dados internamente e os expõe via interface de query SQL no Console e CLI.

### 3.2 Dialeto SQL suportado

[FATO] O CloudTrail Lake usa **Trino SQL**. Restrições importantes:
- Apenas instruções `SELECT` são suportadas
- O `FROM` aponta para o ID do event data store, não para um nome de tabela
- Funções de data/hora como `DATE_ADD` e `NOW()` são suportadas

### 3.3 Schema principal de eventos

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `eventname` | `string` | Nome da API chamada (ex: `AssumeRole`) |
| `eventsource` | `string` | Serviço AWS (ex: `sts.amazonaws.com`) |
| `eventtime` | `timestamp` | Quando o evento ocorreu |
| `awsregion` | `string` | Região do evento |
| `sourceipaddress` | `string` | IP de origem |
| `useragent` | `string` | User agent (SDK, CLI, console) |
| `errorcode` | `string` | Código de erro, se houver |
| `errormessage` | `string` | Mensagem de erro detalhada |
| `useridentity` | `struct` | Identidade que fez a chamada |

**Campos do struct `useridentity`:**
```
useridentity.type          -- ex: "AssumedRole", "IAMUser", "Root"
useridentity.arn           -- ARN completo
useridentity.accountid     -- ID da conta de origem
useridentity.principalid   -- ID do principal
useridentity.accesskeyid   -- Access key usada
```

### 3.4 Query O3 — AssumeRole com AccessDenied nas últimas 24h

```sql
SELECT
  eventtime,
  useridentity.arn                          AS caller_arn,
  useridentity.accountid                    AS caller_account,
  useridentity.type                         AS identity_type,
  sourceipaddress,
  useragent,
  requestparameters,
  errormessage
FROM <event_data_store_id>
WHERE eventname = 'AssumeRole'
  AND errorcode = 'AccessDenied'
  AND eventtime > DATE_ADD('hour', -24, NOW())
ORDER BY eventtime DESC
LIMIT 200
```

**Variação — agrupar por caller:**
```sql
SELECT
  useridentity.arn    AS caller_arn,
  sourceipaddress,
  COUNT(*)            AS tentativas
FROM <event_data_store_id>
WHERE eventname = 'AssumeRole'
  AND errorcode = 'AccessDenied'
  AND eventtime > DATE_ADD('hour', -24, NOW())
GROUP BY useridentity.arn, sourceipaddress
ORDER BY tentativas DESC
LIMIT 50
```

**Variação — incluir outros erros de STS (padrão de enumeração):**
```sql
SELECT
  eventtime, eventname, errorcode,
  useridentity.arn AS caller_arn,
  sourceipaddress
FROM <event_data_store_id>
WHERE eventsource = 'sts.amazonaws.com'
  AND errorcode IN ('AccessDenied', 'InvalidClientTokenId', 'ExpiredTokenException')
  AND eventtime > DATE_ADD('hour', -24, NOW())
ORDER BY eventtime DESC
LIMIT 200
```

### 3.5 Por que `AssumeRole` + `AccessDenied` é sinal de alerta

[CONSENSO] Uma sequência de `AssumeRole` negados pode indicar:
- Tentativa de **privilege escalation**: atacante testando quais roles consegue assumir
- **Credential stuffing**: chaves comprometidas testadas contra múltiplas roles
- Configuração incorreta legítima (falso positivo frequente)

O padrão suspeito é **múltiplas falhas** em curto intervalo, especialmente de IPs externos ou user agents incomuns.

### 3.6 Executando via CLI

```bash
# 1. Listar event data stores
aws cloudtrail list-event-data-stores \
  --query 'EventDataStores[*].{Name:Name,ARN:EventDataStoreArn}'

# 2. Iniciar query (retorna QueryId)
aws cloudtrail start-query \
  --query-statement "SELECT eventtime, useridentity.arn, sourceipaddress
                     FROM <event_data_store_id>
                     WHERE eventname = 'AssumeRole'
                       AND errorcode = 'AccessDenied'
                       AND eventtime > DATE_ADD('hour', -24, NOW())
                     ORDER BY eventtime DESC LIMIT 100"

# 3. Obter resultados
aws cloudtrail get-query-results \
  --event-data-store <event_data_store_id> \
  --query-id <QueryId>
```

---

## Parte 4 — Tipos de Evento e Custo Incremental (O4)

### 4.1 Os quatro tipos de eventos CloudTrail

#### Management Events (Control Plane)
- Operações de gerenciamento de recursos: `CreateBucket`, `RunInstances`, `AttachRolePolicy`
- ✅ Capturados por padrão
- Custo: Event History gratuito (90 dias); primeira cópia via trail gratuita; cópias adicionais $2,00/100k

#### Data Events (Data Plane)
- Operações de acesso a dados: `GetObject`, `PutObject` (S3), `Invoke` (Lambda), `GetItem` (DynamoDB)
- ❌ Não capturados por padrão
- Custo: $0,10/100k eventos

#### Network Activity Events
- Operações via VPC Endpoints, incluindo chamadas negadas por políticas de endpoint
- ❌ Não capturados por padrão
- Custo: $0,10/100k eventos

#### Insights Events
- Eventos derivados gerados quando CloudTrail detecta atividade anômala vs. baseline
- Detecta: picos de chamadas de escrita, taxas anormais de erros
- ❌ Não habilitados por padrão
- Custo: $0,35/100k eventos analisados (mgmt) | $0,03/100k (data)

### 4.2 Tabela comparativa

| Dimensão | Management | Data | Network Activity | Insights |
|----------|------------|------|-----------------|----------|
| Plane | Control | Data | VPC | Análise derivada |
| Capturado por padrão | ✅ Sim | ❌ Não | ❌ Não | ❌ Não |
| Custo (trail S3) | Grátis (1ª cópia) | $0,10/100k | $0,10/100k | $0,35/100k (mgmt) |
| Volume típico | Baixo-médio | Muito alto | Médio | Muito baixo |
| Caso de uso principal | Auditoria de mudanças | Auditoria de acesso a dados | Segurança de VPC | Detecção de anomalias |

### 4.3 Estratégia de custo para ambientes reais

[CONSENSO] Abordagem mais comum em produção:
1. **Management Events:** sempre habilitado (primeira cópia gratuita)
2. **Data Events:** seletivamente — apenas buckets S3 sensíveis, Lambdas críticas
3. **Insights:** habilitado se custo de não-detecção é alto
4. **CloudTrail Lake:** para SQL ad-hoc sobre histórico longo (ingestion: $0,75/GB)

```bash
# Habilitar data events seletivamente via advanced event selectors
aws cloudtrail put-event-selectors \
  --trail-name minha-trail \
  --advanced-event-selectors '[
    {
      "Name": "S3 data events para bucket sensível",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
        {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::meu-bucket-sensivel/"]}
      ]
    }
  ]'
```

---

## Checklist de conclusão

- [ ] **O1** — Consigo explicar os 3 pré-requisitos de uma organization trail e a diferença entre o path `AWSLogs/ACCOUNT-ID/` e `AWSLogs/o-ORG-ID/`
- [ ] **O2** — Consigo descrever o mecanismo de hash chain: SHA-256 no log → digest hourly → assinatura RSA → `previousDigestHashValue`
- [ ] **O3** — Consigo escrever a query SQL sem consultar o guia e entendo por que `AssumeRole` + `AccessDenied` em volume é padrão suspeito
- [ ] **O4** — Consigo preencher a tabela comparativa de tipos de eventos (capturado por padrão, custo, caso de uso)

---

## Exercício de reflexão

**Contexto:** Você é Security Engineer numa empresa com 15 contas AWS em uma Organization. O CISO pediu que você:
1. Garantisse que **todas as contas** tenham logs de management events centralizados
2. Garantisse que os logs **não possam ser adulterados** mesmo se uma conta-membro for comprometida
3. Detectasse automaticamente se alguma conta começar a fazer `AssumeRole` em volume anormal

**Perguntas:**
1. Para o requisito 1, qual é a abordagem mais simples? Quais ações no Management Account são necessárias?
2. Para o requisito 2, qual recurso do CloudTrail você habilita, e por que o comprometimento de uma conta-membro não é suficiente para adulterar os logs?
3. Para o requisito 3, qual tipo de evento e qual feature do CloudTrail você habilita? Qual seria o custo estimado se a org processar 10 milhões de management events por mês?

**Respostas:**

**1.** Organization trail com `--is-organization-trail --is-multi-region-trail`. Pré-requisitos: `enable-all-features` e `enable-aws-service-access` para CloudTrail. Novas contas recebem a trail automaticamente.

**2.** Log File Integrity Validation (`--enable-log-file-validation`). Conta-membro comprometida não é suficiente porque: (a) digest files estão no bucket do Management Account; (b) re-assinar o digest requer a chave privada RSA da AWS — impossível. Reforço: S3 Object Lock (COMPLIANCE mode).

**3.** CloudTrail Insights para management events. Custo: 10M eventos × $0,35/100k = **$35/mês**.

---

## Referências primárias

- [Creating a trail for an organization (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
- [Prepare for creating an organizational trail (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-an-organizational-trail-prepare.html)
- [Validating CloudTrail log file integrity (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [CloudTrail digest file structure (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)
- [Running queries with CloudTrail Lake (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-lake.html)
- [CloudTrail Lake SQL constraints (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-limitations.html)
- [Understanding CloudTrail events (docs)](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html)
- [AWS CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/)
