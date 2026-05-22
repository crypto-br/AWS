# Guia 5 — AWS Config + Conformance Packs: Custom Rule + Remediation Automática

**Depende de:** Nenhuma nova (Lambda e SSM cobertos pela Security Specialty)  
**Próxima sessão:** Guia 6 — Exfiltração S3

---

## Objetivos verificáveis desta sessão

Ao final, você deve conseguir — sem consultar documentação:

- [ ] **O1** — Escrever (ou explicar linha a linha) uma custom Lambda rule que detecta buckets S3 sem Block Public Access habilitado
- [ ] **O2** — Configurar auto-remediation via SSM Automation Document associada a uma Config rule
- [ ] **O3** — Implantar o CIS AWS Foundations Benchmark Conformance Pack via console
- [ ] **O4** — Diferenciar `AWS::Config::ConfigRule` de um Conformance Pack e quando usar cada um

---

## Alocação de tempo sugerida

| Bloco | Tempo | Conteúdo |
|-------|-------|----------|
| Parte 1 | 15 min | Arquitetura do AWS Config — conceitos fundamentais |
| Parte 2 | 20 min | Custom Lambda Rule — O1 (código completo + ciclo de vida) |
| Parte 3 | 15 min | Auto-remediation com SSM — O2 |
| Parte 4 | 10 min | Conformance Packs — O3 + O4 (deploy + distinção) |
| Revisão | 0 min | Checklist dos objetivos — integrado ao longo da sessão |

---

## Parte 1 — Arquitetura do AWS Config: o que o serviço faz e o que não faz

### 1.1 O modelo mental correto

 O AWS Config é um serviço de **auditoria de configuração de recursos** — ele rastreia *como* os recursos AWS estão configurados ao longo do tempo e avalia se essa configuração obedece a regras definidas. Ele **não** bloqueia ações em tempo real (isso é responsabilidade de IAM e SCPs) e **não** é um SIEM (isso é CloudWatch / Security Lake). A distinção é importante para posicioná-lo corretamente em discussões de arquitetura de segurança.

 O fluxo fundamental é:

```
Recurso muda de estado
        ↓
Config Configuration Recorder captura o novo ConfigurationItem
        ↓
Config Rule é invocada (se trigger configurado)
        ↓
Rule retorna COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE
        ↓
(Opcional) Remediation Action é executada via SSM Automation
```

### 1.2 Componentes principais

 Para que qualquer Config rule funcione, o **Configuration Recorder** deve estar habilitado na região. O Recorder observa recursos suportados e publica snapshots e mudanças de configuração para um S3 bucket de destino e, opcionalmente, um SNS topic. O Recorder é pré-requisito — sem ele, nenhuma rule recebe eventos.

 Uma **ConfigurationItem (CI)** é o objeto central do AWS Config. Ela contém:
- `resourceType` — ex: `AWS::S3::Bucket`
- `resourceId` — ARN ou ID único do recurso
- `configuration` — representação JSON da configuração atual (equivalente ao output de `describe-*` APIs)
- `supplementaryConfiguration` — campos adicionais que não cabem no `configuration` principal (ex: S3 Block Public Access settings são aqui)
- `configurationItemStatus` — `OK`, `ResourceDiscovered`, `ResourceDeleted`
- `configurationItemCaptureTime` — timestamp do snapshot

### 1.3 Dois tipos de trigger

 Toda Config rule tem um tipo de trigger:

| Trigger | Como funciona | Melhor para |
|---------|---------------|-------------|
| **Configuration changes** | Invocada quando o recurso muda; pode filtrar por resource type, tag, resource ID | Detecção near-real-time de misconfigurações |
| **Periodic** | Invocada em schedule (1h, 3h, 6h, 12h, 24h); recebe apenas metadados da invocação, sem CI | Checks que consultam APIs de terceiros ou não mapeiam para um recurso específico |

[CONSENSO] A maioria das custom security rules usa trigger **Configuration changes** porque oferece latência menor. Rules periódicas são mais usadas quando a avaliação precisa agregar dados de múltiplos recursos ou consultar APIs externas.

---

## Parte 2 — Custom Lambda Rule (O1): detectando S3 sem Block Public Access

### 2.1 Por que criar uma custom rule aqui?

 AWS já oferece a managed rule `S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED` (identifier `s3-bucket-level-public-access-prohibited`), que detecta exatamente esse padrão — buckets S3 cujo Block Public Access em nível de bucket está desabilitado. Ela tem trigger **Configuration changes** e resource type `AWS::S3::Bucket`.

O exercício de escrever uma custom Lambda rule equivalente tem valor pedagógico: mostra o contrato de comunicação entre Config e Lambda, que é o mesmo para qualquer avaliação personalizada que você precisar escrever (e que não tenha managed rule disponível).

### 2.2 Os dois tipos de custom rule

 Desde 2022, o AWS Config suporta dois tipos de custom rule:

- **Custom Policy Rules** — escritas em [Guard](https://github.com/aws-cloudformation/cloudformation-guard), policy-as-code language. Não exigem Lambda. Criadas via console ou API. Iniciadas exclusivamente por configuration changes. Ideais para regras simples com lógica declarativa.
- **Custom Lambda Rules** — função Java ou Python que você faz upload para o Lambda. O Config invoca a função quando a rule é disparada. Permitem lógica arbitrária, chamadas a APIs externas, e são o modelo anterior (mais flexível, mais complexo).

O exercício abaixo usa **Custom Lambda Rule** (Python) para expor todos os detalhes do contrato.

### 2.3 O contrato Lambda ↔ Config

 Quando o Config invoca uma Custom Lambda Rule com trigger **Configuration changes**, o event recebido pela função tem a seguinte estrutura:

```json
{
  "invokingEvent": "{\"configurationItem\": {...}, \"messageType\": \"ConfigurationItemChangeNotification\"}",
  "ruleParameters": "{\"exemptedBuckets\": \"my-public-cdn-bucket\"}",
  "resultToken": "token-para-put-evaluations",
  "eventLeftScope": false,
  "executionRoleArn": "arn:aws:iam::123456789012:role/config-rule-role",
  "configRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/rule-name",
  "configRuleName": "s3-no-public-access-custom",
  "configRuleId": "config-rule-id",
  "accountId": "123456789012",
  "version": "1.0"
}
```

**Campos críticos:**
- `invokingEvent` — string JSON (não objeto) contendo o `configurationItem` e o `messageType`
- `resultToken` — deve ser passado para `put_evaluations()` — identifica a invocação na fila do Config
- `eventLeftScope` — se `true`, o recurso saiu do escopo da rule (ex: foi deletado antes da avaliação); a função deve retornar `NOT_APPLICABLE`

[CONSENSO] A função deve chamar `config.put_evaluations()` com a lista de avaliações dentro do timeout do Lambda (default 300s para rules). Se não chamar, o Config marcará a evaluation como `INSUFFICIENT_DATA`.

### 2.4 Código completo da custom rule

```python
import json
import boto3

config = boto3.client('config')

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    result_token = event['resultToken']

    # Se o recurso saiu do escopo (ex: bucket deletado), retornar NOT_APPLICABLE
    if event.get('eventLeftScope', False):
        config.put_evaluations(
            Evaluations=[{
                'ComplianceResourceType': 'AWS::S3::Bucket',
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': 'NOT_APPLICABLE',
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            }],
            ResultToken=result_token
        )
        return

    ci = invoking_event['configurationItem']
    bucket_name = ci['resourceId']

    # Block Public Access está em supplementaryConfiguration, não em configuration
    supplementary = ci.get('supplementaryConfiguration', {})
    bpa = supplementary.get('PublicAccessBlockConfiguration', {})

    # Todos os 4 campos devem ser True para COMPLIANT
    is_compliant = all([
        bpa.get('BlockPublicAcls', False),
        bpa.get('IgnorePublicAcls', False),
        bpa.get('BlockPublicPolicy', False),
        bpa.get('RestrictPublicBuckets', False),
    ])

    # Verificar lista de exceções configuradas como parâmetro da rule
    exempted = [b.strip() for b in rule_parameters.get('exemptedBuckets', '').split(',') if b.strip()]
    if bucket_name in exempted:
        compliance_type = 'NOT_APPLICABLE'
    else:
        compliance_type = 'COMPLIANT' if is_compliant else 'NON_COMPLIANT'

    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': ci['resourceType'],
            'ComplianceResourceId': bucket_name,
            'ComplianceType': compliance_type,
            'Annotation': 'All 4 Block Public Access settings enabled' if is_compliant else 'One or more Block Public Access settings disabled',
            'OrderingTimestamp': ci['configurationItemCaptureTime']
        }],
        ResultToken=result_token
    )
```

**Observações técnicas críticas:**

 O campo `PublicAccessBlockConfiguration` está em `supplementaryConfiguration`, não em `configuration`. Esse é um erro frequente em custom rules para S3 — o objeto `configuration` principal não contém as configurações de Block Public Access; elas ficam no `supplementaryConfiguration` que o Config captura via `GetPublicAccessBlock` API. Se você checar o campo errado, a rule sempre retorna `NON_COMPLIANT` mesmo para buckets protegidos.

 O campo `Annotation` no `put_evaluations()` é opcional mas aparece no console do Config e é visível via `GetComplianceDetailsByResource` — use para facilitar troubleshooting.

### 2.5 Permissões necessárias

A função Lambda precisa de uma IAM role com:

```json
{
  "Effect": "Allow",
  "Action": ["config:PutEvaluations"],
  "Resource": "*"
}
```

E o AWS Config precisa de permissão para invocar a função Lambda:

```bash
# Adicionar permissão para Config invocar a Lambda
aws lambda add-permission \
  --function-name s3-block-public-access-rule \
  --statement-id config-invoke \
  --action lambda:InvokeFunction \
  --principal config.amazonaws.com
```

### 2.6 Criando a rule via CLI

```bash
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-no-public-access-custom",
  "Source": {
    "Owner": "CUSTOM_LAMBDA",
    "SourceIdentifier": "arn:aws:lambda:us-east-1:123456789012:function:s3-block-public-access-rule",
    "SourceDetails": [{
      "EventSource": "aws.config",
      "MessageType": "ConfigurationItemChangeNotification"
    }]
  },
  "Scope": {
    "ComplianceResourceTypes": ["AWS::S3::Bucket"]
  },
  "InputParameters": "{\"exemptedBuckets\": \"\"}"
}'
```

---

## Parte 3 — Auto-Remediation com SSM Automation (O2)

### 3.1 O modelo de remediation

 O Config aplica remediation usando **AWS Systems Manager Automation documents** (SSM documents). O mecanismo é:

1. Config detecta NON_COMPLIANT
2. Config invoca o SSM Automation document configurado para aquela rule
3. O SSM document executa ações no recurso não-conforme (ex: habilitar Block Public Access)
4. Config reavalia o recurso após a execução

 Há dois modos de remediation:
- **Manual remediation**: você precisa clicar "Remediate" para cada recurso — útil quando quer revisão humana
- **Auto remediation**: Config dispara a remediation automaticamente quando detecta NON_COMPLIANT

 Confirmado nas docs: **auto remediation pode ser disparada mesmo para recursos já conforme** se o snapshot de compliance estiver desatualizado. Isso ocorre porque o processador de auto-remediation usa o banco de dados de avaliações, que pode ter resultados stale. Leve isso em conta em produção — evite remediation automática para ações destrutivas ou irreversíveis.

### 3.2 SSM documents de remediation: managed vs. custom

 A AWS fornece uma biblioteca de SSM documents de remediation para os managed Config rules mais comuns. O padrão de nomenclatura é `AWSConfigRemediation-*`.

Para a rule de S3 Block Public Access, o document relevante é `AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock`. O nome exato pode variar — confirme em **Systems Manager → Documents → Owned by Amazon** antes de usar em produção.

Para criar um SSM document custom:

```yaml
# custom-ssm-enable-s3-bpa.yaml
schemaVersion: '0.3'
description: 'Habilita todos os Block Public Access settings em um bucket S3'
assumeRole: '{{AutomationAssumeRole}}'
parameters:
  BucketName:
    type: String
    description: Nome do bucket S3 a ser corrigido
  AutomationAssumeRole:
    type: String
    description: ARN da role que o SSM irá assumir para executar a automação
mainSteps:
  - name: EnableBlockPublicAccess
    action: 'aws:executeAwsApi'
    inputs:
      Service: s3control
      Api: PutPublicAccessBlock
      AccountId: '{{global:ACCOUNT_ID}}'
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
    # Nota: para configuração em nível de bucket (não conta), use a API s3:PutBucketPublicAccessBlock
```

 Na prática, a maioria das remediations de S3 usam `aws:executeAwsApi` com `s3:PutPublicAccessBlock` (nível de bucket). O exemplo acima usa `s3control` para demonstrar a variação de nível de conta — para a rule de S3 individual, ajuste para `s3:PutPublicAccessBlock` com o parâmetro `Bucket`.

### 3.3 Configurando auto-remediation no console

 Caminho no console:

```
AWS Config → Rules → [selecionar rule] → Actions → Manage remediation
  → Selecionar "Automatic remediation"
  → Escolher SSM document (managed ou custom)
  → Mapear parâmetros:
      - Resource ID parameter: BucketName → [Config ResourceId]  ← substitution dinâmica
      - AutomationAssumeRole → ARN da role com permissões S3
  → (Opcional) Configurar retries: ex: 5 tentativas em 300 segundos
  → Save
```

**Parâmetro "Resource ID parameter":** quando você seleciona um parâmetro como "Resource ID parameter", o Config substitui aquele campo em runtime com o ID do recurso não-conforme. Isso é o que conecta a rule específica ao recurso correto no SSM document.

### 3.4 Configurando via CLI

```bash
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "s3-no-public-access-custom",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock",
  "Parameters": {
    "BucketName": {
      "ResourceValue": {"Value": "RESOURCE_ID"}
    },
    "AutomationAssumeRole": {
      "StaticValue": {"Values": ["arn:aws:iam::123456789012:role/ConfigRemediationRole"]}
    }
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 5,
  "RetryAttemptSeconds": 300
}]'
```

### 3.5 Troubleshooting

```bash
# Ver status de execução das remediations
aws configservice describe-remediation-execution-status \
  --config-rule-name s3-no-public-access-custom
```

A role `ConfigRemediationRole` precisa de permissões para executar o SSM document (trust: `ssm.amazonaws.com`) e para modificar o recurso alvo (`s3:PutPublicAccessBlock`, `s3:GetPublicAccessBlock`).

---

## Parte 4 — Conformance Packs (O3 + O4)

### 4.1 O que é um Conformance Pack

 Um **Conformance Pack** é uma coleção de Config rules e remediation actions empacotadas em um único artefato YAML, implantável como uma entidade única em uma conta+região ou em toda uma organização via AWS Organizations.

 Definição oficial (AWS docs): *"A conformance pack is a collection of AWS Config rules and remediation actions that can be easily deployed as a single entity in an account and a Region or across an organization in AWS Organizations."*

 O artefato é um template YAML com estrutura similar a CloudFormation, mas não é um template CFN — é um formato proprietário do Config. Pode conter Config managed rules, custom Lambda rules, e remediation actions. Deploy via console do Config ou CLI com `put-conformance-pack`.

### 4.2 Estrutura de um Conformance Pack YAML

Exemplo mínimo de estrutura:

```yaml
Parameters:
  # Parâmetros podem ser passados na hora do deploy
  ExemptedBuckets:
    Default: ""
    Type: String

Resources:
  S3BlockPublicAccessRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-level-public-access-prohibited
      Source:
        Owner: AWS                         # managed rule
        SourceIdentifier: S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED
      InputParameters:
        excludedPublicBuckets: !Ref ExemptedBuckets

  S3BlockPublicAccessRemediation:
    Type: AWS::Config::RemediationConfiguration
    DependsOn: S3BlockPublicAccessRule
    Properties:
      ConfigRuleName: s3-bucket-level-public-access-prohibited
      TargetType: SSM_DOCUMENT
      TargetId: AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock
      Automatic: false                     # manual remediation no pack
      Parameters:
        BucketName:
          ResourceValue:
            Value: RESOURCE_ID
        AutomationAssumeRole:
          StaticValue:
            Values:
              - !Sub arn:aws:iam::${AWS::AccountId}:role/ConfigRemediationRole
```

 Templates de sample conformance packs estão disponíveis em:  
`https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs`

### 4.3 Implantando o CIS AWS Foundations Benchmark via console (O3)

 O AWS Config oferece o CIS AWS Foundations Benchmark como conformance pack sample. A versão disponível nos templates de sample é a **v1.4**, com dois níveis: Level 1 e Level 2 (o Level 2 é superset do Level 1 e tem mais controles restritivos).

Caminho no console:

```
AWS Config → Conformance packs → Deploy conformance pack
  → "Use sample template"
  → Selecionar: "Operational Best Practices for CIS AWS Foundations Benchmark v1.4 Level 1"
  → Conformance pack name: ex "cis-foundations-level1"
  → Delivery S3 bucket: selecionar ou criar
  → (Opcional) Parameters: ajustar valores padrão dos parâmetros
  → Deploy
```

 Aviso das docs oficiais (importante para provas e decisões arquiteturais):

> *"AWS conformance pack sample templates intend to help you create your own conformance packs with different or additional rules. The sample templates, including those related to compliance standards and industry benchmarks, are not designed to ensure your compliance with a specific governance standard. They can neither replace your internal efforts nor guarantee that you will pass a compliance assessment."*

Tradução prática: passar em 100% nas regras do CIS conformance pack **não significa** conformidade certificada com o CIS — é uma *aproximação operacional*, não uma auditoria formal.

Via CLI:

```bash
# Deploy do CIS Level 1 usando o template do GitHub
aws configservice put-conformance-pack \
  --conformance-pack-name "cis-foundations-level1" \
  --template-s3-uri "s3://my-bucket/aws-config-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v1.4-Level1.yaml" \
  --delivery-s3-bucket "my-config-delivery-bucket"
```

### 4.4 ConfigRule vs. Conformance Pack — quando usar cada um (O4)

 A distinção prática:

| Dimensão | `AWS::Config::ConfigRule` (individual) | Conformance Pack |
|----------|----------------------------------------|-----------------|
| **Escopo** | Uma única rule, gerenciada individualmente | Conjunto de rules como uma unidade |
| **Ciclo de vida** | Criação/edição/deleção individual | Deploy, update ou delete do pack inteiro — não é possível deletar uma rule de dentro do pack sem deletar o pack |
| **Parâmetros** | Configurados por rule | Parametrizados no template do pack; podem ser passados no deploy |
| **Remediation** | Associada individualmente via `PutRemediationConfigurations` | Pode ser declarada dentro do template YAML |
| **Multi-conta** | Requer automação própria (StackSets, script) | Suporte nativo a Organizations via `PutOrganizationConformancePack` |
| **Compliance score** | Nível de rule: COMPLIANT/NON_COMPLIANT | Score do pack: % de rules conformes; visível no Conformance Pack Dashboard |
| **Auditabilidade** | Flexível para regras ad hoc ou one-off | Preferível quando o conjunto de regras representa um framework (CIS, PCI, interno) e precisa ser tratado como artefato versionado |

**Regra prática:**
- **ConfigRule individual** → quando você precisa de uma regra específica, não relacionada a um framework, ou que será gerenciada independentemente do ciclo de outros controles
- **Conformance Pack** → quando o conjunto de rules representa um *framework de compliance* (CIS, PCI, NIST, padrão interno corporativo) que deve ser tratado como artefato único, versionado, e possivelmente implantado em múltiplas contas

 Uma limitação relevante: as rules de dentro de um Conformance Pack **não podem ser editadas ou deletadas individualmente** sem remover o pack inteiro. Isso garante integridade do framework mas impede correções cirúrgicas. Por isso, começar com rules individuais e depois empacotar em um Conformance Pack é um caminho válido de maturidade.

---

## Checklist dos Objetivos

Antes de encerrar a sessão, confirme:

- [ ] **O1** ✅ Você consegue explicar o que `invokingEvent`, `resultToken` e `eventLeftScope` fazem, e por que `PublicAccessBlockConfiguration` está em `supplementaryConfiguration` e não em `configuration`
- [ ] **O2** ✅ Você consegue descrever o fluxo Config → SSM Automation, o que o "Resource ID parameter" faz, e o risco do false-positive em auto-remediation por snapshot stale
- [ ] **O3** ✅ Você consegue fazer o deploy do CIS Level 1 Conformance Pack via console e sabe que o resultado não equivale a certificação formal
- [ ] **O4** ✅ Você consegue justificar quando usar uma ConfigRule individual versus um Conformance Pack, citando pelo menos 3 dimensões de diferença (multi-conta, ciclo de vida, compliance score)

---

## Exercício de reflexão (3 perguntas)

**Pergunta 1 — Técnica (O1):**  
Sua custom Lambda rule para S3 Block Public Access está funcionando, mas você percebe que buckets recém-criados aparecem como `INSUFFICIENT_DATA` por vários minutos antes de serem avaliados. Qual é a causa mais provável e como você ajustaria a configuração da rule para reduzir essa janela?

*(Dica: pense no tipo de trigger e no que o Configuration Recorder precisa fazer antes que a invocação ocorra)*

**Pergunta 2 — Operacional (O2):**  
Um bucket S3 marcado como NON_COMPLIANT teve Block Public Access habilitado pelo time de desenvolvimento 3 minutos antes do ciclo de auto-remediation do Config rodar. A auto-remediation executou mesmo assim. Qual o mecanismo que causou isso, como isso afeta o bucket, e como você detectaria esse evento?

*(Dica: o comportamento está documentado nas docs de remediation — snapshot stale)*

**Pergunta 3 — Arquitetural (O4):**  
Seu time de compliance quer garantir que todas as 200 contas da organização sigam o CIS Level 1 e que nenhuma equipe de desenvolvimento possa deletar regras específicas do framework sem passar por aprovação. Qual combinação de serviços e funcionalidades você usaria e por quê?

*(Dica: Organizations Conformance Pack + SCP para bloquear `config:DeleteConformancePack`)*

---

## Referências primárias

- [AWS Config Custom Rules (docs)](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html) — tipos de custom rule: Guard vs Lambda
- [Creating Custom Lambda Rules (docs)](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html) — contrato event/response
- [Setting Up Auto Remediation (docs)](https://docs.aws.amazon.com/config/latest/developerguide/setup-autoremediation.html) — console walkthrough + aviso de snapshot stale
- [Conformance Packs (docs)](https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html) — definição oficial + disclaimer de compliance
- [Conformance Pack Sample Templates (docs)](https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html) — lista de templates incluindo CIS
- [s3-bucket-level-public-access-prohibited (managed rule)](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-level-public-access-prohibited.html) — managed rule de referência para comparação com custom
- [Sample templates GitHub](https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs) — YAML dos conformance packs para estudo
- [Guard GitHub Repository](https://github.com/aws-cloudformation/cloudformation-guard) — policy-as-code language para Custom Policy Rules
