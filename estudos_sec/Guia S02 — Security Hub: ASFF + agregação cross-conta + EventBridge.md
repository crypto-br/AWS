# Guia 2 — Security Hub: ASFF + agregação cross-conta + EventBridge

**Depende de:** Guia 1 (GuardDuty — finding types + multi-conta)  
**Próxima sessão:** Guia 3 — Escalação de privilégios IAM (ofensivo)


---

## Orientação para a sessão

- **0–20 min** → Parte 1: ASFF — campos obrigatórios + mapeamento de um finding GuardDuty
- **20–35 min** → Parte 2: Agregação cross-região — home region + linked regions
- **35–50 min** → Parte 3: EventBridge — tipos de evento + regra CRITICAL → SNS
- **50–58 min** → Parte 4: Os 4 security standards (o plano lista 3, mas há 4)
- **58–60 min** → Revisão do checklist de objetivos

---

## Parte 1 — ASFF: Amazon Security Finding Format

### 1.1 Por que o ASFF existe

 Antes do Security Hub, cada serviço AWS de segurança (GuardDuty, Inspector, Macie, IAM Access Analyzer) gerava findings em formatos incompatíveis. O ASFF é o formato normalizado que o Security Hub usa para receber, processar e exportar todos os findings, independente da fonte.

 O Security Hub processa findings usando o ASFF. Produtos externos (ferramentas de terceiros) que querem enviar findings para o Security Hub também devem seguir o ASFF.

### 1.2 Campos obrigatórios do ASFF

 Um finding ASFF válido **deve** conter os seguintes campos:

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:guardduty:us-east-1:123456789012:detector/abc123/finding/def456",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
  "GeneratorId": "arn:aws:guardduty:us-east-1:123456789012:detector/abc123",
  "AwsAccountId": "123456789012",
  "Types": ["TTPs/Command and Control/Backdoor:EC2-C&CActivity.B-DNS"],
  "CreatedAt": "2026-05-05T10:30:00Z",
  "UpdatedAt": "2026-05-05T11:00:00Z",
  "Severity": {
    "Label": "HIGH",
    "Normalized": 70
  },
  "Title": "EC2 instance is communicating with a known C&C server",
  "Description": "...",
  "Resources": [
    {
      "Type": "AwsEc2Instance",
      "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456"
    }
  ]
}
```

Mapeamento dos campos obrigatórios:

| Campo | O que é | Exemplo (GuardDuty) |
|-------|---------|---------------------|
| `SchemaVersion` | Versão do ASFF — sempre `"2018-10-08"` | `"2018-10-08"` |
| `Id` | Identificador único do finding | ARN do finding no GuardDuty |
| `ProductArn` | ARN do produto que gerou o finding | `arn:aws:securityhub:<region>::product/aws/guardduty` |
| `GeneratorId` | Identificador do detector/regra | ARN do GuardDuty detector |
| `AwsAccountId` | Conta onde o finding foi gerado | `"123456789012"` |
| `Types` | Classificação no ASFF taxonomy (ver 1.3) | `["TTPs/Command and Control/..."]` |
| `CreatedAt` | ISO 8601 — quando foi detectado pela primeira vez | `"2026-05-05T10:30:00Z"` |
| `UpdatedAt` | ISO 8601 — última atualização | Atualizado a cada reaparição |
| `Severity` | Objeto com `Label` e/ou `Normalized` | `{"Label": "HIGH", "Normalized": 70}` |
| `Title` | Título do finding | String legível |
| `Description` | Descrição do que foi detectado | String legível |
| `Resources` | Array de recursos afetados | Instâncias EC2, usuários IAM, buckets S3 etc. |

### 1.3 Campos opcionais importantes

Além dos obrigatórios, estes campos são altamente relevantes na prática:

- **`Compliance`** — resultado de um controle de security standard. Valores: `PASSED`, `FAILED`, `WARNING`, `NOT_AVAILABLE`. Presente em findings gerados pelos próprios controles do Security Hub (não em findings vindos do GuardDuty).
- **`Workflow`** — status de investigação. Valores: `NEW`, `NOTIFIED`, `SUPPRESSED`, `RESOLVED`.  Você atualiza este campo (via `BatchUpdateFindings`); o produto gerador (GuardDuty) não o altera.
- **`RecordState`** — `ACTIVE` ou `ARCHIVED`. Produto gerador controla este campo.
- **`FindingProviderFields`** — bloco que o produto gerador pode usar para campos proprietários sem poluir o namespace principal.
- **`Remediation`** — instruções de remediação com URL de documentação.

### 1.4 Taxonomia de tipos: `Types`

 O campo `Types` segue o formato hierárquico:
```
Namespace/Category/Classifier
```

Exemplos de namespaces: `TTPs`, `Software and Configuration Checks`, `Effects`, `Sensitive Data Identifications`, `Unusual Behaviors`.

 A taxonomia completa é documentada em: [Finding type taxonomy](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-type-taxonomy.html)

### 1.5 Como um finding GuardDuty é mapeado para o ASFF

Quando o GuardDuty envia um finding para o Security Hub, ele o converte automaticamente para ASFF:

```
GuardDuty finding: Backdoor:EC2/C&CActivity.B!DNS
                         ↓
ASFF Types: ["TTPs/Command and Control/Backdoor:EC2-C&CActivity.B-DNS"]
```

Mapeamento de severidade:

| GuardDuty severity score | ASFF `Severity.Label` |
|--------------------------|----------------------|
| 0.1 – 3.9 | `LOW` |
| 4.0 – 6.9 | `MEDIUM` |
| 7.0 – 8.9 | `HIGH` |
| 9.0 – 10.0 | `CRITICAL` |

 O campo `Resources` no ASFF recebe o recurso afetado em formato padronizado — uma instância EC2 vira `{"Type": "AwsEc2Instance", "Id": "arn:..."}`, um usuário IAM vira `{"Type": "AwsIamUser", ...}`.

 O campo `ProductArn` para findings do GuardDuty é sempre:
```
arn:aws:securityhub:<region>::product/aws/guardduty
```

(Note: dois `::` — o account ID fica em branco porque é um produto AWS nativo, não de terceiro.)

---

## Parte 2 — Agregação cross-região

### 2.1 O conceito central: home region + linked regions

 Cross-region aggregation replica dados do Security Hub de múltiplas regiões para uma única **home region** (antes chamada de "aggregation Region" — a API ainda usa o termo antigo em alguns lugares). A partir da home region você tem visão consolidada de todo o ambiente.

```
┌─────────────────────────────────────────────────────────┐
│                    HOME REGION                          │
│              (ex: us-east-1)                            │
│  ─ Findings de todas as linked regions                  │
│  ─ Insights consolidados                                │
│  ─ Security scores agregados                            │
│  ─ Compliance statuses de todos os controles            │
│  ─ EventBridge feed inclui eventos de linked regions    │
└──────────────────────┬──────────────────────────────────┘
                       │ replicação bidirecional
          ┌────────────┴────────────┐
          ▼                         ▼
   ┌─────────────┐          ┌─────────────┐
   │  us-west-2  │          │  eu-west-1  │
   │  (linked)   │          │  (linked)   │
   └─────────────┘          └─────────────┘
```

### 2.2 O que é replicado (e o que não é)

 Dados replicados das linked regions para a home region:
- Findings (novos + atualizações)
- Insights
- Control compliance statuses
- Security scores

 A replicação é **bidirecional**: atualizações feitas na home region (ex: mudar `Workflow.Status` de um finding) são replicadas de volta para a linked region. Se houver conflito, a atualização mais recente ganha.

 Cross-region aggregation **não tem custo adicional** — a replicação de dados entre regiões não gera cobrança extra no Security Hub.

 Security Hub não é habilitado automaticamente em uma conta baseado na configuração de aggregation. Se uma linked region não tiver Security Hub habilitado, seus dados não são replicados.

### 2.3 Configuração via console

1. Security Hub console → **Settings** → **Regions**
2. Escolha **Configure regions** (ou "Aggregation")
3. Selecione a home region (atual, onde você está logado)
4. Adicione as linked regions desejadas
5. Salve

Via CLI:
```bash
# Habilitar aggregation e definir linked regions
aws securityhub create-finding-aggregator \
  --region-linking-mode ALL_REGIONS

# Para regiões específicas:
aws securityhub create-finding-aggregator \
  --region-linking-mode SPECIFIED_REGIONS \
  --regions us-west-2 eu-west-1 ap-southeast-1
```

### 2.4 Comportamento com contas membro

 Quando um administrator account habilita cross-region aggregation:
- A configuração é herdada pelas contas membro associadas
- O admin deve estar logado na **home region** para ver dados agregados de todos os membros
- Contas membro só veem seus próprios dados na home region, não os de outras contas membro
- Se o administrator-member relationship for encerrado, cross-region aggregation para para a conta membro — mesmo que ela tenha habilitado antes da relação começar

 Para convites manuais (não via Organizations): o admin deve convidar o membro a partir da home region **e** de todas as linked regions para que a aggregation funcione corretamente.

### 2.5 Implicação para CIS compliance

 A documentação do Security Hub afirma explicitamente: "For full compliance with CIS AWS Foundations Benchmark security checks, you must enable Security Hub in all supported AWS Regions." Isso porque o CIS Benchmark inclui controles de monitoramento (ex: CloudTrail habilitado em todas as regiões) que só são verificados se o Security Hub estiver presente em cada região.

---

## Parte 3 — EventBridge: automação com findings

### 3.1 Os 3 tipos de evento do Security Hub no EventBridge

 O Security Hub envia 3 tipos de evento para o EventBridge:

**Tipo 1: `Security Hub Findings - Imported`**
- Disparado automaticamente, sem ação do usuário
- Gerado a cada `BatchImportFindings` (novo finding de um produto) ou `BatchUpdateFindings` (atualização)
- Cada evento contém **um único finding**
- Uso: capturar todos os findings ou findings com características específicas para automação

**Tipo 2: `Security Hub Findings - Custom Action`**
- Disparado manualmente por um analista no console do Security Hub
- O analista seleciona até 20 findings e aplica uma "Custom Action" criada previamente
- Cada finding vira um evento separado no EventBridge
- Uso: fluxos de resposta manuais — enviar para ticketing system, pedir aprovação humana etc.

**Tipo 3: `Security Hub Insight Results`**
- Disparado via Custom Action aplicado a um insight (não a findings individuais)
- Envia até 100 resource identifiers (não os findings em si)
- Uso: notificar sobre um conjunto de recursos identificados por um insight

### 3.2 Regra EventBridge: findings CRITICAL → SNS

Estrutura de uma regra EventBridge que captura findings `CRITICAL` do Security Hub e publica em um SNS topic:

**Event pattern (o filtro):**
```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "Severity": {
        "Label": ["CRITICAL"]
      }
    }
  }
}
```

**Target:** SNS topic ARN

**Via CLI (criação completa):**
```bash
# 1. Criar a regra
aws events put-rule \
  --name "securityhub-critical-to-sns" \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Severity": {
          "Label": ["CRITICAL"]
        }
      }
    }
  }' \
  --state ENABLED

# 2. Associar o SNS topic como target
aws events put-targets \
  --rule "securityhub-critical-to-sns" \
  --targets '[{
    "Id": "sns-target",
    "Arn": "arn:aws:sns:us-east-1:123456789012:security-alerts"
  }]'
```

**Permissão necessária no SNS topic policy:**
```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "events.amazonaws.com"
  },
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:us-east-1:123456789012:security-alerts",
  "Condition": {
    "ArnEquals": {
      "aws:SourceArn": "arn:aws:events:us-east-1:123456789012:rule/securityhub-critical-to-sns"
    }
  }
}
```

### 3.3 Variações úteis do event pattern

**Filtrar por produto de origem (ex: só GuardDuty):**
```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "ProductArn": [{"prefix": "arn:aws:securityhub:us-east-1::product/aws/guardduty"}],
      "Severity": {
        "Label": ["HIGH", "CRITICAL"]
      }
    }
  }
}
```

**Filtrar por tipo de finding específico:**
```json
{
  "detail": {
    "findings": {
      "Types": [{"prefix": "TTPs/"}],
      "RecordState": ["ACTIVE"],
      "Workflow": {
        "Status": ["NEW"]
      }
    }
  }
}
```

 O campo `Workflow.Status` filtra o status do workflow (`NEW`, `NOTIFIED`, `SUPPRESSED`, `RESOLVED`) — útil para evitar re-processar findings já resolvidos.

### 3.4 Onde o EventBridge fica em relação à home region

 O EventBridge event feed na home region inclui findings das linked regions em near real-time. Isso significa que uma única regra EventBridge na home region pode capturar e responder a findings de todas as regiões configuradas como linked — sem precisar criar regras separadas em cada região.

---

## Parte 4 — Os 4 security standards nativos

O plano original menciona "3 security standards nativos (CIS, FSBP, PCI-DSS)".  A documentação atual lista 4 standards principais. O NIST SP 800-53 foi adicionado. Esta tabela cobre os 4:

### 4.1 Tabela comparativa

| Standard | Origem | Foco principal | Quando usar |
|----------|--------|----------------|-------------|
| **AWS FSBP** | AWS (interno) | Best practices AWS-specific, cobrindo dezenas de serviços | Ponto de partida para qualquer conta AWS; revisado continuamente pela AWS |
| **CIS AWS Foundations** | Center for Internet Security (independente) | Configurações fundamentais: IAM, CloudTrail, logging, networking | Ambientes que precisam de framework de terceiro auditável; comum em RFPs e auditorias |
| **PCI DSS** | Payment Card Industry Security Standards Council | Proteção de dados de cartão de crédito | Qualquer ambiente que processe, armazene ou transmita dados de pagamento |
| **NIST SP 800-53** | National Institute of Standards and Technology (EUA) | Framework federal amplo, mais de 900 controles base | Contratados do governo federal EUA; organizações buscando FedRAMP |

### 4.2 FSBP — AWS Foundational Security Best Practices

 É o standard desenvolvido internamente pela AWS. Cobre uma gama ampla de serviços (EC2, IAM, S3, RDS, Lambda, CloudTrail etc.) com controles específicos para AWS.

 É considerado o melhor ponto de partida para ambientes AWS novos — é o mais atualizado em relação a novos serviços e tem o maior número de controles verificáveis automaticamente pelo Security Hub.

 Exemplo de controles: `EC2.2` (SGs não devem permitir 0.0.0.0/0 na porta 22), `IAM.1` (IAM policies não devem ter full "*:*" admin), `S3.1` (Block Public Access habilitado no nível de conta).

### 4.3 CIS AWS Foundations Benchmark

 Produzido pelo Center for Internet Security (organização sem fins lucrativos). O Security Hub suporta múltiplas versões — CIS AWS Foundations Benchmark v1.2.0 e v1.4.0 são as mais comuns; versões mais recentes podem estar disponíveis.

 Dividido em seções: IAM, Storage, Logging, Monitoring, Networking. Os controles de Monitoring incluem alarmes CloudWatch para eventos específicos de CloudTrail (ex: alarme para `root account usage`, `unauthorized API calls`).

 Para compliance completo com CIS: Security Hub deve estar habilitado em **todas** as regiões suportadas.

 O CIS Benchmark é o framework mais citado em processos de auditoria externa no ecossistema AWS — é comum que RFPs de segurança exijam compliance com CIS como requisito mínimo.

### 4.4 PCI DSS

 O PCI DSS (Payment Card Industry Data Security Standard) é mantido pelo PCI Security Standards Council. O Security Hub implementa um subconjunto de controles do PCI DSS v3.2.1 (verificar versão atual nas docs).

Escopo de aplicação: qualquer workload que faça parte do "cardholder data environment" (CDE) — sistemas que armazenam, processam ou transmitem dados de cartão.

 Os controles no Security Hub para PCI DSS são mapeados para os 12 requirements principais do PCI (ex: Requirement 1 — instalar e manter um firewall; Requirement 10 — logging e monitoramento).

[OPINIÃO — AWS] Para ambientes com PCI scope pequeno, [CONSENSO] é prática comum usar o PCI DSS standard como filtro para resources in-scope e o FSBP para o resto do ambiente.

### 4.5 Quando usar cada um

```
Cenário 1: Startup AWS-native sem requisito regulatório
→ FSBP como baseline. Adicionar CIS se quiser terceiro validado.

Cenário 2: Empresa com auditoria SOC 2 / ISO 27001
→ FSBP + CIS. O CIS é referência comum nesses frameworks.

Cenário 3: E-commerce com pagamentos via cartão
→ FSBP + PCI DSS para os recursos em CDE scope.

Cenário 4: Contratado do governo federal EUA / FedRAMP
→ NIST SP 800-53. É o framework mandatório.

Cenário 5: Ambiente misto — múltiplos requisitos
→ Habilitar múltiplos standards. Os mesmos controles de infra
  se mapeiam para diferentes frameworks — o Security Hub
  evita duplicação de checks via o conceito de "security control"
  consolidado (um check, múltiplos standards).
```

 O Security Hub usa "security controls" consolidados — um mesmo controle de infraestrutura (ex: "CloudTrail deve estar habilitado") pode aparecer em múltiplos standards, mas o Security Hub roda o check uma única vez e mapepa o resultado para todos os standards relevantes.

---

## Checklist de objetivos verificáveis

Ao final da sessão, você deve conseguir responder sem consultar documentação:

- [ ] Citar os 12 campos obrigatórios do ASFF e o que cada um representa
- [ ] Explicar como um finding GuardDuty `Backdoor:EC2/C&CActivity.B!DNS` aparece no campo `Types` e `ProductArn` do ASFF
- [ ] Distinguir `RecordState` (controlado pelo produto gerador) de `Workflow.Status` (controlado pelo usuário)
- [ ] Explicar o que é home region vs. linked region, o que é replicado e quanto custa
- [ ] Citar os 3 tipos de evento do Security Hub no EventBridge e quando cada um é usado
- [ ] Escrever o `event-pattern` de uma regra EventBridge que captura findings CRITICAL do Security Hub
- [ ] Citar os 4 security standards e em qual situação cada um é aplicável
- [ ] Explicar por que o FSBP roda o mesmo check uma vez para múltiplos standards

---

## Exercício de reflexão

> Sua empresa tem 8 contas AWS em us-east-1, us-west-2, eu-west-1 e ap-southeast-1. Vocês processam pagamentos (PCI scope). O time de segurança quer:
> 
> (a) Visão unificada de todos os findings a partir de uma única console, sem duplicação  
> (b) Pager automático (PagerDuty via SNS) para qualquer finding CRITICAL de qualquer conta e região  
> (c) Compliance com PCI DSS e CIS documentado para auditoria externa  
>
> **Pergunta 1:** Descreva a arquitetura do Security Hub que atende (a) — quais contas precisam ter Security Hub habilitado, qual é a home region, como as contas membro são gerenciadas.
>
> **Pergunta 2:** Para (b), onde você cria a regra EventBridge (em qual região, em qual conta) e qual `event-pattern` você usa? O que garante que findings de us-west-2 chegam nessa regra?
>
> **Pergunta 3:** Para (c), você habilita PCI DSS em todas as 8 contas e todas as regiões, ou apenas nas contas/regiões com recursos em PCI scope? Qual é a diferença prática e o que acontece com os security scores?

---

## Referências primárias

- [ASFF — Amazon Security Finding Format (spec completa)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) — referência de todos os campos com tipos e exemplos
- [ASFF type taxonomy](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-type-taxonomy.html) — hierarquia Namespace/Category/Classifier
- [Cross-Region aggregation (docs)](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) — home region, linked regions, o que é replicado
- [Security Hub event types in EventBridge (docs)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html) — os 3 tipos de evento e quando usar cada um
- [Configuring EventBridge rule for Security Hub findings (docs)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-all-findings.html) — procedimento completo com exemplos de event patterns
- [Security standards reference (docs)](https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html) — lista de todos os standards e controles disponíveis
- [AWS Security Blog — Security Hub cross-account setup](https://aws.amazon.com/blogs/security/simplify-setup-of-aws-security-hub-across-accounts-and-regions/) — modelo de delegated administrator com Organizations
