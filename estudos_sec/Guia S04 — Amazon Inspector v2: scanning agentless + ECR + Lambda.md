# Guia S04 — Amazon Inspector v2: scanning agentless + ECR + Lambda

**Depende de:** Conhecimento de EC2, ECR e Lambda (pré-existente). S02 útil para contexto de integração Security Hub.  
**Próxima sessão:** S05 — AWS Config + Conformance Packs

> **Correção ao plano original:** O plano descreve o EC2 scanning do Inspector v2 como "SSM-based, agentless". A documentação atual descreve o modo padrão como **híbrido**: o Inspector usa o SSM agent se estiver instalado (agent-based) e usa EBS snapshots se não estiver (agentless). Os dois caminhos coexistem — "hybrid scanning mode". Esta distinção é importante para a questão arquitetural do objetivo 1.

---

## Orientação para a sessão

- **0–15 min** → Parte 1: Inspector v1 vs v2 — diferença arquitetural
- **15–30 min** → Parte 2: habilitação — EC2, ECR, Lambda via console e CLI
- **30–50 min** → Parte 3: interpretando um finding — Inspector score, CVSS, EPSS, Vulnerability Intelligence
- **50–58 min** → Parte 4: integração com Security Hub
- **58–60 min** → Checklist de objetivos

---

## Parte 1 — Inspector v1 vs v2: diferença arquitetural

### 1.1 Inspector v1 (legado)

[FATO] O Amazon Inspector v1 (console legado: `inspector.amazonaws.com`, não `inspector2`) foi projetado em torno do modelo de **avaliações agendadas** com agent obrigatório:

- **Agent obrigatório:** Era necessário instalar o Amazon Inspector Agent em cada instância EC2 a ser avaliada.
- **Avaliações manuais:** O usuário criava "assessment targets" (grupos de instâncias via tags), "assessment templates" (conjunto de rules packages + duração), e agendava as execuções.
- **Rules packages:** Vulnerabilidades de software (CVEs), CIS Benchmarks, Security Best Practices, Network Reachability — cada um como pacote separado.
- **Execução pontual:** O Inspector v1 fazia scans periódicos e discretos, não monitoramento contínuo. Uma instância lançada entre dois scans ficava sem cobertura até o próximo ciclo.
- **Sem cobertura nativa de ECR ou Lambda.**

[FATO] O Inspector v1 foi descontinuado. A AWS encerrou o suporte ao Inspector v1 em 18 de dezembro de 2023 — contas ainda usando v1 devem ter migrado para v2.

### 1.2 Inspector v2 — arquitectura atual

[FATO] O Amazon Inspector v2 foi completamente redesenhado em torno de quatro princípios:

**1. Auto-descoberta:** Quando ativado, o Inspector v2 descobre automaticamente todos os recursos elegíveis na conta (instâncias EC2, imagens ECR, funções Lambda). Não há configuração de "targets" ou "templates".

**2. Scanning contínuo:** [FATO] O Inspector v2 não faz scans pontuais. Ele rescan automaticamente recursos em resposta a:
- Instalação de novo pacote em uma instância EC2
- Aplicação de patch
- Publicação de novo CVE que afeta o recurso

Isso significa que uma instância recém-lançada começa a ser escaneada automaticamente.

**3. Hybrid scanning para EC2 (correção ao plano):**

[FATO] Confirmado na documentação oficial — quando você ativa EC2 scanning, o Inspector v2 habilita automaticamente o **hybrid scanning mode**:

```
┌─────────────────────────────────────────────────────────────┐
│              EC2 HYBRID SCANNING MODE                       │
│                                                             │
│  SSM agent instalado?                                       │
│  ├── SIM → Usa SSM agent (agent-based path)                 │
│  │         Inspector consulta inventário de pacotes via SSM │
│  │         Scanning sem impacto de I/O no disco da instância│
│  │                                                          │
│  └── NÃO → Usa EBS snapshot (agentless path)               │
│            Inspector cria snapshot do volume EBS            │
│            Analisa pacotes a partir do snapshot             │
│            Instância não precisa estar running              │
└─────────────────────────────────────────────────────────────┘
```

[FATO] O caminho via EBS snapshot ("agentless scanning") permite escanear instâncias **sem SSM agent instalado** e até **instâncias paradas (stopped)**. Esta é a inovação arquitetural principal do v2 em relação ao v1.

**4. Cobertura expandida:** [FATO] Inspector v2 escaneia EC2, ECR container images, e Lambda functions — e adicionou Lambda code scanning e Code Security (IaC, dependências de aplicação) posteriormente.

### 1.3 Tabela comparativa v1 vs v2

| Dimensão | Inspector v1 | Inspector v2 |
|----------|-------------|-------------|
| Agent | Obrigatório (Inspector Agent proprietário) | Opcional — SSM agent (se disponível) ou EBS snapshot |
| Cobertura EC2 | Somente instâncias com agent | EC2 com ou sem SSM agent; instâncias paradas |
| Cobertura ECR | Não suportado | Sim (enhanced scanning) |
| Cobertura Lambda | Não suportado | Sim (standard + code scanning) |
| Modo de execução | Scans agendados e pontuais | Contínuo, event-driven |
| Configuração | assessment targets + templates | Ativação por scan type — sem targets/templates |
| Status | **Descontinuado (EOL: dez/2023)** | Atual |

---

## Parte 2 — Habilitação: EC2, ECR e Lambda

### 2.1 O que acontece ao ativar o Inspector v2

[FATO] Confirmado na documentação oficial: quando você ativa o Inspector v2 pela primeira vez, a conta é automaticamente inscrita em **todos os scan types**:
- Amazon EC2 scanning (com hybrid mode habilitado por padrão)
- Amazon ECR scanning
- Lambda standard scanning

[FATO] Lambda **code** scanning é opcional e deve ser ativado separadamente.

### 2.2 Habilitação via console

**Pré-requisito:** IAM permissions `inspector2:Enable`, `inspector2:ListCoverage`, `iam:CreateServiceLinkedRole`.

1. Console AWS → **Amazon Inspector** → **Get started**
2. Selecione os scan types desejados (ou deixe todos habilitados)
3. Clique **Enable Amazon Inspector**
4. O Inspector começa a descobrir e escanear recursos imediatamente

Para contas membro em Organizations, o delegated admin pode habilitar o Inspector em todas as contas de uma vez.

### 2.3 Habilitação via CLI

```bash
# Habilitar Inspector v2 com todos os scan types principais
aws inspector2 enable \
  --resource-types EC2 ECR LAMBDA

# Para Lambda code scanning (opcional, adicional):
aws inspector2 enable \
  --resource-types LAMBDA_CODE

# Verificar status de ativação na conta
aws inspector2 batch-get-account-status \
  --account-ids $(aws sts get-caller-identity --query Account --output text)
```

Resposta esperada de `batch-get-account-status`:
```json
{
  "accounts": [{
    "accountId": "123456789012",
    "resourceState": {
      "ec2": {"status": "ENABLED"},
      "ecr": {"status": "ENABLED"},
      "lambda": {"status": "ENABLED"}
    },
    "state": {"status": "ENABLED"}
  }]
}
```

### 2.4 Comportamentos específicos por scan type

**EC2 scanning:**
[FATO] O Inspector escaneia instâncias para:
- CVEs em pacotes de OS (Amazon Linux, Debian, RHEL, Ubuntu, CentOS etc.)
- Vulnerabilidades em runtime languages instalados (Python, Node.js, Java etc.)
- Network reachability — portas abertas acessíveis da internet
- O Inspector rescan automaticamente quando: novo pacote instalado, patch aplicado, novo CVE publicado

[FATO] Para o path via SSM, é necessário que o SSM agent esteja instalado e que a instância tenha conectividade com os endpoints do SSM. Para o path agentless via EBS snapshot, não há requisito de conectividade de rede — o Inspector opera diretamente no snapshot.

**ECR scanning:**
[FATO] Ao ativar ECR scanning, o Inspector converte todos os repositórios privados de **basic scanning** para **enhanced scanning**. Basic scanning (nativo do ECR) usa apenas o banco de dados de vulnerabilidades open-source do ECR; enhanced scanning usa o banco de dados do Inspector.

[FATO] O Inspector escaneia imagens ECR que foram:
- Pushed ou ativadas nos últimos 30 dias
- Pulled nos últimos 90 dias

[FATO] O monitoramento contínuo de uma imagem dura 90 dias por padrão (configurável). Uma imagem não acessada por mais de 90 dias deixa de ser monitorada ativamente.

**Lambda scanning:**
[FATO] Lambda standard scanning:
- Escaneia todas as funções na conta quando o scan é ativado
- Rescan automático quando a função é atualizada ou quando novo CVE é publicado
- Escaneia pacotes de dependências (third-party libraries) incluídos na função

[FATO] Lambda **code** scanning (opcional):
- Escaneia vulnerabilidades no código da aplicação (não apenas dependências)
- Avalia dependências de aplicação para CVEs
- Ativar Lambda code scanning também ativa Lambda standard scanning

---

## Parte 3 — Interpretando um finding

### 3.1 Estrutura de um finding Inspector v2

[FATO] Um finding do Inspector v2 é um relatório detalhado sobre uma vulnerabilidade em um recurso. Os estados possíveis são:
- **Active** — vulnerabilidade detectada, não remediada
- **Suppressed** — sujeito a uma suppression rule
- **Closed** — vulnerabilidade remediada (o Inspector detecta automaticamente a remediação)

[FATO] Comportamentos de ciclo de vida confirmados na doc:
- Recurso deletado/terminado → findings fechados automaticamente, **deletados após 3 dias**
- Finding fechado por outro motivo → **deletado após 30 dias**
- Inspector desabilitado → findings removidos após **24 horas**
- [FATO] O Inspector **reabre** um finding remediado dentro de 7 dias se o problema reaparecer

### 3.2 O Inspector Score vs. CVSS base score

Este é o campo mais importante para entender — e o que diferencia o Inspector v2 de scanners tradicionais.

**CVSS base score (NVD):**
[FATO] O CVSS (Common Vulnerability Scoring System) base score é calculado pelo NVD (National Vulnerability Database) com base em características intrínsecas da vulnerabilidade:

```
CVSS base score = f(
  Attack Vector,        # Network / Adjacent / Local / Physical
  Attack Complexity,    # Low / High
  Privileges Required,  # None / Low / High
  User Interaction,     # None / Required
  Scope,                # Unchanged / Changed
  Confidentiality,      # None / Low / High
  Integrity,            # None / Low / High
  Availability          # None / Low / High
)
```

[FATO] Confirmado na doc: o CVSS base score é estático — reflete a vulnerabilidade em abstrato, sem considerar o ambiente específico onde ela existe.

**Amazon Inspector Score:**
[FATO] O Inspector Score é calculado correlacionando o CVSS base score com dados do **ambiente de computação específico** do recurso:

```
Inspector Score = CVSS base score
  ± ajustes por:
    - Network reachability (instância acessível da internet?)
    - Exploitability data
    - Contexto de deployment do recurso
```

[FATO] Confirmado: "Amazon Inspector may lower the Inspector score of a finding for an EC2 instance if the vulnerability is exploitable over the network but no open network path to the internet is available from the instance."

Exemplo prático:
```
CVE-2023-XXXX — vulnerabilidade com exploit via rede, CVSS base 9.8 (CRITICAL)

Instância A — porta vulnerável exposta à internet:
  Inspector Score: 9.8 → CRITICAL (sem ajuste, risco real)

Instância B — mesma CVE, mesma instância, mas sem rota de rede para a internet:
  Inspector Score: 6.5 → MEDIUM (ajustado para baixo — exploit impossível remotamente)
```

[FATO] O Inspector Score está em formato CVSS (0–10) e representa a severidade **contextualizada ao ambiente real**, não a severidade teórica máxima.

**CVSS 4.0:**
[FATO] Confirmado na doc: devido a requisitos FedRAMP, o CVSS v3.1 é o score padrão. Quando disponível, um CVSS 4.0 base score é incluído nos metadados de vulnerabilidade. Você pode encontrar a fonte e versão do CVSS nos detalhes do finding.

[FATO] Inspector score NÃO está disponível para instâncias Ubuntu — o Ubuntu usa um sistema de severity rating customizado que difere do CVSS.

### 3.3 EPSS — Exploit Prediction Scoring System

[INCERTO — verificar nas docs atuais; a informação abaixo é baseada no conhecimento de treinamento e no blog AWS de lançamento do Inspector v2] 

O EPSS é um score produzido pela FIRST.org que estima a **probabilidade de exploração ativa** de uma CVE nos próximos 30 dias, baseado em evidências observadas (exploit databases, threat intelligence, darkweb activity). É expresso como um percentil (0–100%) ou probabilidade (0.0–1.0).

Diferença entre CVSS e EPSS:

| Dimensão | CVSS base score | EPSS |
|----------|----------------|------|
| O que mede | Severidade intrínseca da vulnerabilidade | Probabilidade de exploração ativa nos próximos 30 dias |
| Quem calcula | NVD / vendor (FIRST.org spec) | FIRST.org (modelo preditivo) |
| Como varia | Raramente muda (revisto em RCNAs) | Atualizado diariamente |
| Foco | "Quão grave seria se explorado?" | "Qual a chance de estar sendo explorado agora?" |

Exemplo de como CVSS e EPSS divergem:

```
CVE-A: CVSS 9.8 (CRITICAL), EPSS 0.3% (percentil 40)
  → Muito grave se explorado, mas raramente explorada na prática
  → Pode ser deprioritizada em favor de...

CVE-B: CVSS 6.5 (MEDIUM), EPSS 87% (percentil 95)
  → Moderada se explorada, mas sendo ativamente explorada agora
  → Deve ser prioridade imediata de patch
```

[INCERTO] Se o Inspector v2 exibe o campo EPSS diretamente no console: verificar nas docs atuais em `findings-understanding-score.html` ou `findings-understanding-details.html`. A doc que consegui acessar menciona "exploitability data" como fator no Inspector Score, e lista ATT&CK TTPs, CISA KEV, Known malware e Last exploit date como campos de Vulnerability Intelligence — mas não cita EPSS explicitamente pelo nome na versão da página que obtive.

### 3.4 Vulnerability Intelligence

[FATO] Além do score, o painel de Vulnerability Intelligence do finding mostra (confirmado na doc):

| Campo | O que contém |
|-------|-------------|
| **ATT&CK** | MITRE TTPs (tactics, techniques, procedures) associados ao CVE |
| **CISA** | Data em que a CISA adicionou ao Known Exploited Vulnerabilities (KEV) catalog + prazo de patch exigido pelo CISA |
| **Known malware** | Exploit kits e ferramentas conhecidos que exploram esta CVE |
| **Last time reported** | Data do último exploit público conhecido |

[FATO] CISA KEV (Known Exploited Vulnerabilities Catalog) é uma lista mantida pela Cybersecurity and Infrastructure Security Agency com evidências de exploração ativa. Uma CVE presente no KEV tem exploração documentada em ambiente real — independentemente do CVSS score.

**Decisão de prioridade usando todos os sinais:**

```
CVE presente em CISA KEV + CVSS alto + Inspector Score alto
→ Prioridade máxima — exploração ativa confirmada + impacto real no seu ambiente

CVE com CVSS 9.8 + Inspector Score 4.0 (instância isolada) + sem KEV
→ Prioridade menor — instância não é reachable, sem exploração ativa conhecida

CVE com CVSS 6.0 + Inspector Score 6.0 + CISA KEV + Known malware: Emotet
→ Prioridade alta — sendo ativamente explorada por malware real, mesmo com score moderado
```

---

## Parte 4 — Integração com Security Hub

### 4.1 Como funciona

[FATO] Confirmado na documentação oficial do Inspector: **se o Security Hub estiver ativado na conta, o Inspector automaticamente publica findings para o Security Hub via ASFF**. Não há configuração adicional necessária além de ter ambos os serviços habilitados.

[FATO] O fluxo é:
```
Inspector detecta vulnerabilidade
       ↓
Cria finding internamente (Inspector console/API)
       ↓
Publica automaticamente para Security Hub via ASFF
       ↓
(Também publica para EventBridge como evento separado)
```

### 4.2 Formato ASFF do finding Inspector

Campos relevantes de um finding Inspector no ASFF:

```json
{
  "SchemaVersion": "2018-10-08",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/inspector",
  "GeneratorId": "AWSInspector",
  "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
  "Severity": {
    "Label": "HIGH",
    "Normalized": 70
  },
  "Title": "CVE-2023-XXXX - libssl affected",
  "Description": "OpenSSL vulnerability affecting EC2 instance...",
  "Resources": [{
    "Type": "AwsEc2Instance",
    "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"
  }],
  "Vulnerabilities": [{
    "Id": "CVE-2023-XXXX",
    "Cvss": [{
      "Version": "3.1",
      "BaseScore": 9.8
    }],
    "ReferenceUrls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX"]
  }]
}
```

[FATO] O campo `Types` para findings de vulnerabilidade de pacote é `"Software and Configuration Checks/Vulnerabilities/CVE"` — diferente dos findings de rede que usam `"Software and Configuration Checks/Vulnerabilities/Network"`.

### 4.3 Verificação de integração via CLI

```bash
# Verificar se integração com Security Hub está ativa
aws inspector2 list-finding-aggregations \
  --aggregation-type AWS_ACCOUNT

# Confirmar que Inspector está listado como provider no Security Hub
aws securityhub list-enabled-products-for-import
# Deve incluir: arn:aws:securityhub:<region>::product/aws/inspector
```

### 4.4 Adições ao Inspector v2 não cobertas pelo plano

[FATO] Desde o lançamento do Inspector v2, foram adicionados scan types que ampliam o escopo além dos 3 originais:

**Lambda code scanning:** Escaneia vulnerabilidades no código da aplicação (não apenas dependências), integrado ao scan de Lambda functions. Ativação separada dos demais scan types.

**Code Security for Amazon Inspector:** Utiliza o engine do Amazon Q Developer para escanear código de primeira parte (first-party application code), dependências de terceiros e Infrastructure as Code (IaC) — Terraform, CloudFormation etc. — para vulnerabilidades. [INCERTO — verificar disponibilidade regional e integração com Security Hub para este scan type específico]

---

## Checklist de objetivos verificáveis

Ao final da sessão, você deve conseguir responder sem consultar documentação:

- [ ] Explicar a diferença arquitetural entre Inspector v1 (agent obrigatório, scans agendados) e v2 (hybrid mode, continuous scanning, auto-discovery)
- [ ] Descrever os dois caminhos do hybrid scanning mode: SSM agent vs. EBS snapshot, e quando cada um é usado
- [ ] Citar o comando CLI para habilitar EC2 + ECR + Lambda scanning
- [ ] Explicar a diferença entre CVSS base score (estático, intrínseco) e Inspector Score (contextualizado ao ambiente)
- [ ] Dar um exemplo de como o Inspector Score pode ser mais baixo que o CVSS base score
- [ ] Explicar o que é o CISA KEV e por que uma CVE nele é prioridade independente do CVSS score
- [ ] Explicar por que a integração Inspector → Security Hub não requer configuração adicional
- [ ] Citar o `ProductArn` que identifica findings do Inspector no Security Hub

---

## Exercício de reflexão

> Você é o security engineer responsável por uma conta AWS com 80 instâncias EC2, 15 repositórios ECR e 40 funções Lambda. O Inspector v2 foi habilitado ontem e gerou **2.400 findings** de vulnerabilidade de pacotes. O CISO pede uma estratégia de priorização para os próximos 30 dias.
>
> **Pergunta 1:** Descreva os critérios de priorização que você aplicaria, usando os campos disponíveis em um finding do Inspector v2. Quais sinais indicam "patch imediato" vs. "próximo ciclo de manutenção"?
>
> **Pergunta 2:** 30 das 80 instâncias EC2 não têm SSM agent instalado e são instâncias paradas (stopped) de um ambiente de batch processing que roda apenas à noite. O Inspector as está escaneando? Se sim, por qual caminho?
>
> **Pergunta 3:** Você tem uma imagem ECR com CVSS 9.8, Inspector Score 9.8, presente no CISA KEV, com known malware "Metasploit module". Mas a imagem não está atualmente rodando em nenhum cluster ECS. Isso muda a prioridade? Explique o raciocínio.

---

## Referências primárias

- [What is Amazon Inspector (docs)](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) — visão geral do serviço e integrações
- [Automated scan types in Amazon Inspector (docs)](https://docs.aws.amazon.com/inspector/latest/user/scanning-resources.html) — cobertura de EC2 (hybrid), ECR, Lambda
- [Understanding Amazon Inspector findings (docs)](https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html) — estados (Active/Suppressed/Closed) e ciclo de vida
- [Amazon Inspector score and vulnerability intelligence (docs)](https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-score.html) — CVSS metrics, Inspector score, CISA/ATT&CK/known malware
- [Scanning EC2 instances — agentless (docs)](https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html#agentless) — hybrid scanning mode detalhado
- [AWS Security Blog — Inspector v2 deep dive](https://aws.amazon.com/blogs/security/amazon-inspector-v2-continually-scans-workloads-for-vulnerabilities/) — post de lançamento com comparação v1 vs v2, EPSS, e modelo de integração
