# Guia 9 — Threat Modeling em Workloads AWS: STRIDE + IAM Lateral Movement

**Depende de:** Guia 3 (escalação IAM), S06 (exfiltração S3), S07 (CloudTrail), S08 (Macie)  
**Ultimo guia da semana**

> **Nota:** Esta sessão sintetiza os conhecimentos dos Guias 3, 6, 7 e 8. Se você ainda não completou essas sessões, o guia ainda é utilizável — mas o exercício final terá mais profundidade com esse contexto.

---

## Objetivos da sessão

| # | Objetivo | Verificável |
|---|----------|-------------|
| O1 | Modelar arquitetura API Gateway → Lambda → RDS + S3 no AWS Threat Composer | Arquivo `.tc.json` com assets, threats e mitigações |
| O2 | Identificar o IAM lateral movement path mais provável nessa arquitetura | Técnica específica com permissão mínima + CloudTrail event |
| O3 | Mapear controles preventivos e detectivos para cada threat identificada | Tabela threat → preventivo → detectivo |

---

## Parte 1 — Fundamentos de Threat Modeling no Contexto AWS

### 1.1 Por que threat modeling

 O AWS Well-Architected Framework Security Pillar (SEC01-BP07) define threat modeling como best practice:

> *"Use a threat model to identify and maintain an up-to-date register of potential threats. Prioritize your threats and adapt your security controls to prevent, detect, and respond."*

### 1.2 Os 4 passos centrais

```
1. Identificar  — assets, atores, entry points, componentes, trust levels
2. Enumerar     — listar ameaças potenciais (STRIDE, OWASP Top 10, etc.)
3. Mitigar      — para cada threat, identificar controles de segurança
4. Avaliar      — risk matrix: threat adequadamente mitigada? residual risk aceitável?
```

### 1.3 STRIDE

| Letra | Ameaça | Propriedade violada | Exemplo em AWS |
|-------|--------|--------------------|----|
| **S** | Spoofing | Autenticação | Credenciais IAM roubadas |
| **T** | Tampering | Integridade | SQL injection; alterar objeto S3 |
| **R** | Repudiation | Não-repúdio | Desabilitar CloudTrail |
| **I** | Information Disclosure | Confidencialidade | Bucket S3 público; segredos em env vars |
| **D** | Denial of Service | Disponibilidade | Flood sem rate limiting |
| **E** | Elevation of Privilege | Autorização | `iam:PassRole` abuse |

### 1.4 Shared Responsibility como balizador

Em arquitetura serverless (API Gateway + Lambda + S3), você foca em: configuração incorreta, políticas IAM excessivas e falhas na aplicação — não em ameaças de infraestrutura (responsabilidade AWS).

---

## Parte 2 — AWS Threat Composer

 Ferramenta open-source em `https://awslabs.github.io/threat-composer/` (web app, sem conta AWS necessária). Arquivo `.tc.json` versionável em Git.

### Threat Grammar

```
[Threat Actor] pode [Action] via [Threat Method] para [Impact] em [Asset]
```

**Exemplo:**
> *"Um atacante com credenciais IAM vazadas pode realizar privilege escalation via iam:PassRole + lambda:UpdateFunctionCode para assumir a execution role com permissões elevadas, obtendo acesso ao RDS e dados sensíveis."*

---

## Parte 3 — Modelando a Arquitetura (O1)

### 3.1 Arquitetura de referência

```
Internet → [API Gateway] → [Lambda (LambdaExecRole)] → [RDS PostgreSQL] + [S3 Bucket]
```

### 3.2 Assets

| Asset | Classificação | Impacto se comprometido |
|-------|--------------|------------------------|
| Dados de clientes (PII, financeiros) | Alto | Violação LGPD/PCI-DSS |
| Credenciais da aplicação (DB password) | Crítico | Acesso irrestrito ao banco |
| Execution role da Lambda (credenciais IAM) | Crítico | Pivot para todos os serviços da role |
| Código da função Lambda | Alto | Backdoor no processamento |
| Logs de auditoria | Médio | Perda de visibilidade |

### 3.3 Entry points

| Entry Point | Trust Level | Autenticado? |
|-------------|-------------|--------------|
| API Gateway (public endpoint) | Untrusted | Depende de config |
| Lambda → RDS | VPC internal | Senha ou IAM auth |
| Lambda → S3 | IAM | ✅ (execution role) |
| Developer → Lambda deploy | IAM | ✅ |

---

## Parte 4 — STRIDE por Componente (O1 + O3)

### API Gateway

| STRIDE | Threat | Likelihood |
|--------|--------|-----------|
| S | API sem autenticação (endpoint público sem authorizer) | Alta |
| T | Payloads maliciosos (SQL injection, XSS) | Média |
| R | Access Logging não habilitado | Média |
| I | Stack traces/mensagens de erro detalhadas | Alta |
| D | Volume alto sem WAF/throttling | Média |

### Lambda

| STRIDE | Threat | Likelihood |
|--------|--------|-----------|
| S | Execution role credentials exfiltradas (env var leak) | Alta |
| T | `lambda:UpdateFunctionCode` para adicionar backdoor | Média |
| R | Desabilitar CloudTrail/apagar CloudWatch logs | Baixa |
| I | Segredos em env vars visíveis via `GetFunctionConfiguration` | Alta |
| D | Esgotar concorrência (reserve não configurado) | Média |
| E | **iam:PassRole abuse** — criar recursos com roles privilegiadas | Alta |

### RDS

| STRIDE | Threat | Likelihood |
|--------|--------|-----------|
| S | SQL injection contorna autenticação de usuário | Média |
| T | SQL injection modifica/apaga dados | Média |
| I | SQL injection faz dump de tabelas com PII | Média |

### S3

| STRIDE | Threat | Likelihood |
|--------|--------|-----------|
| T | Sobrescrever objetos (role com PutObject sem MFA delete) | Média |
| R | Data events não habilitados — GetObject não auditado | Alta |
| I | Bucket policy permite acesso cross-account sem `aws:PrincipalOrgID` | Alta |
| E | Cross-account replication para bucket de atacante | Baixa |

---

## Parte 5 — IAM Lateral Movement (O2)

### 5.1 Path mais provável: `iam:PassRole` + `lambda:UpdateFunctionCode`

```
1. Atacante compromete Lambda execution role (env var leak, código exposto)
2. Role tem (por excesso): iam:PassRole + lambda:UpdateFunctionCode
3. Atacante:
   ├─ Atualiza Lambda com código malicioso que assume role privilegiada
   ├─ Cria nova Lambda com role de alto privilégio
   └─ Cria CloudFormation stack com role admin
```

**Permissão mínima:** `iam:PassRole` + `lambda:UpdateFunctionCode` (ou `CreateFunction` ou `cloudformation:CreateStack`)

**CloudTrail events:**
- `UpdateFunctionCode20150331v2` (lambda.amazonaws.com)
- `CreateFunction20150331v2` (lambda.amazonaws.com)
- `CreateStack` (cloudformation.amazonaws.com)
- `iam:PassRole` aparece nos request parameters do evento que o usa

### 5.2 OrganizationAccountAccessRole

 Em contas **criadas** via Organizations (não convidadas):
- AWS cria `OrganizationAccountAccessRole` com trust para Management Account root
- Permissões: `AdministratorAccess`
- Atacante que compromete qualquer principal na Management Account pode assumir essa role em todas as contas-membro

**Mitigação:** não fazer deploy de workloads na Management Account; modificar trust policy da role; SCP restringindo `sts:AssumeRole` para essa role.

---

## Parte 6 — Controles Preventivos e Detectivos (O3)

### Tabela resumida

| Threat | Preventivo | Detectivo |
|--------|-----------|-----------|
| T1 — API sem auth | Cognito/Lambda Authorizer + resource policy | API Gateway access logging + CloudTrail |
| T2 — Role exfiltrada | Least privilege na role + Secrets Manager | GuardDuty `InstanceCredentialExfiltration` + CloudTrail (IP externo) |
| T3 — iam:PassRole abuse | Remover/restringir PassRole + Permission boundary | CloudTrail `UpdateFunctionCode`/`CreateFunction` com role suspeita |
| T4 — S3 exfiltração | `aws:PrincipalOrgID` deny + Block Public Access | CloudTrail data events + Macie policy findings |
| T5 — Credenciais em env vars | Secrets Manager + RDS IAM Auth | CloudTrail `GetFunctionConfiguration` por não-autorizados |
| T6 — OrgAccountAccessRole | Não usar Mgmt Account para workloads + SCP | CloudTrail `AssumeRole` para essa role |

### Priorização (Likelihood × Impact)

| Threat | Prioridade |
|--------|-----------|
| T3 — iam:PassRole abuse | **P1** |
| T2 — execution role exfiltrada | **P1** |
| T5 — credenciais em env vars | **P1** |
| T1 — API sem autenticação | **P2** |
| T4 — S3 exfiltração cross-account | **P2** |
| T6 — OrganizationAccountAccessRole | **P2** |

---

## Checklist de conclusão

- [ ] **O1** — Consigo listar os 6 componentes do STRIDE com exemplo concreto nessa arquitetura
- [ ] **O1** — Entendo a estrutura do Threat Composer: Threats (com grammar), Mitigations, links
- [ ] **O2** — Consigo descrever o lateral movement via `iam:PassRole + lambda:UpdateFunctionCode` e o CloudTrail event
- [ ] **O2** — Entendo o risco do `OrganizationAccountAccessRole` e como mitigar
- [ ] **O3** — Para cada threat P1, consigo citar um controle preventivo E um detectivo

---

## Exercício de reflexão

**Contexto:** Arquitetura expandida com Cognito User Pool. Lambda agora chama `cognito-idp:AdminGetUser`.

**Perguntas:**
1. Qual novo asset é introduzido? Impact rating?
2. Com `cognito-idp:AdminGetUser` na role, que Information Disclosure é possível se comprometida?
3. CI/CD precisa de `lambda:UpdateFunctionCode`. Que controles exigir para reduzir risco de T3?
4. Escreva UMA threat statement para Cognito usando a gramática do Threat Composer.

**Respostas:**

**1.** Cognito User Pool (identidades, e-mails, MFA). Impact: **Alto** — permite impersonation de qualquer usuário.

**2.** Atacante enumera todos os usuários via `ListUsers` + `AdminGetUser` — exfiltra e-mails, telefones, atributos. Mitigação: restringir ao User Pool ARN específico; usar `GetUser` (escopo do próprio usuário) quando possível.

**3.** Controles: restringir permissão ao ARN da função; role do CI/CD sem `iam:PassRole`; AWS Signer (code signing); alerting em `UpdateFunctionCode` fora do horário de deploy; code review obrigatório.

**4.** *"Um atacante com credenciais de usuário comprometido (phishing) pode realizar account takeover via Cognito password reset flow exploiting fraco rate limiting, para assumir a identidade do usuário legítimo e acessar seus dados no RDS."* — Spoofing | Priority: High.

---

## Referências primárias

- [How to approach threat modeling — AWS Security Blog](https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/)
- [SEC01-BP07 — AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_threat_model.html)
- [AWS Threat Composer (web app)](https://awslabs.github.io/threat-composer/)
- [AWS Threat Composer (GitHub)](https://github.com/awslabs/threat-composer)
- [AWS IAM Privilege Escalation — Hacking The Cloud](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
- [AWS Organizations Defaults & Pivoting — Hacking The Cloud](https://hackingthe.cloud/aws/general-knowledge/aws_organizations_defaults/)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
