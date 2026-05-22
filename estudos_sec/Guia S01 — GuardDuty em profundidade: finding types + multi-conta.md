# Guia 1 — GuardDuty em profundidade: finding types + multi-conta

**Depende de:** nenhuma sessão anterior  
**Próxima sessão:** Guia 2 — Security Hub (ASFF + EventBridge)

---

## Orientação para a sessão

Esta sessão cobre quatro objetivos verificáveis. Organize o tempo assim:

- **0–15 min** → Parte 1: anatomia de um finding + as 5 famílias
- **15–30 min** → Parte 2: fontes de dados (management vs. data events)
- **30–45 min** → Parte 3: suppression rules — configuração prática
- **45–55 min** → Parte 4: modelo multi-conta com Organizations
- **55–60 min** → Exercício de reflexão

---

## Parte 1 — As 5 famílias de findings

### 1.1 Formato do nome de um finding

 Todo finding do GuardDuty segue o formato:

```
ThreatPurpose:ResourceType/ThreatFamilyName.DetectionMechanism
```

Exemplo: `CryptoCurrency:EC2/BitcoinTool.B!DNS`

- **ThreatPurpose** — intenção da ameaça (o que o atacante está fazendo): `Backdoor`, `CryptoCurrency`, `Exfiltration`, `PrivilegeEscalation`, `Recon`, `Stealth`, `Trojan`, `UnauthorizedAccess`, `Policy`, `PenTest` etc.
- **ResourceType** — o recurso AWS afetado: `EC2`, `IAMUser`, `S3`, `Kubernetes`, `Malware`
- **ThreatFamilyName** — família de ameaça específica
- **DetectionMechanism** (após `!`) — como foi detectado: `DNS`, `TCP`, `UDP`, `B` (comportamento) etc.

> Saber ler o nome do finding é metade do diagnóstico: `Exfiltration:S3/ObjectRead.Unusual` já diz que houve leitura anômala de objetos S3 com intenção de exfiltração.

---

### 1.2 Família EC2

**O que monitora:** atividade de rede em instâncias EC2 — tráfego VPC Flow Logs e consultas DNS.

**Fonte de dados primária:**  VPC Flow Logs e DNS query logs — estes são **foundational data sources**, consumidos pelo GuardDuty diretamente sem necessidade de habilitação adicional.

**Finding crítico de referência:** `Backdoor:EC2/C&CActivity.B!DNS`

- **O que significa:** Uma instância EC2 está fazendo consultas DNS para um domínio registrado como infraestrutura de Command & Control (C2) conhecida.
- **Por que é crítico:** Indica comprometimento de host — a instância está "ligando para casa" para receber comandos do atacante.
- **Severidade:** High (7.5–8.9 na escala 0–10 do GuardDuty)
- **Resposta esperada:** Isolar a instância imediatamente (SG de quarentena), tirar snapshot EBS para forensics, invalidar credenciais de instância (Instance Profile).

**Outros findings EC2 importantes:**
- `CryptoCurrency:EC2/BitcoinTool.B!DNS` — mineração de criptomoeda; impacto financeiro imediato
- `Trojan:EC2/DropPoint` — instância atuando como receptora de dados exfiltrados
- `Recon:EC2/PortProbeUnprotectedPort` — varredura de portas recebida em porta não protegida por SG

---

### 1.3 Família IAMUser

**O que monitora:** atividade de entidades IAM — usuários, roles, chaves de acesso.

**Fonte de dados primária:**  CloudTrail **management events** — o GuardDuty tem pipeline próprio e independente do CloudTrail; você não precisa ter CloudTrail habilitado na conta para receber esses findings.

**Finding crítico de referência:** `Policy:IAMUser/RootCredentialUsage`

- **O que significa:** As credenciais root da conta AWS foram usadas para fazer uma chamada de API (exceto chamadas ao próprio console de billing ou de suporte).
- **Por que é crítico:** Root credentials não devem ser usadas operacionalmente. [CONSENSO] O uso de credenciais root é considerado um indicador de comprometimento ou de configuração gravemente inadequada pela comunidade de segurança AWS.
- **Severidade:** High
- **Resposta esperada:** Verificar se a ação foi autorizada; se não foi, considerar o root comprometido — ativar MFA se ausente, rotacionar senha root, revisar access keys root (devem ser deletadas).

**Outros findings IAMUser importantes:**
- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — login no console de um IP anômalo (TOR, VPN conhecida, país inesperado)
- `Recon:IAMUser/MaliciousIPCaller` — chamadas de API de reconhecimento (ListBuckets, DescribeInstances) de IP malicioso
- `PenTest:IAMUser/KaliLinux` — chamadas de API usando user-agent reconhecido do Kali Linux (pentester ou atacante)

---

### 1.4 Família S3

**O que monitora:** acesso a buckets e objetos S3.

**Fonte de dados primária:**  CloudTrail **S3 data events** e S3 management events — requerem que o **S3 Protection** esteja habilitado no GuardDuty (não é parte dos foundational data sources no modo legado, mas é habilitado por padrão em contas novas desde 2021).

**Finding crítico de referência:** `Exfiltration:S3/ObjectRead.Unusual`

- **O que significa:** Uma entidade está lendo objetos S3 de forma incomum — volume, padrão de acesso, localização geográfica ou horário anômalos em relação ao histórico da entidade.
- **Por que é crítico:** Padrão clássico de exfiltração de dados — atacante com credenciais válidas extraindo conteúdo do bucket.
- **Severidade:** High
- **Resposta esperada:** Identificar quais objetos foram lidos, verificar se contêm dados sensíveis, revogar credenciais da entidade, habilitar Macie para classificação retrospectiva.

**Outros findings S3 importantes:**
- `Policy:S3/BucketAnonymousAccessGranted` — bucket configurado para acesso público (qualquer pessoa, sem autenticação)
- `Stealth:S3/ServerAccessLoggingDisabled` — logging de acesso do bucket foi desabilitado (evasão de defesa)
- `Discovery:S3/MaliciousIPCaller` — enumeração de objetos S3 a partir de IP malicioso conhecido

---

### 1.5 Família EKS (Kubernetes)

**O que monitora:** atividade nos clusters EKS via audit logs do Kubernetes.

**Fonte de dados primária:**  EKS Audit Logs — requerem que o **EKS Audit Log Monitoring** (ou **EKS Protection**) esteja habilitado no GuardDuty. [INCERTO — verificar docs atuais] A nomenclatura exata da feature variou entre "EKS Protection" e "Kubernetes protection" ao longo das versões da UI.

**Finding crítico de referência:** `PrivilegeEscalation:Kubernetes/PrivilegedContainer`

- **O que significa:** Um container foi criado ou iniciado com a flag `privileged: true` no security context, o que dá ao processo dentro do container acesso quase irrestrito ao kernel do host.
- **Por que é crítico:** Um container privilegiado pode fazer escape para o nó subjacente (node) e comprometer todo o cluster.
- **Severidade:** High
- **Resposta esperada:** Identificar qual pod/deployment foi modificado, verificar se houve kubectl exec subsequente, investigar se é workload legítimo ou comprometimento da supply chain.

**Outros findings Kubernetes importantes:**
- `CredentialAccess:Kubernetes/MaliciousIPCaller` — chamadas à API do Kubernetes (kubectl) de IP malicioso
- `Execution:Kubernetes/ExecInKubernetesPod` — `kubectl exec` executado em um pod — pode indicar post-exploitation
- `Policy:Kubernetes/AdminAccessToDefaultServiceAccount` — service account `default` recebeu permissão cluster-admin

---

### 1.6 Família Malware Protection

**O que monitora:** presença de malware em volumes EBS e (com configuração adicional) objetos S3.

**Fonte de dados primária:**  Scanning de volumes EBS — o GuardDuty cria snapshots dos volumes suspeitos e os escaneia em ambiente isolado. Não requer agente na instância.

**Finding crítico de referência:** `Execution:EC2/MaliciousFile`

- **O que significa:** Um arquivo malicioso (vírus, trojan, rootkit) foi detectado no scan do volume EBS de uma instância EC2.
- **Por que é crítico:** Evidência direta de comprometimento de host — o arquivo malicioso está no disco da instância.
- **Severidade:** High
- **Resposta esperada:** Isolar a instância, preservar o snapshot EBS para forensics, identificar vetor de entrada (via CloudTrail + VPC Flow Logs), verificar se outros volumes do mesmo ASG foram comprometidos.

**Outro finding Malware importante:**
- `Object:S3/MaliciousFile` — arquivo malicioso enviado para um bucket S3 (requer Malware Protection for S3, habilitação separada)

---

### 1.7 Nota sobre proteções adicionais (além das 5 famílias do plano)

O GuardDuty adicionou proteções adicionais que não estavam no escopo original deste plano:
- **RDS Protection** — anomalias de login em instâncias RDS/Aurora
- **Lambda Protection** — atividade de rede suspeita em funções Lambda durante execução
- **Runtime Monitoring** — agente (SSM-based ou ECS/EKS sidecar) que monitora syscalls em tempo de execução para EC2, ECS e EKS

Estas proteções têm custo incremental separado e precisam ser habilitadas explicitamente.

---

## Parte 2 — Management events vs. data events como fonte

Esta é uma das distinções mais cobradas e mais mal-entendidas no GuardDuty.

### 2.1 O que são

 No contexto do CloudTrail (e por extensão do GuardDuty), os eventos são categorizados em:

**Management events** (também chamados de *control plane events*):
- Chamadas de API que criam, modificam ou deletam recursos AWS
- Exemplos: `CreateBucket`, `RunInstances`, `CreateUser`, `AttachRolePolicy`, `DeleteTrail`
-  São capturados pelo CloudTrail por padrão (sem custo adicional para 1 trail gratuito)
-  O GuardDuty tem seu **próprio pipeline independente** de ingestão de management events — ele não depende de um CloudTrail estar configurado na conta para gerar findings IAMUser

**Data events** (também chamados de *data plane events*):
- Chamadas de API sobre recursos específicos — operações em objetos, não no recurso em si
- Exemplos: `GetObject`, `PutObject` (S3), `Invoke` (Lambda), `GetItem` (DynamoDB)
-  **NÃO são capturados pelo CloudTrail por padrão** — requerem configuração explícita e geram custo adicional
-  O GuardDuty também tem pipeline independente para S3 data events — você não precisa habilitar CloudTrail data events para ter S3 Protection no GuardDuty

### 2.2 A implicação operacional crítica

```
┌─────────────────────────────────────────────────────────────┐
│                    GUARDDUTY DATA SOURCES                   │
│                                                             │
│  Foundational (sempre ativas):                              │
│  ├── VPC Flow Logs         → EC2 findings                   │
│  ├── DNS query logs        → EC2 findings                   │
│  └── CloudTrail mgmt evts  → IAMUser findings               │
│                                                             │
│  Protection plans (habilitação separada):                   │
│  ├── S3 Protection         → S3 findings (data events S3)   │
│  ├── EKS Audit Log Mon.    → Kubernetes findings            │
│  ├── Malware Protection    → Malware findings (EBS scan)    │
│  ├── RDS Protection        → RDS login anomalies            │
│  ├── Lambda Protection     → Lambda network findings        │
│  └── Runtime Monitoring    → Syscall-level findings         │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Por que isso importa para detecção

 Um finding `Policy:IAMUser/RootCredentialUsage` vem de um **management event** (`ConsoleLogin` ou uma chamada de API) — o GuardDuty detecta isso mesmo sem CloudTrail configurado na conta.

 Um finding `Exfiltration:S3/ObjectRead.Unusual` vem de um **S3 data event** (`GetObject`) — requer S3 Protection habilitado. Se S3 Protection estiver desabilitado, o GuardDuty **não verá** esse acesso.

 Isso também significa que um atacante que desabilita o CloudTrail (`DeleteTrail`, `StopLogging`) ainda será detectado pelo GuardDuty via management events — o GuardDuty tem seu próprio canal, independente do CloudTrail da conta.

---

## Parte 3 — Suppression rules

### 3.1 O que são e quando usar

 Uma suppression rule é um filtro persistente que arquiva automaticamente os findings que correspondem a critérios definidos. Findings suprimidos são arquivados com status `ARCHIVED` — eles ainda existem e são auditáveis, mas não aparecem como findings ativos.

**Casos de uso legítimos:**
- Findings de atividade esperada em ambientes de pentest
- Findings de scanners de segurança internos conhecidos (ex: Tenable, Qualys)
- Findings de ferramentas de CI/CD que fazem chamadas de API em volume
- Findings de ambientes de desenvolvimento com configurações deliberadamente abertas

A regra de ouro é: suppression rules devem ser específicas ao máximo. Uma regra ampla demais pode silenciar ameaças reais disfarçadas de atividade conhecida.

### 3.2 Configuração via console

**Pré-requisito:** estar logado na conta GuardDuty ou ter acesso como delegated admin.

1. GuardDuty console → **Findings** → selecione o finding que deseja suprimir
2. Na barra de ação: **Actions** → **Create suppression rule**
3. O console pré-preenche os critérios com os atributos do finding selecionado
4. Ajuste os critérios para ser específico:
   - **Finding type** — ex: `Recon:EC2/PortProbeUnprotectedPort`
   - **Resource tags** — ex: `Environment = dev`
   - **Instance ID** específica, ou **IP** específico do scanner
5. Nomeie a regra (ex: `suppress-portscan-dev-nessus`) e salve

> Você pode — e deve — combinar múltiplos critérios com AND. Quanto mais específico, menor o risco de supressão acidental.

### 3.3 Configuração via CLI

```bash
# Criar um filter (suppression rule) que arquiva automaticamente findings
# de portprobe em instâncias tagged como Environment=dev
aws guardduty create-filter \
  --detector-id <DETECTOR_ID> \
  --name "suppress-portprobe-dev" \
  --action ARCHIVE \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": ["Recon:EC2/PortProbeUnprotectedPort"]
      },
      "resource.instanceDetails.tags.key": {
        "Eq": ["Environment"]
      },
      "resource.instanceDetails.tags.value": {
        "Eq": ["dev"]
      }
    }
  }'
```

 O parâmetro `--action ARCHIVE` é o que torna um filter uma suppression rule — sem ele, é apenas um saved filter para visualização.

### 3.4 O que NÃO fazer

[OPINIÃO — recomendação da documentação AWS] Não suprima por finding type isoladamente sem pelo menos um critério de recurso específico. Uma regra que suprime todo `Recon:EC2/PortProbeUnprotectedPort` vai silenciar também atividade real de reconhecimento externo direcionada às suas instâncias de produção.

---

## Parte 4 — Multi-conta com AWS Organizations

### 4.1 O modelo de delegated administrator

 O modelo preferencial para GuardDuty em ambientes multi-conta com AWS Organizations funciona assim:

```
┌────────────────────────────────────────┐
│         Management Account             │
│  (designa o delegated admin via API    │
│   EnableOrganizationAdminAccount)      │
└─────────────┬──────────────────────────┘
              │ designa
              ▼
┌────────────────────────────────────────┐
│      Delegated Admin Account           │
│  (security account / dedicated)        │
│  - Vê findings de TODAS as contas      │
│  - Configura auto-enable               │
│  - Gerencia suppression rules global   │
│  - Configura protection plans          │
└─────────────┬──────────────────────────┘
              │ gerencia
    ┌─────────┴─────────┐
    ▼                   ▼
┌────────┐         ┌────────┐
│ Conta A│   ...   │ Conta N│
│(member)│         │(member)│
└────────┘         └────────┘
```

### 4.2 Fatos operacionais críticos confirmados na documentação oficial

 **O delegated admin é regional.** Você deve designar o mesmo delegated admin em cada região onde quer gerenciar GuardDuty. Não é possível ter contas diferentes como delegated admin em regiões diferentes.

 **Limite de membros:** 50.000 member accounts por delegated admin account. Acima disso, você recebe notificação via CloudWatch e Health Dashboard.

 **Não é recomendado usar o Management Account como delegated admin.** A documentação AWS explicitamente desaconselha por princípio de menor privilégio.

 **Remover o delegated admin não desabilita o GuardDuty nas contas membro.** GuardDuty permanece ativo em todas as contas membro mesmo após a remoção do admin.

### 4.3 Auto-enable preferences

 O delegated admin configura três opções de auto-enable via console (`Accounts` → `Edit`) ou via `UpdateOrganizationConfiguration`:

| Opção | Comportamento |
|-------|---------------|
| `ALL` | Habilita GuardDuty em todos os membros existentes e novos (pode levar até 24h para propagação) |
| `NEW` | Habilita automaticamente apenas em contas que ingressam na org após a configuração |
| `NONE` | Sem habilitação automática — cada conta é gerenciada individualmente |

**Exemplo CLI:**
```bash
aws guardduty update-organization-configuration \
  --detector-id <DETECTOR_ID_DO_DELEGATED_ADMIN> \
  --auto-enable-organization-members ALL
```

**Validação:**
```bash
aws guardduty describe-organization-configuration \
  --detector-id <DETECTOR_ID_DO_DELEGATED_ADMIN>
```

 Cada protection plan (S3 Protection, EKS, Malware etc.) tem seu próprio auto-enable configurável separadamente — exceto Malware Protection for S3, que não suporta auto-enable via Organizations.

### 4.4 Como designar o delegated admin (Management Account)

Via console: Organizations → Services → GuardDuty → Enable trusted access, depois GuardDuty → Settings → Delegate administrator.

Via CLI (a partir do **Management Account**):
```bash
aws guardduty enable-organization-admin-account \
  --admin-account-id <ID_DA_SECURITY_ACCOUNT>
```

### 4.5 O que o delegated admin PODE e NÃO PODE fazer

 **Pode:**
- Ver findings de todas as contas membro
- Configurar auto-enable e protection plans para toda a org
- Criar suppression rules que se aplicam à sua própria conta
- Suspender ou remover contas membro do GuardDuty

 **Não pode:**
- Ver o conteúdo dos recursos da conta membro (só os metadados do finding)
- Aplicar suppression rules centralizadas que afetam as contas membro automaticamente (cada membro gerencia suas próprias suppression rules, a menos que você use automação via EventBridge + Lambda)

---

## Checklist de objetivos verificáveis

Ao final da sessão, você deve conseguir responder sem consultar documentação:

- [ ] Citar as 5 famílias de findings e um exemplo crítico em cada
- [ ] Explicar qual fonte de dados (VPC Flow Logs, CloudTrail management events, S3 data events) alimenta cada família
- [ ] Explicar por que o GuardDuty detecta uso de root credentials mesmo sem CloudTrail habilitado
- [ ] Explicar a diferença entre `action ARCHIVE` e um saved filter
- [ ] Descrever quem designa o delegated admin e como
- [ ] Citar as 3 opções de auto-enable (ALL / NEW / NONE) e o que cada uma faz
- [ ] Dizer o que acontece com as contas membro se o delegated admin for removido

---

## Exercício de reflexão

> Você é o security engineer de uma empresa com 120 contas AWS. Nos últimos 30 dias, o GuardDuty gerou 4.200 findings — 92% deles são `Recon:EC2/PortProbeUnprotectedPort` originados de um scanner de vulnerabilidade interno (Tenable) que roda em uma instância dedicada com IP fixo e tags `Team=security, Purpose=scanner`.
>
> **Pergunta 1:** Descreva a suppression rule mais específica possível para eliminar o ruído desse scanner sem silenciar atividade real de reconhecimento externo.
>
> **Pergunta 2:** Se amanhã o IP do scanner mudar (migração para outra AZ), o que acontece com a sua suppression rule? Como você tornaria a rule resiliente a essa mudança usando tags?
>
> **Pergunta 3:** Uma das suas contas membro tem o S3 Protection desabilitado no GuardDuty. Um atacante obtém credenciais de um usuário IAM dessa conta e faz GetObject em 15 buckets. Qual finding o GuardDuty geraria (se algum)? Por quê?

---

## Referências primárias

- [GuardDuty — Understanding findings (docs oficiais)](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html) — ponto de entrada para a taxonomia completa de findings
- [GuardDuty finding format (docs)](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html) — anatomia do nome e campos de um finding
- [GuardDuty — Managing accounts with AWS Organizations (docs)](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_organizations.html) — modelo de delegated administrator
- [Setting auto-enable preferences (docs)](https://docs.aws.amazon.com/guardduty/latest/ug/set-guardduty-auto-enable-preferences.html) — opções ALL/NEW/NONE com exemplos CLI
- [Amazon GuardDuty Tester (repositório GitHub oficial)](https://github.com/awsamples/amazon-guardduty-tester) — scripts para gerar findings sintéticos em lab
