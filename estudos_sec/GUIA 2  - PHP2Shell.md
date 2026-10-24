# PHP2Shell em ambiente AWS: simular, detectar e corrigir com serviços AWS

---

## Objetivo

Operacionalizar na AWS os três trabalhos defensivos da Parte 1:

1. **Descobrir exposição** na frota (quais hosts/imagens/funcões rodam PHP afetado).
2. **Reduzir a janela na borda** enquanto o patch não chega (WAF/CloudFront/ALB).
3. **Corrigir em escala** por tipo de compute (EC2, containers, Beanstalk, Lambda, Lightsail) e **detectar uso** da janela (GuardDuty/CloudWatch/Security Hub).

Tudo sem exploit mesma postura da Parte 1.

---

## Posição oficial da AWS (boletim 2026-143-AWS)

A AWS afirma: **"AWS services are not impacted by these issues"** mas clientes que **rodam versões de PHP afetadas dentro de serviços** podem ser impactados. Não havia propagação cross-customer estabelecida até a data.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

 Orientação **por serviço** (do boletim):

```
╔════════════════════╦══════════════════════════════════════════════════════════╗
║ Serviço            ║ Situação / ação                                            ║
╠════════════════════╬══════════════════════════════════════════════════════════╣
║ Amazon WorkMail    ║ AWS aplicou controles e subiu p/ PHP 8.3.36. Sem ação.     ║
║ Elastic Beanstalk  ║ Novas platform versions p/ PHP 8.2–8.5. Managed Platform   ║
║                    ║ Updates: chega na próxima janela. Senão: atualizar manual. ║
║ AWS Lambda         ║ NÃO há runtime PHP gerenciado. PHP via custom runtime /     ║
║                    ║ container: atualizar PHP e reimplantar.                    ║
║ Amazon Linux       ║ Pacotes PHP atualizados nas regiões comerciais.            ║
║ Amazon Lightsail   ║ Blueprints atualizados. NÃO atualiza instância em execução ║
║                    ║ no lugar → criar nova instância e migrar.                  ║
╚════════════════════╩══════════════════════════════════════════════════════════╝
```
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

 Versões afetadas e corrigidas (ranges confirmados pelo boletim):

```
PHP 8.5: afetado 8.5.0–8.5.11  → corrigido 8.5.12
PHP 8.4: afetado 8.4.0–8.4.26  → corrigido 8.4.27
PHP 8.3: afetado 8.3.0–8.3.35  → corrigido 8.3.36
PHP 8.2: afetado 8.2.0–8.2.34  → corrigido 8.2.35
PHP 5.4–8.1: SEM correção upstream (EOL) → "Migration to a supported branch is required."
```
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

 **AWS WAF:** o **AWS WAF PHP Managed Rule Group está sendo atualizado para as duas CVEs**. Clientes na *default version* são protegidos automaticamente; quem **fixou (pinned) uma versão precisa atualizar** para receber a proteção. Acompanhe o *AWS WAF Managed Rules changelog* e assine o tópico SNS de Managed Rules. O boletim reforça: **patch é a única correção completa**; WAF é controle compensatório.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

---

## Mapa: os 3 trabalhos → serviços AWS

```
                    ┌──────────────────────── BORDA ────────────────────────┐
  Internet ──▶ CloudFront ──▶ AWS WAF ──▶ ALB ──▶  PHP em EC2 / ECS / EKS
                               │  (PHP Managed Rule Group + Size + Rate)      │
                               └── reduz a janela (NÃO corrige) ──────────────┘
                                                      │
   DESCOBRIR            REDUZIR JANELA                │ logs            DETECTAR USO
   ─────────            ─────────────                 ▼                 ───────────
   Inspector (EC2/ECR)  AWS WAF (managed+custom)   CloudWatch Logs   GuardDuty Runtime
   SSM Inventory        Shield / CloudFront        + Logs Insights   (processo/rede)
        │                                          (crash/OOM)             │
        └──────────────┐                                   └───────┐      │
                       ▼                                           ▼      ▼
   CORRIGIR EM ESCALA: SSM Patch Manager (EC2) · Image Builder/CI (containers) ·
   Beanstalk platform update · Lambda redeploy · Lightsail migrar
                       │                                           │
                       └────────▶ Security Hub (agrega achados) ◀──┘
                                        │
                                        ▼  EventBridge → SSM Automation / SNS (resposta)
```

---

## 1. Descobrir o que está vulnerável (Amazon Inspector + SSM Inventory)

 O **Amazon Inspector** escaneia **EC2, imagens em ECR e funções Lambda**, cruzando pacotes com 50+ feeds (NVD, MITRE, advisories de fornecedor), atualizados ao menos 1x/dia. **PHP é uma linguagem suportada** para EC2 (agentless/VM Scanner) e para ECR.
Fonte: [Amazon InspectorSupported OS and languages](https://docs.aws.amazon.com/inspector/latest/user/supported.html).

 Dois detalhes que mudam sua estratégia:
- Detecções de pacote de **SO em Linux cobrem só o repositório padrão (rpm/dpkg)****não** incluem aplicações de terceiros, repositórios de suporte estendido nem *application streams*, salvo exceção documentada. Ou seja: PHP instalado via **repositório de terceiros (Remi, PPA ondrej/sury)** pode **não** ser flagrado como pacote de SO.
- **Lambda não tem runtime PHP gerenciado**; o Inspector **não** lista PHP entre os runtimes Lambda. PHP em Lambda só existe via custom runtime/container → quem escaneia é o Inspector na **imagem em ECR**, não o scan de runtime Lambda.
Fonte: [Amazon InspectorSupported OS and languages](https://docs.aws.amazon.com/inspector/latest/user/supported.html) ; [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

**Práticofiltrar achados pelas CVEs:**
```bash
# Achados do Inspector para as duas CVEs em toda a conta/região
aws inspector2 list-findings \
  --filter-criteria '{"vulnerabilityId":[
      {"comparison":"EQUALS","value":"CVE-2026-109618"},
      {"comparison":"EQUALS","value":"CVE-2026-109619"}]}' \
  --query 'findings[].{res:resources[0].id,sev:severity,pkg:packageVulnerabilityDetails.vulnerablePackages[0].name}' \
  --output table
```

**Práticoinventário de versão de PHP na frota (SSM Inventory / Run Command):**
```bash
# Coleta a versão de PHP servida/instalada em instâncias gerenciadas pelo SSM
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets '[{"Key":"tag:app","Values":["web-php"]}]' \
  --parameters 'commands=["php -v | head -1 || true","(php-fpm -v 2>/dev/null | head -1) || true"]' \
  --comment "inventario versao PHP - php2shell"
```

> **Recomendação de ferramenta Amazon Inspector**
> (a) **Recomendação:** scan contínuo multi-alvo (EC2/ECR/Lambda) com correlação automática de CVE e integração nativa com Security Hub; já reconhece PHP.
> (b) **Limita:** SO só repo padrão → **gap para PHP de repositório de terceiros**; exige SSM agent/role para EC2 agent-based; não "corrige", só acha; não enxerga a versão realmente *servida* por pool (vide Parte 1).
> (c) **Alternativa open-source:** **Trivy** ou **Grype** no pipeline de build e contra imagens/host (cobre pacotes de terceiros melhor em muitos casos); `syft` para SBOM.
> (d) **Para este contexto:** em frota AWS existente, Inspector é o de menor atrito para cobertura ampla; adicione **Trivy no CI** para fechar o gap de PHP de terceiros em imagens.

---

## 2. Reduzir a janela na borda (AWS WAF + CloudFront/ALB)

 Caminho de menor esforço: garantir o **AWS WAF PHP Managed Rule Group** na *default version* (atualizado para as duas CVEs)se você fixou versão, atualize; assine o SNS de Managed Rules.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

 Como complemento, regras custom de **forma de requisição** (alinhadas à orientação interina do PHP na Parte 1): limite de tamanho de corpo, rate-based, e opcionalmente bloqueio/throttle de `multipart/form-data`. Um estudo público com ALB implementou exatamente isso via CloudFormation (bloqueio de POST multipart por AndStatement método+content-type, rate-based por IP e por JA4, regra de país).
Fonte: [ClassmethodAWS WAF rules on ALB after the php2shell advisory](https://dev.classmethod.jp/en/articles/aws-waf-alb-block-multipart-post/).

 **Limitações honestas desse WAF** (do mesmo estudo): a regra de multipart **também bloqueia uploads legítimos** (apps com formulário de arquivo não podem usá-la); regras **rate-based deixam passar requisições antes de bloquear** (nos testes, de 23 a 52 POSTs passaram); o autor **não verificou proteção efetiva contra o php2shell** e reforça que a correção fundamental é **atualizar o PHP**.
Fonte: [Classmethod](https://dev.classmethod.jp/en/articles/aws-waf-alb-block-multipart-post/).

**Práticoregra de limite de tamanho de corpo (reduz a janela da 109618/OOM):**
```json
{
  "Name": "limit-body-size",
  "Priority": 10,
  "Action": { "Block": {} },
  "Statement": {
    "SizeConstraintStatement": {
      "FieldToMatch": { "Body": { "OversizeHandling": "MATCH" } },
      "ComparisonOperator": "GT",
      "Size": 1048576,
      "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
    }
  },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "limitBodySize" }
}
```
> Observação: o AWS WAF inspeciona por padrão só os primeiros ~8 KB do corpo (configurável conforme o tipo de associação); por isso `OversizeHandling` importa e por isso isto é *redução de janela*, não blindagem.

> **Recomendação de ferramenta AWS WAF Managed Rule Group**
> (a) **Recomendação:** atualizado e operado pela AWS, ativa proteção p/ vetores conhecidos com baixo esforço; integra com CloudFront/ALB/API GW e logging.
> (b) **Limita:** baseado em assinatura/vetores **conhecidos**falha de corrupção de memória não autenticada pode ter variações novas; regras custom de multipart/size podem **barrar tráfego legítimo**; rate-based **vaza** requisições. **Não corrige.**
> (c) **Alternativa open-source:** **ModSecurity + OWASP CRS** (no Nginx/Apache) com os limites de forma de requisição da Parte 1.
> (d) **Para este contexto:** se já está em CloudFront/ALB, habilite o managed group + limite de tamanho de corpo como *compra de tempo*, com WAF logging para o CloudWatch; trate como ponte até o patch.

---

## 3. Corrigir em escala, por tipo de compute

`[CONSENSO]` A correção muda conforme onde o PHP roda. A regra que vale para todos: **atualizar o binário e reiniciar o que serve** (workers longevos continuam com o binário antigo em memóriaexatamente o vetor da 109619).

### 3.1 EC2Systems Manager Patch Manager + Run Command

 Pacotes PHP atualizados estão disponíveis para **Amazon Linux** nas regiões comerciais.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

`[CONSENSO]` Fluxo típico com Patch Manager: *patch baseline* → *patch groups* por tag → *maintenance window* (ou on-demand) com operação `Scan` e depois `Install`. O **restart dos workers** você garante com Run Command logo após.

**Práticopatch on-demand + restart dos workers:**
```bash
# 1) instalar atualizações (inclui o PHP do repo padrão) via Patch Manager
aws ssm send-command \
  --document-name "AWS-RunPatchBaseline" \
  --parameters 'Operation=Install' \
  --targets '[{"Key":"tag:app","Values":["web-php"]}]'

# 2) reiniciar os workers para o binário novo entrar em uso
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets '[{"Key":"tag:app","Values":["web-php"]}]' \
  --parameters 'commands=[
     "systemctl restart php*-fpm 2>/dev/null || systemctl restart php-fpm 2>/dev/null || true",
     "systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || true",
     "php -v | head -1"]'
```

 **Cuidado com o gap de repositório:** o Inspector e o Patch Manager se apoiam no **repositório padrão (rpm/dpkg)**. PHP instalado via **Remi/ondrej/sury** pode não ser atualizado por `AWS-RunPatchBaseline` nem flagrado pelo Inspector como pacote de SOnesses hosts, atualize pelo mesmo repositório de onde veio o PHP.
Fonte: [Amazon InspectorSupported OS and languages](https://docs.aws.amazon.com/inspector/latest/user/supported.html).

### 3.2 Containers (ECS/EKS)reconstruir a imagem, não "patchar" o container

`[CONSENSO]` Containers **não** se corrigem em execução. O fluxo é: atualizar o PHP na **imagem base** → rebuild → push para **ECR** → **Inspector escaneia** a imagem → redeploy forçando nova task/pod. Tasks/pods em execução seguem vulneráveis até o redeploy.

**Práticoforçar novo deployment no ECS após imagem corrigida:**
```bash
aws ecs update-service --cluster prod --service web-php --force-new-deployment
```
> Em EKS: `kubectl rollout restart deployment/web-php` após a nova tag de imagem corrigida ser referenciada. Garanta `imagePullPolicy` que puxe a tag nova (evite `:latest` ambíguofixe digest).

### 3.3 Elastic Beanstalkatualizar a platform version

 A AWS liberou **novas platform versions para PHP 8.2–8.5**. Com **Managed Platform Updates** habilitado, chega na próxima janela de manutenção; senão, atualize a platform version do ambiente **manualmente**.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

### 3.4 Lambdarebuild + redeploy (não há runtime PHP gerenciado)

 Não existe runtime PHP gerenciado. Se você roda PHP via **custom runtime** (ex.: Bref/camada) ou **imagem de container**, **atualize o PHP e reimplante**.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

### 3.5 Lightsailcriar nova instância e migrar

 Blueprints atualizados em todas as regiões, mas a AWS **não atualiza instâncias em execução no lugar** → **crie nova instância a partir do blueprint atualizado e migre**.
Fonte: [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/).

> **Recomendação de ferramenta SSM Patch Manager**
> (a) **Recomendação:** patch em escala por tag, agendado em maintenance windows, com relatório de compliance; integra com Run Command para o restart.
> (b) **Limita:** depende do timing do advisory da distro e do **repo padrão** (gap de PHP de terceiros); **não** cobre containers nem Lambda; não reinicia workers sozinho.
> (c) **Alternativa:** **EC2 Image Builder** para gerar AMI dourada já corrigida (substituição imutável), **Ansible/config mgmt** para hosts com repositório de terceiros, e **rebuild no CI** para imagens de container.
> (d) **Para este contexto:** EC2 mutável → Patch Manager + Run Command; frota imutável/ASG → Image Builder + rotação de AMI; containers → CI rebuild + ECR + redeploy.

---

## 4. Detectar uso da janela (GuardDuty + CloudWatch Logs + Security Hub)

`[CONSENSO]` O **GuardDuty Runtime Monitoring** (EC2, ECS/Fargate, EKS) observa **execução de processo e atividade de rede** no host/container e gera achados para comportamento suspeito em runtimeé o equivalente gerenciado da regra "worker web gerou shell / conexão de saída" da Parte 1. O GuardDuty usa inteligência de ameaça da AWS; foi o **MadPot** (honeypot da AWS) que registrou a tentativa de 17/10 citada na Parte 1.

`[INCERTO]` **Nomes exatos de finding types** de Runtime Monitoring (ex.: execução suspeita, reverse shell, mineração) mudam e devem ser confirmados na documentação do GuardDuty antes de você escrever automações que dependem do nome do achado. Não cite o nome de memóriavalide no console/docs.

**Práticodetectar rajada de SIGSEGV/OOM no CloudWatch Logs Insights** (envie os logs de `php-fpm`/Apache via CloudWatch agent):
```sql
fields @timestamp, @message
| filter @message like /SIGSEGV|SIGABRT|Segmentation fault|Allowed memory size .* exhausted/
| stats count() as eventos by bin(5m)
| sort eventos desc
```
> Alerte sobre **padrão anômalo** (clusterização por 5 min), não evento isoladomesma lógica de baseline da Parte 1. Como os logs já estão no CloudWatch, você atende de graça o requisito da Parte 1 de **encaminhar logs para fora do host** (um atacante com permissão adultera log local).

`[CONSENSO]` **Agregar e responder:** mande achados de **Inspector + GuardDuty** para o **Security Hub**; dispare resposta com **EventBridge → SSM Automation** (ex.: isolar instância trocando o security group, snapshot do volume para forense, notificar via SNS). Isso materializa o "assuma que a janela esteve aberta" da Parte 1: após patch, procure `.php` novos/alterados, cron inesperado e conexões de saída do uid webagora com telemetria central.

> **Recomendação de ferramenta GuardDuty Runtime Monitoring**
> (a) **Recomendação:** visibilidade de processo/rede gerenciada, com threat intel da AWS (inclui MadPot), sem você manter regras; integra com Security Hub/EventBridge.
> (b) **Limita:** Runtime Monitoring exige **agente** (coverage varia por plataforma); achados são de **comportamento**, não específicos do php2shell; custo por volume.
> (c) **Alternativa open-source:** **Falco/Tracee/auditd** (Parte 1) encaminhando para um SIEM (OpenSearch), com as regras de árvore de processo você mesmo.
> (d) **Para este contexto:** AWS-nativo e pouca equipe → GuardDuty Runtime Monitoring; se já roda Falco no cluster, use-o como segundo sinal e reserve GuardDuty para a camada de conta/rede.

---

## Exemplo práticorunbook AWS end-to-end (em ordem)

Execute **em conta/VPC isolada de laboratório** antes de rodar em produção (sem IGW, sem dados reaismesma regra de ouro da Parte 1).

```
1. DESCOBRIR   aws inspector2 list-findings (filtra CVE-2026-109618/619)
               + SSM Run Command inventariando php -v / php-fpm -v por tag
               → lista de hosts/imagens/ambientes afetados, por tipo de compute

2. CONTER      WAF: PHP Managed Rule Group na default version (ou atualizar pin)
   (borda)     + regra limit-body-size (1 MB) + rate-based; WAF logging → CloudWatch
               → reduz janela; NÃO fecha

3. DETECTAR    GuardDuty Runtime Monitoring ligado nos alvos
               + Logs Insights alertando SIGSEGV/OOM anômalo
               → você passa a ver tentativa/crash

4. CORRIGIR    EC2: Patch Manager Install + Run Command restart workers
               ECS/EKS: rebuild imagem → ECR → Inspector → force-new-deployment
               Beanstalk: platform update   Lambda: redeploy   Lightsail: migrar
               → fecha a falha (binário novo + restart)

5. VERIFICAR   Inspector re-scan (achado some) + endpoint diag por pool (Parte 1)
               + varredura pós-comprometimento (Parte 1) → rotacionar segredos se houver IOC
```

---

## Armadilhas comuns nos cénarios (específicas de AWS)

1. **"O Inspector não acusou, logo estou limpo."** O scan de SO cobre só o **repo padrão**; PHP de **Remi/ondrej/sury** e *application streams* podem passar batido, e **containers/Lambda** são cobertos por caminhos diferentes (imagem em ECR, não runtime Lambda). *Evite:* cruze Inspector com **inventário de versão por pool** (Run Command) e com **Trivy no CI**.

2. **"Atualizei a AMI / a imagem base."** Mas as **tasks ECS/pods em execução** e os **workers FPM longevos** seguem com o binário antigo. *Reconhecer:* `php -v` do host novo diz corrigido, mas o endpoint servido ainda crasha/serve versão velha. *Evite:* **force-new-deployment**/rollout restart e **restart dos workers** (a 109619 vive justamente na reutilização de worker).

3. **Tratar o WAF Managed Rule Group como a correção.** É **controle compensatório**: assinatura cobre vetor conhecido, a regra de multipart **quebra uploads legítimos** e a rate-based **vaza** requisições. A própria AWS diz que **patch é a única correção completa**. *Evite:* WAF = ponte; patch + restart = fim.

4. **Supor atualização in-place onde não existe.** **Lightsail não atualiza instância em execução** (tem que migrar); **Beanstalk** precisa de **platform version** nova; **Lambda** precisa de **redeploy**. *Evite:* trate cada compute pelo seu caminho (seção 3).

---

---

## Recursos para aprofundar

**Fontes primárias AWS:**
- [AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)orientação por serviço, versões afetadas/corrigidas, WAF Managed Rule Group. **A referência canônica AWS** desta CVE; declara-se em evolução, então volte nela.
- [Amazon InspectorSupported OS and programming languages](https://docs.aws.amazon.com/inspector/latest/user/supported.html)confirma PHP suportado em EC2/ECR, ausência de runtime PHP em Lambda, e o limite de "repo padrão".
- **AWS WAF Managed Rules changelog** + tópico **SNS de Managed Rules** (citados no boletim)para saber quando a proteção da regra PHP entrou e versioná-la.

**Prático / alta autoridade (com limitações declaradas):**
- [ClassmethodWAF rules on ALB after php2shell](https://dev.classmethod.jp/en/articles/aws-waf-alb-block-multipart-post/)CloudFormation de WAF (multipart/rate/country) **com medições e limitações honestas**; o autor não comprova proteção e aponta patch como correção fundamental.

**Conecta com a Parte 1:**
- `extra-php2shell-cve-2026-109618-109619.md`causa raiz (OOM corruption / stale state), lab isolado, regra auditd/Falco, mitigações interinas de `php.ini`, verificação de patch por pool e varredura pós-comprometimento. Os controles AWS aqui **operacionalizam**, não substituem, aquele raciocínio de host.
