# Guia — PHP2Shell: RCE crítico no interpretador PHP (CVE-2026-109618 e CVE-2026-109619)

> Este guia foi montado a partir das divulgações de 21–23/10/2026. Vários detalhes ainda estavam mudando no momento da escrita (status de exploração, produtos downstream afetados.

---

## Objetivo

Entender, com base em fontes primárias e de alta autoridade:

1. **O que é** o PHP2Shell: a classe de bug, por que recebeu esse nome, e por que ele difere de um web shell clássico.
2. **Como simular com segurança**: montar um laboratório isolado para *validar detecção e proteção* sem escrever exploit, PoC ou web shell.
3. **Como proteger**: patching (a única mitigação completa), mitigações interinas, limites no proxy/WAF, e detecção no host.

> **Nota: este guia não traz exploit.**
> PHP2Shell é uma falha de *memory safety* no interpretador C do PHP. Não existe caminho legítimo de aprendizado defensivo que exija reproduzir o exploit, e um PoC de corrupção de memória é exatamente o tipo de artefato que dá vantagem ofensiva real a um atacante. Então aqui a parte de "simular" é construída em torno de: (a) um lab isolado com PHP deliberadamente desatualizado para estudar a *telemetria de crash*, (b) o scanner open-source público para medir exposição, e (c) a validação das suas próprias regras de detecção com gatilhos benignos. Em nenhum momento o guia fornece código de exploração. Essa escolha é parte do conteúdo: defensor pensa em *contenção e detecção*, não em reproduzir a arma.

---

## Contexto

Em 21/10/2026, o time do PHP publicou correções emergenciais para **duas** vulnerabilidades críticas de execução remota de código (RCE) no PHP, divulgadas em conjunto sob o apelido **"PHP2Shell"**: **CVE-2026-109618** e **CVE-2026-109619**. As correções vieram acompanhadas de advisories oficiais no GitHub (`GHSA-w8hw-w9fx-j79w` e `GHSA-6wmf-4rv5-p3rp`).
Fonte: [Help Net Security "PHP2Shell: PHP vulnerabilities patched"](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) ; [BleepingComputer "PHP ships emergency patches for critical PHP2Shell flaws"](https://bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws).

A Amazon Threat Intelligence relatou que seu honeypot **MadPot** registrou uma tentativa de exploração em **17/10/2026 quatro dias antes da divulgação pública**, indicando que algum ator já tinha detalhes da falha durante o embargo. O IP de origem estava ligado a um serviço comercial de anonimização.
Fonte: Help Net Security (acima).

Vários fornecedores descreveram o impacto como "70% da internet" / "quase metade da web". Isso é **enquadramento de marketing de fornecedor**, não um número verificável PHP é onipresente, mas a fração realmente *explorável* depende de SAPI, configuração e versão. Trate como ordem de grandeza, não como fato.
Fonte (exemplos do enquadramento): [Wiz CVE-2026-109618](https://www.wiz.io/vulnerability-database/cve/cve-2026-109618) ; [Dark Reading](https://www.darkreading.com/application-security/php2shell-bugs-red-alert-security-industry).

**Por que importa aprender agora:** diferente da maioria dos bugs de aplicação PHP (SQLi, upload de arquivo, `eval` de input), estas falhas estão **no motor**, são **não autenticadas** e disparam **antes de qualquer código da sua aplicação rodar**. Isso inverte várias suposições de defesa de camada de aplicação.

---

## Conceitos principais

### 1. O que é "PHP2Shell" (e por que o nome engana)

"PHP2Shell" é um **apelido de divulgação** para o par de CVEs, não um nome de produto nem de malware. O "2Shell" descreve o *resultado* levar à execução de código ("shell") não o mecanismo.

A confusão comum é tratar PHP2Shell como um "web shell" clássico. São coisas diferentes:

```
WEB SHELL CLÁSSICO (ex.: c99, b374k)          PHP2SHELL (CVE-2026-109618/619)
──────────────────────────────────           ───────────────────────────────
O atacante consegue GRAVAR/INJETAR            O atacante envia UMA requisição
um arquivo .php malicioso (via upload,        HTTP criada que corrompe a
LFI, config errada) e depois o acessa.        memória do próprio interpretador.

Bug de APLICAÇÃO / configuração.              Bug de MEMORY SAFETY no motor C.
Corrige-se no código/app/permissões.          Corrige-se SÓ atualizando o PHP.
WAF e sanitização de input ajudam muito.      WAF só reduz exposição; não corrige.
```

A implicação prática dessa distinção é o conceito mais importante da sessão: **não há "sanitize seu input" que resolva PHP2Shell.** A correção é no binário do interpretador.

### 2. CVE-2026-109618 RCE por corrupção em condição de *out-of-memory* (OOM)

A causa raiz divulgada publicamente: uma condição de **falta de memória (OOM)** pode **interromper o PHP enquanto estruturas internas da requisição estão apenas parcialmente inicializadas**. A rotina de limpeza (cleanup) da requisição pode então **tratar esses dados inválidos/parciais como se fossem válidos**, levando a corrupção de memória e, a partir dela, a um caminho de execução de código.
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619).

```
Fluxo normal de uma requisição no PHP:
  [chegada] → aloca estado interno → inicializa (passos 1..N) → processa → cleanup (libera tudo)

Fluxo sob OOM no meio da inicialização:
  [chegada] → aloca estado interno → inicializa (passos 1..K) ──✗ OOM──┐
                                                                       │
                           estado PARCIAL: passos K+1..N nunca rodaram │
                                                                       ▼
  cleanup roda ASSUMINDO estado COMPLETO → opera sobre lixo como se fosse válido
                                         → corrupção de memória → execução
```

O **caminho de código vulnerável exato e a classificação CWE completa não foram totalmente divulgados** publicamente no momento da escrita uma decisão deliberada para retardar a weaponização. A Wiz afirma isso explicitamente.
Fonte: [Wiz CVE-2026-109618](https://www.wiz.io/vulnerability-database/cve/cve-2026-109618).

### 3. CVE-2026-109619 RCE por estado global "velho" (stale) entre requisições

 A causa raiz divulgada: um **estado interno pertencente a uma requisição pode persistir depois que a memória que o respaldava já foi liberada**. Uma requisição *posterior*, atendida pelo **mesmo worker**, pode usar esse estado "velho" **antes** de a inicialização normal reiniciá-lo. É um padrão da família *use-after-free* / ponteiro pendente exposto através da reutilização de workers.
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619).

```
Worker de PHP-FPM / mod_php = processo LONGEVO que atende muitas requisições:

  Request A  ─ cria estado X (da requisição) ─ ... ─ memória de X é LIBERADA no fim
                                                       │
                                 mas um ponteiro/estado global ainda referencia X
                                                       │
  Request B  ─ (MESMO worker) usa X "velho" ANTES da reinicialização ─→ use-after-free ─→ execução
```

É por isso que **reutilização de worker** importa tanto aqui: em FPM e mod_php os processos são longevos e servem milhares de requisições; isso cria a janela de contaminação cruzada entre requisições que a 109619 explora.

### 4. Superfície de ataque: por que "afeta todo mundo"

As falhas afetam o PHP servindo requisições web em praticamente todas as SAPIs: **PHP-FPM, Apache com mod_php, php-cgi, FrankenPHP e LiteSpeed**. Configurações com **mod_php correm o maior risco** (o interpretador roda dentro do próprio processo do Apache, no mesmo espaço de endereçamento e frequentemente com mais privilégio).
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) ; [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

O impacto se estende a **produtos que embarcam PHP**. Até 22/10/2026 a **Palo Alto Networks confirmou que todas as versões de PAN-OS e Panorama são afetadas** e ainda não tinha liberado correção; Fortinet e Cisco publicaram advisories mas ainda investigavam seus produtos.
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619).

Características que anulam defesas de camada de aplicação: o ataque é **não autenticado** e **uma única requisição** basta; no caminho confirmado via mod_php ele pode **rodar antes do código da aplicação**, de modo que **os logs da aplicação podem não registrar nada**.
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

**CVSS:** a Wiz reporta **9.2 (score do CNA), "Crítico"**, mas observa que rótulos de severidade variam entre fornecedores (de HIGH a LOW em alguns feeds). Confirme no advisory oficial / NVD.
Fonte: [Wiz — CVE-2026-109618](https://www.wiz.io/vulnerability-database/cve/cve-2026-109618).

**Existe PoC público/weaponizado?** As fontes se **contradizem**: Help Net Security fala em "exploit funcional já existe"; a Wiz diz no corpo do texto que não havia PoC público confirmado na divulgação, enquanto os metadados da mesma página marcam "Has Public Exploit: Yes". Trate como *provavelmente sim, em círculos restritos*, e assuma que a janela está aberta.
Fontes: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) ; [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-109618).

### 5. A classe de bug: memory safety no motor (a lição que generaliza)

As duas CVEs são bugs de **segurança de memória em código C** (corrupção induzida por OOM; estado stale / use-after-free). Isso tem três consequências que você deve internalizar como defensor:

- **Não é CWE-78 (command injection).** Não há input de aplicação a "escapar". A mentalidade de "validar entrada" não se aplica ao motor.
- **A única correção completa é trocar o binário do interpretador.** Mitigações de borda apenas estreitam a janela.
- **A detecção precisa olhar o host, não só o HTTP.** Como o payload pode rodar antes/fora da aplicação, os sinais confiáveis são crashes do interpretador e comportamento anômalo de processo — não assinaturas de URL.

---

## Exemplo prático — Laboratório isolado de detecção e validação de defesas

O objetivo deste lab **não** é explorar a falha. É responder três perguntas defensivas:

1. Minha instrumentação **vê** um crash/OOM fora da normalidade do interpretador?
2. Minhas regras disparam quando um worker web gera um processo filho suspeito?
3. Eu consigo **confirmar a versão realmente servida** (não só a do CLI) e verificar o patch?

### 0. Regra de ouro do lab

Isole de verdade: rede Docker **interna** (sem egress), snapshot/descartável, sem dados reais, sem credenciais reais. Nada de rodar isto num host que também serve produção.

### 1. Ambiente descartável (PHP deliberadamente desatualizado, SÓ para telemetria de crash)

```yaml
# docker-compose.yml  — lab isolado; rede sem saída para a internet
# Uso: estudar LOGS de crash/OOM e validar DETECÇÃO.
services:
  web:
    # Imagem antiga de propósito, para o worker poder registrar crash/OOM.
    image: php:8.2.10-fpm      # < 8.2.35 (anterior ao patch) — apenas para o lab
    networks: [labnet]
    volumes:
      - ./app:/var/www/html:ro
      - ./php-lab.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro
    # sem 'ports:' -> não publica nada no host

  proxy:
    image: nginx:1.27-alpine
    networks: [labnet]
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "127.0.0.1:8080:80"

networks:
  labnet:
    internal: true
```

### 2. Gerar telemetria de crash/OOM **benigna** (sem exploit) para calibrar alertas

Os sinais de detecção mais citados são **rajadas de SIGSEGV/SIGABRT** nos logs de `php-fpm`/Apache e **OOMs** do tipo `Allowed memory size ... exhausted`. Você pode produzir esses sinais de forma totalmente benigna, só para ver se seu pipeline os captura:

```php
<?php // oom-benigno.php — NÃO é exploit: só estoura o memory_limit de propósito
//     para gerar a linha de log de OOM que você quer aprender a alertar.
ini_set('memory_limit', '32M');
$buf = [];
while (true) { $buf[] = str_repeat('x', 1024 * 1024); } // aloca até o limite
```

```bash
# dispara o OOM benigno e observa o log do worker
docker compose exec web php /var/www/html/oom-benigno.php 2>&1 | tail -n 3
# Esperado: "Fatal error: Allowed memory size of 33554432 bytes exhausted ..."
```

Faça **baseline antes**: muitos crashes/OOMs são legítimos (picos de tráfego, libs pesadas como `imagick`/`gs`). O valor do alerta está no *padrão anômalo* (clusterizado em requisições específicas), não no evento isolado.

### 3. Validar a regra de "processo filho suspeito a partir de worker web"

 Telemetria de processo recomendada: **alertar quando um worker web** (`php-fpm`, `php-cgi`, `httpd`/`apache2` com mod_php, `lsphp`, `frankenphp`) **gera** shells (`sh`, `bash`, `cmd.exe`, `powershell.exe`), interpretadores (`python`, `perl`, `ruby`), ferramentas de rede (`curl`, `wget`, `nc`, `ncat`, `socat`, `certutil.exe`) ou recon (`whoami`, `id`, `uname`, `hostname`). Atenção a strings de reverse shell (`/dev/tcp/`, `mkfifo`, `bash -i`, `nc -e`, `base64 -d | sh`).
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

Regra **auditd** (Linux) escopada ao usuário do servidor web (`euid=33` = `www-data` em Debian/Ubuntu; ajuste ao seu ambiente):

```
# /etc/audit/rules.d/php-exec.rules
-a always,exit -F arch=b64 -S execve -F euid=33 -k php_exec
```

```bash
sudo augenrules --load
# depois, teste BENIGNO: simule um "filho" legítimo saindo do contexto web
# para confirmar que a regra captura — sem nenhum exploit envolvido:
sudo -u www-data id            # deve gerar um evento com a key php_exec
ausearch -k php_exec -i | tail
```

> **Recomendação de ferramentas (contrato §4).**
> - **auditd** (open-source, nativo): **faz bem** captura de `execve` por usuário/arch com baixo custo; **limita** porque é por-host, regras verbosas e correlação/alerta ficam a cargo de um SIEM externo. **Alternativa open-source:** **Falco** ou **Tracee** (eBPF) dão regras de árvore de processo mais ricas e context de container; **Sysmon for Linux** (Microsoft, gratuito) é outra opção. No Windows, **Sysmon Event ID 1** filtrando por `ParentImage`. **Para este contexto** (frota mista Linux + apps containerizados) a dupla **auditd para a regra mínima + Falco para árvore de processo** cobre bem; se você já tem um EDR comercial que faz process-tree, use-o e trate o acima como validação/segundo sinal.

### 4. Medir exposição com scanner público (não é exploit)

A Searchlight Cyber liberou um scanner open-source, **`php2shell-scanner`**, para testar exposição.
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619).

> **Recomendação de ferramentas (contrato §4).**
> - **php2shell-scanner (Searchlight, open-source):** **faz bem** checar rapidamente se um alvo *parece* vulnerável (fingerprint de versão/SAPI) sem explorar; **limita** porque scanner de versão pode dar falso-positivo/negativo (backports de distro reportam versões "antigas" já corrigidas) e só vê o que está exposto na borda. **Alternativas:** scanners de SCA/host como **Trivy** ou **Grype** (open-source) cruzando a versão instalada com o advisory; feeds comerciais (Wiz, Qualys, Tenable) para frota grande. **`[INCERTO]` — valide a ferramenta você mesmo** (leia o código, rode no lab isolado) antes de confiar no veredito; é um projeto muito recente.
> - **Simulação adversária controlada:** a Picus Threat Library traz o threat ID **60730 "PHP Php2Shell RCE Campaign"** (módulo Web Application), que testa se o ataque *alcança* seus ativos PHP e se os controles sinalizam — útil em quem já é cliente Picus; a alternativa open-source é construir o caso no lab acima + o scanner. Fonte: [Picus](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

### 5. Verificar o patch do jeito certo (o `php -v` do CLI engana)

Checar só a versão do CLI é **insuficiente**: o binário que serve o site (pool do PHP-FPM, módulo do Apache) pode ser diferente do PHP da linha de comando. Verifique **o runtime que de fato atende cada site**, via um endpoint de diagnóstico protegido.
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

```php
<?php // diag-version.php — proteja por IP/allowlist/auth; remova após o rollout
header('Content-Type: text/plain');
echo 'runtime=' . PHP_VERSION . PHP_EOL;     // versão REAL servindo este pool
echo 'sapi='    . PHP_SAPI    . PHP_EOL;      // fpm-fcgi, apache2handler, cli-server...
```

```bash
# compare: o que o CLI diz  x  o que o pool realmente serve
php -v | head -1
curl -s http://127.0.0.1:8080/diag-version.php
```

Versões **corrigidas** (veja seção de Proteção): 8.5.12, 8.4.27, 8.3.36, 8.2.35 (ou o pacote corrigido da sua distro / backport para 7.4/8.0/8.1).
---

## Como proteger (em ordem de prioridade)

### A. Atualizar a única mitigação completa

O time do PHP é explícito: **atualizar é a única mitigação completa.** Versões corrigidas:

```
╔══════════════╦════════════════════════════════════════════════════════╗
║ Branch       ║ Versão corrigida                                         ║
╠══════════════╬════════════════════════════════════════════════════════╣
║ PHP 8.5      ║ 8.5.12                                                   ║
║ PHP 8.4      ║ 8.4.27                                                   ║
║ PHP 8.3      ║ 8.3.36                                                   ║
║ PHP 8.2      ║ 8.2.35                                                   ║
║ 7.4/8.0/8.1  ║ backports mínimos de código-fonte (branches fora de      ║
║              ║ suporte oficial) ou upgrade para branch suportada      ║
╚══════════════╩════════════════════════════════════════════════════════╝
```
Distribuições Linux e fornecedores LTS receberam patch antes da liberação pública; prefira o **pacote corrigido da sua distro** quando existir (o número de versão do pacote pode diferir do upstream por causa de backport confie no changelog do fornecedor, não no número "nu").
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) ; [BleepingComputer](https://bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws).

Após atualizar, **reinicie os workers** (PHP-FPM, Apache) processos longevos continuam rodando o binário antigo em memória até o restart.

### B. Para o que não dá pra corrigir já (appliances, PAN-OS etc.)

A orientação do **NCSC (Reino Unido)** foi **tirar de produção** qualquer sistema que não possa ser corrigido imediatamente. Para appliances afetados sem patch (ex.: PAN-OS no momento da escrita), restrinja exposição de rede ao mínimo e monitore.
Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619).

### C. Mitigações interinas (reduzem exposição NÃO corrigem)

Enquanto o patch não chega, as seguintes configurações **reduzem** a exposição; devem ser revertidas depois quando causarem dano:

```ini
; php-lab.ini / php.ini mitigação INTERINA, não substitui o patch
memory_limit = -1                      ; reduz a janela da 109618 (OOM) ...
                                       ; ATENÇÃO: -1 = risco de DoS por exaustão de memória
post_max_size = 1M                     ; corpo pequeno dificulta gatilhos de request
session.upload_progress.enabled = 0    ; desliga vetor de upload-progress
fatal_error_backtraces = 0             ; (apenas PHP 8.5)
```

Há um **advisory de acompanhamento de 23/10/2026, CVE-2026-115560**, que afeta uma **configuração estreita**; a mitigação recomendada é `session.upload_progress.enabled=0` e **ainda não havia patch** no momento da escrita.
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

Observe o *trade-off*: `memory_limit=-1` troca um risco de RCE por um risco de DoS. Em frota, prefira patch + restart a depender de interino.

### D. Limites de forma de requisição no proxy/WAF

A orientação interina do PHP mapeia para limites que você pode impor **no proxy**, mantidos **mesmo após o patch** (defesa em profundidade): tamanho de requisição decodificada, contagem de campos, número de partes multipart, headers por parte e profundidade de aninhamento. Indicadores de *forma* suspeita de requisição: corpos POST/multipart enormes ou profundamente aninhados, milhares de campos/partes, requisições *chunked* sem `Content-Length`, e `PHP_SESSION_UPLOAD_PROGRESS` enviado a endpoints que nunca o usam.
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

```nginx
# nginx.conf (trecho) limites de forma de requisição; mantenha após o patch
http {
  client_max_body_size      1m;    # teto de corpo
  client_body_buffer_size   16k;
  large_client_header_buffers 4 8k;
  # rejeite métodos/ível de aninhamento fora do esperado na borda, conforme sua app
}
```

> **Recomendação de ferramentas (contrato §4).**
> - **WAF:** a **Cloudflare** publicou regras para vetores conhecidos, disponíveis a todos os clientes; a **Check Point NGX** traz a assinatura `asm_dynamic_prop_CVE_2026_109618` ("PHP Remote Code Execution"). **Fazem bem** barrar tentativas conhecidas e dar visibilidade; **limitam** porque assinatura cobre vetores *conhecidos* como a falha é de corrupção de memória não autenticada, variações novas podem passar, então **WAF não substitui patch**. **Alternativa open-source:** **ModSecurity + OWASP CRS** com limites de forma de requisição (acima). **Para este contexto:** use o WAF que você já opera para ganhar tempo, com os limites de forma no proxy como rede independente; trate ambos como *redução de janela*, não correção. Fonte: [Help Net Security](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) ; [Picus](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

### E. Detecção e resposta (assuma que a janela esteve aberta)

Como houve exploração desde **17/10** (antes da divulgação), após corrigir **assuma comprometimento possível** e procure: arquivos `.php` novos/modificados em web roots e diretórios de upload, cron jobs inesperados, processos/usuários desconhecidos, e **conexões de saída a partir do usuário do web server**. Se algo estiver errado, **rotacione todo segredo que o usuário web podia ler**. Encaminhe logs para fora do host (um atacante com permissão pode adulterar logs locais). Lembre: um payload em código nativo pode abrir um socket **sem** spawnar shell então monitore conexão de saída, não só criação de processo.
Fonte: [Picus Security](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained).

```bash
# varredura pós-patch (rode a partir de inventário conhecido-bom, com cautela)
find /var/www -name '*.php' -mtime -14 -printf '%TY-%Tm-%Td %p\n' | sort   # .php recentes
sudo -u www-data crontab -l 2>/dev/null                                     # cron do usuário web
ss -tunp | grep -Ei 'www-data|php-fpm|apache|nginx' || true                 # conexões do web uid
```

---

## Armadilhas comuns nos cénarios

1. **"Rodei `apt upgrade php`, então estou seguro."**
   *Por que acontece:* confunde-se a versão do CLI com a versão que serve o site. *Como reconhecer:* `php -v` mostra corrigido, mas o pool do FPM / mod_php / um appliance embarcando PHP continua antigo, e os workers não foram reiniciados. *Como evitar:* verifique o **runtime por pool** (endpoint de diagnóstico da seção prática), reinicie FPM/Apache, e inventarie PHP embarcado em appliances (PAN-OS etc.).

2. **Tratar como injeção de aplicação e confiar em sanitização/WAF.**
   *Por que acontece:* a maioria dos bugs PHP que a gente vê no dia a dia é de camada de aplicação. *Como reconhecer:* o plano de resposta fala em "validar input", "regra de WAF" como *correção*. *Como evitar:* internalize que é *memory safety no motor*: WAF e limites de borda só **reduzem a janela**; a correção é o binário. A detecção confiável é no **host** (crash/OOM anômalo, árvore de processo, saída de rede), não na URL.

3. **Ligar mitigação interina e esquecer o trade-off / o rollback.**
   *Por que acontece:* `memory_limit=-1` "resolve" o sinal de OOM e fica. *Como reconhecer:* meses depois o interino ainda está lá, agora virou vetor de DoS por exaustão de memória; ou alguém acha que o interino = corrigido. *Como evitar:* trate interino como *ponte* com data de validade, documente, e reverta após o patch + restart.

---

## Recursos para aprofundar

**Fontes primárias (confirme aqui antes de decidir operação):**
- **Advisories oficiais do PHP no GitHub:** `GHSA-w8hw-w9fx-j79w` e `GHSA-6wmf-4rv5-p3rp`. `[INCERTO]` a URL direta do GitHub Security Advisory não estava acessível pela ferramenta de fetch desta sessão; abra manualmente em `github.com/php/php-src/security/advisories/` e nos release notes de 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. É a referência canônica de causa raiz e versões.
- **NVD / CVE:** CVE-2026-109618 e CVE-2026-109619 (para CVSS oficial e CWE quando publicados).

**Alta autoridade (jornalismo técnico e pesquisa de fornecedor):**
- [Help Net Security patch, timeline, causa raiz das duas CVEs](https://helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619) melhor visão geral de causa raiz (OOM corruption / stale state), versões corrigidas, MadPot, produtos downstream.
- [BleepingComputer "PHP ships emergency patches for critical PHP2Shell flaws"](https://bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws) resumo de patch e cronologia.
- [Picus Security detecção, logging, limites de forma de requisição, teste de exposição](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained) a melhor fonte **defensiva**: indicadores de log, regra auditd, telemetria de processo, mitigações interinas, avaliação pós-patch.
- [Wiz CVE-2026-109618 (vuln DB)](https://www.wiz.io/vulnerability-database/cve/cve-2026-109618) CVSS 9.2, status de exploração, tabela por distro. **Atenção:** a própria página sinaliza inconsistências internas (foi gerada por IA); use só para orientação, confirme no advisório.
- [Dark Reading "'PHP2Shell' Bugs Signal Red Alert"](https://www.darkreading.com/application-security/php2shell-bugs-red-alert-security-industry) contexto de indústria e reação.

**Ferramenta de exposição (valide você mesmo antes de confiar):**
- `php2shell-scanner` (Searchlight Cyber, open-source) scanner de exposição citado por Help Net Security; `[INCERTO]` confirme o repositório oficial e leia o código antes de usar.
