# ASPM com IA — Tomahawks

Implementação prática da arquitetura apresentada no Challenge Pride 2026:
**Descoberta → Coleta → Correlação → Priorização com IA → Remediação → Dashboard**

> ### ⚠️ Aviso
>
> A pasta **`demo_app/` contém vulnerabilidades propositais** (SQL Injection,
> XSS refletido, entre outras). Ela existe para dar aos scanners algo real
> para encontrar.
>
> **Não faça deploy desta aplicação, não a exponha na internet e não
> reaproveite esse código em produção.**

## 1. O que cada arquivo faz

```
aspm_ia/
├── scanners/
│   ├── bandit_scanner.py    # SAST gratuito (código Python)
│   ├── trivy_scanner.py     # SCA gratuito (dependências/containers)
│   ├── dast_scanner.py      # DAST gratuito (OWASP ZAP, ataca app rodando)
│   └── nvd_lookup.py        # Enriquecimento com CVSS oficial (NVD, gratuito)
├── agents/
│   ├── risk_agent.py         # Pontua e prioriza (0-100)
│   ├── explanation_agent.py  # Explica em linguagem natural
│   └── remediation_agent.py  # Sugere correção técnica
├── integrations/
│   ├── wazuh_forwarder.py    # Envia achados como alertas ao Wazuh SIEM
│   ├── wazuh_rules.xml       # Regras a colar no Manager do Wazuh
│   └── defectdojo_client.py  # Import/leitura/anotação de Findings no DefectDojo
├── demo_app/app.py            # App propositalmente vulnerável (alvo do DAST)
├── normalizer.py              # Unifica formatos diferentes num schema só
├── orchestrator.py            # Amarra tudo (é o que você roda)
├── dashboard.py                # Interface Streamlit
├── verificar_chave.py          # Testa a chave de IA isoladamente
└── sample_data/                # Dados de teste (não precisa scanner instalado)
```

## 2. Instalação (tudo gratuito)

```bash
# 1. Crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Instale as dependências Python
pip install -r requirements.txt

# 3. (Opcional, mas recomendado) instale o Trivy
# Linux/Mac:
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
# Windows: choco install trivy
```

Bandit já vem no `requirements.txt` (é uma lib Python pura).

## 3. Configure a chave da IA (opção gratuita)

O projeto usa o **Google Gemini** por padrão — tem nível gratuito real, sem
cartão de crédito.

```bash
cp .env.example .env
```

1. Acesse **https://aistudio.google.com/apikey**
2. Faça login com uma conta Google
3. Clique em **"Create API key"**
4. Copie a chave e cole no `.env`:

```
AI_PROVIDER=gemini
GEMINI_API_KEY=sua-chave-aqui
```

Limites do nível gratuito (mais que suficiente para o volume de achados
do projeto): poucas dezenas de requisições por minuto e centenas por dia,
dependendo do modelo. Se um dia vocês quiserem usar a API paga da Anthropic
em vez disso, é só trocar `AI_PROVIDER=anthropic` e preencher
`ANTHROPIC_API_KEY` — o resto do código não muda nada, a troca de motor
de IA é transparente para os 3 agentes.

## 4. Teste rápido, sem precisar escanear nada ainda

```bash
python orchestrator.py --demo
streamlit run dashboard.py
```

Isso roda os 3 agentes de IA sobre os 4 achados de exemplo (os mesmos da
tabela do slide 5 da apresentação) e abre o dashboard no navegador.

## 5. Rodando em um projeto real

```bash
python orchestrator.py --path /caminho/do/seu/projeto --exposto-internet --dados-sensiveis
streamlit run dashboard.py
```

As flags `--exposto-internet` e `--dados-sensiveis` alimentam o contexto
que o Risk Agent usa para ajustar o score além do CVSS puro — é a parte
que diferencia ASPM de "só rodar um scanner".

## 6. Quer rodar 100% offline, sem nenhuma API externa?

O padrão do projeto (Gemini) já é gratuito, mas se quiser rodar sem
depender de internet para os agentes de IA, dá pra usar um modelo local:

**Ollama (roda inteiramente na sua máquina):**
1. Instale o Ollama (ollama.com) e baixe um modelo, ex: `ollama pull llama3.1`
2. Adicione um novo bloco `elif PROVIDER == "ollama":` em
   `agents/base_agent.py`, chamando `http://localhost:11434/api/chat` — a
   estrutura dos agentes (prompts, parsing de JSON) continua idêntica, só
   muda o método `_call_ia`.

Repare que essa é uma opção adicional para quem quer zero dependência de
internet — o Gemini gratuito já resolve o requisito de custo.

O resto do pipeline (Bandit, Trivy, NVD, normalizador, dashboard) já é
gratuito e não muda nada.

## 6.1 Rodando o DAST (OWASP ZAP)

O DAST é diferente dos outros dois: ele ataca uma **aplicação rodando de verdade**,
não só lê arquivos. Passos:

```bash
# Terminal 1: suba a app vulnerável de demonstração
pip install flask
python demo_app/app.py
# acesse http://localhost:5000 para confirmar que subiu

# Terminal 2: baixe e inicie o OWASP ZAP em modo daemon
# (baixe em https://www.zaproxy.org/download/)
zap.sh -daemon -port 8080 -config api.disablekey=true

# Terminal 3: rode o orquestrador completo, incluindo DAST
pip install python-owasp-zap-v2.4
python orchestrator.py --demo --dast-url http://localhost:5000
# (troque --demo pelo --path do seu código quando for escanear um projeto real)
```

O ZAP vai literalmente enviar payloads de ataque (ex: `<script>alert(1)</script>`
no formulário de contato) contra a app rodando e reportar o que conseguiu
explorar — isso é a diferença central para SAST/SCA, que nunca executam nada.

## 7. Roteiro sugerido para a apresentação (live demo)

Ordem que conta a história completa do ASPM na prática, ~8-10 min:

1. **(1 min) Contexto:** relembre o problema (slide 2) — alertas espalhados,
   sem correlação, sem priorização.
2. **(1 min) Mostre a app vulnerável rodando** (`demo_app/app.py`) e explique
   rapidamente as 2-3 falhas propositais no código.
3. **(2 min) Explique as 3 fontes de dado, com uma frase de diferença cada:**
   - *SAST (Bandit)* — "lê o código sem executar, acha falhas de lógica"
   - *SCA (Trivy)* — "compara nossas bibliotecas com bases de CVE conhecidas"
   - *DAST (OWASP ZAP)* — "ataca a aplicação rodando, como um invasor real faria"
4. **(2-3 min) Rode o `orchestrator.py --dast-url ...` ao vivo**, mostrando no
   terminal os 4 passos (Descoberta → Scanners → Normalização → Agentes de IA).
5. **(2 min) Abra o dashboard** (`streamlit run dashboard.py`) e mostre a fila
   já priorizada, com a explicação e remediação geradas pela IA para o item
   crítico.
6. **(1 min) Feche com o roadmap** (slide 8: FastAPI, mais scanners, etc.)

Dica: se o ZAP demorar demais ao vivo (scan ativo pode levar minutos), rode
antes da apresentação e tenha o `resultado.json` pronto como plano B —
mostre o comando rodando por alguns segundos pra dar credibilidade e depois
troque para o resultado já pronto, sendo transparente sobre isso se perguntarem.

## 8. Próximos passos sugeridos (alinhados com o slide 8)

1. Empacotar o `orchestrator.py` como API FastAPI (endpoint `/scan`)
2. Adicionar Semgrep e OWASP ZAP como novas fontes no normalizador
3. Persistir o histórico de scans (SQLite é suficiente para o MVP)
4. Adicionar autenticação por API key no dashboard/API

## 9. Integração com DefectDojo (ingestão/dedup profissional, opcional)

O DefectDojo é o projeto flagship da OWASP pra gestão de vulnerabilidades.
Com a flag `--defectdojo`, ele substitui nosso `normalizer.py` na parte de
ingestão e deduplicação — os scanners continuam sendo os mesmos (Bandit,
Trivy, ZAP), só que o parsing/dedup passa a ser feito pelo DefectDojo, e
nossos 3 Agentes de IA continuam fazendo a parte que ele não faz: pontuar
com contexto, explicar e sugerir remediação. O resultado da IA volta pro
DefectDojo como nota + tag em cada achado.

**Isso é opcional** — sem a flag `--defectdojo`, tudo continua funcionando
exatamente como antes, com nosso normalizer próprio.

### Passo 1 — Instalar Docker (se ainda não tiver)

```bash
sudo apt install ca-certificates curl gnupg -y
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo usermod -aG docker $USER
```
Feche e abra o terminal de novo (pra aplicar o grupo `docker`).

### Passo 2 — Instalar e subir o DefectDojo

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git ~/DefectDojo
cd ~/DefectDojo
docker compose build
docker compose up -d
```
A primeira subida demora (o "initializer" pode levar até 3 min). Pra ver
a senha de admin gerada automaticamente:
```bash
docker compose logs initializer | grep "Admin password:"
```
Acesse **http://localhost:8080**, login `admin` + a senha acima.

### Passo 3 — Gerar o token de API

No DefectDojo, clique no seu usuário (canto superior direito) > **API v2
Key**, copie o token.

### Passo 4 — Configurar o `.env`

```
DEFECTDOJO_URL=http://localhost:8080/api/v2
DEFECTDOJO_API_TOKEN=cole-o-token-aqui
DEFECTDOJO_PRODUCT_NAME=ASPM com IA - Tomahawks
```

### Passo 5 — Rodar com a integração ativa

```bash
python orchestrator.py --path /caminho/do/codigo --dast-url http://localhost:5000 --defectdojo
```

Depois, no painel do DefectDojo (**Products > ASPM com IA - Tomahawks**),
confira os Findings importados — cada um com nossa nota de IA (score,
explicação, remediação) e uma tag `ia-critica`/`ia-alta`/etc.

## 10. Integração com Wazuh (SIEM)

Isso conecta os achados priorizados ao seu Wazuh, fazendo-os aparecerem
como **alertas reais** no painel — não só na tabela do Streamlit.

**Como funciona:** o `orchestrator.py`, com a flag `--wazuh`, escreve os
achados (score >= 40) como eventos JSON em `~/aspm_wazuh_alerts.json`. O
Agente do Wazuh (rodando nesta máquina) monitora esse arquivo e envia pro
Manager, que usa regras customizadas para classificar por prioridade.

### Passo 0 — Confirme se o Agente já está instalado nesta máquina

Como o Manager/Dashboard do Wazuh está numa VM separada, esta máquina
Debian provavelmente ainda não tem o Agente. Confira:

```bash
sudo systemctl status wazuh-agent
```

Se aparecer `Unit wazuh-agent.service could not be found`, precisa
instalar (Passo 1). Se já existir e estiver rodando, pule pro Passo 1b.

### Passo 1 — Instalar e enrolar o Agente nesta máquina (aponta pro Manager remoto)

```bash
sudo apt-get install gnupg apt-transport-https -y
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

# Troque pelo IP real da VM do Wazuh Manager
WAZUH_MANAGER="IP_DA_VM_WAZUH" sudo -E apt-get install wazuh-agent -y

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Confirme que conectou:
```bash
sudo tail -20 /var/ossec/logs/ossec.log
```
Procure por uma linha `Connected to the manager`. Se não aparecer,
normalmente é rede: confirme que dá `ping IP_DA_VM_WAZUH` desta máquina, e
que as portas **1514** e **1515** estão abertas entre elas.

> **Se a "VM separada" for uma VM local (VirtualBox, por exemplo):** o modo
> de rede importa. Em modo **NAT** (padrão do VirtualBox), o host geralmente
> não alcança a VM diretamente — prefira **Bridged Adapter** ou **Host-only
> Adapter** pra essa comunicação funcionar sem redirecionamento de porta.

### Passo 1b — Configurar o log que o Agente vai monitorar

Edite `/var/ossec/etc/ossec.conf` (precisa de `sudo`) e adicione, dentro
da tag `<ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/SEU_USUARIO/aspm_wazuh_alerts.json</location>
</localfile>
```

Troque `SEU_USUARIO` pelo seu usuário real (rode `echo $HOME` se tiver
dúvida). Depois reinicie o agente:

```bash
sudo systemctl restart wazuh-agent
```

### Passo 2 — No Manager do Wazuh (na VM separada)

Abra `/var/ossec/etc/rules/local_rules.xml` (no servidor/Manager — pode
ser a mesma máquina ou outra, dependendo de como seu lab está montado) e
cole o conteúdo de `integrations/wazuh_rules.xml` deste projeto — sem
apagar o que já existir no arquivo. Depois reinicie o manager:

```bash
sudo systemctl restart wazuh-manager
```

### Passo 3 — Testar

```bash
python integrations/wazuh_forwarder.py   # escreve 1 evento de teste isolado
```

Depois rode o pipeline completo já enviando pro Wazuh:

```bash
python orchestrator.py --demo --dast-url http://localhost:5000 --exposto-internet --dados-sensiveis --wazuh
```

No painel do Wazuh, vá em **Módulos > Eventos de segurança** (ou pesquise
pelo grupo de regra `aspm`) — os achados CRÍTICA/ALTA/MÉDIA devem aparecer
como alertas, com a descrição já incluindo o título da vulnerabilidade.

## 11. Cuidados de segurança já implementados

- **Trava de ±25 no score da IA** (`risk_agent.py`) — ver seção 12 abaixo.
- Sanitização de texto antes de qualquer chamada aos agentes de IA
  (`BaseAgent.sanitize`), reduzindo risco de prompt injection vindo de
  descrições de vulnerabilidades controláveis por atacante.
- Fallback determinístico no Risk Agent caso a API de IA falhe.
- `.env` fora do controle de versão (já coberto pelo `.gitignore`).

## 12. A trava de ±25 pontos

O que impede a IA de "achar tudo crítico" e, com isso, destruir a própria
utilidade da fila priorizada.

O score do agente vai de 0 a 100 e o CVSS oficial vai de 0 a 10, então
`CVSS × 10` é o **score-base**, ou âncora. A IA pode ajustar esse número com
base no contexto real — exposição à internet, dado sensível, exploit público —
mas o ajuste nunca ultrapassa **25 pontos** para cima ou para baixo:

```python
score_base  = vulnerabilidade["cvss"] * 10
score_final = max(0, min(100, max(score_base - 25,
                                  min(score_base + 25, score_ia))))
```

```
CVSS 7.5  →  base 75  →  faixa permitida à IA: 50 a 100
```

Consequências práticas:

- Uma vulnerabilidade informativa (CVSS 3.1 → base 31) **nunca** vira Crítica,
  mesmo exposta e com dado sensível: no máximo chega a 56.
- Uma SQL Injection (CVSS 9.8 → base 98) permanece Crítica mesmo que a IA
  tente reduzi-la.
- Se o modelo devolver um valor fora da faixa, o score é cortado no limite e a
  justificativa registra o corte — o comportamento fica auditável.

As faixas de prioridade seguem o padrão oficial do CVSS: Crítica ≥ 90,
Alta 70–89, Média 40–69, Baixa < 40.

> A IA opina, o CVSS ancora.

## 13. CI — segurança na esteira

O workflow em `.github/workflows/seguranca.yml` roda **Bandit** (SAST) e
**Trivy** (SCA) a cada push e pull request, publicando os relatórios como
artefatos da execução, na aba **Actions**.

Os jobs usam `continue-on-error` de propósito: a `demo_app` é vulnerável por
definição, então achados **não** devem quebrar o build. O objetivo é gerar
evidência contínua de que a análise roda dentro do ciclo, não bloquear merge.
