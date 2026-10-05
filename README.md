# ASPM com IA — Tomahawks

Projeto do Challenge Pride 2026 — FIAP, turma 1TDCPF. **MVP entregue na
Sprint 4.** Guia comando por comando, do sistema zerado até o projeto
funcionando por completo: 3 Agentes de IA (Gemini, Ollama local ou
Anthropic), API HTTP própria, painel web, DefectDojo e Wazuh integrados.

Sempre que um passo pedir `sudo`, digite a senha da sua conta quando
solicitado. Sempre que um bloco pedir "venv ativado", confira se o
início da linha do terminal mostra `(venv)` antes de continuar.

> ### ⚠️ Aviso
>
> A pasta **`demo_app/` contém vulnerabilidades propositais** (SQL Injection,
> XSS refletido, entre outras). Ela existe para dar aos scanners algo real
> para encontrar.
>
> **Não faça deploy desta aplicação, não a exponha na internet e não
> reaproveite esse código em produção.**

## Estrutura

```
aspm_ia/
├── scanners/          # Bandit (SAST), Trivy (SCA), ZAP (DAST), NVD
├── agents/            # Risk, Explanation e Remediation Agents (IA)
├── integrations/       # DefectDojo e Wazuh
├── demo_app/            # App propositalmente vulnerável (alvo do DAST)
├── web/                  # Painel web (HTML/CSS/JS puro)
├── normalizer.py          # Unifica os formatos num schema único
├── orchestrator.py        # Coordena o fluxo inteiro (CLI)
├── api.py                  # Expõe o mesmo fluxo como API HTTP (FastAPI)
├── dashboard.py              # Interface Streamlit (alternativa ao painel web)
├── verificar_chave.py        # Testa o provedor de IA isoladamente
└── sample_data/                # Dados de teste (não precisa scanner instalado)
```

---

## Parte 1 — Pacotes de sistema

```bash
sudo apt update
```
Atualiza a lista de programas disponíveis para instalação.

```bash
sudo apt install python3 python3-pip python3-venv git default-jre -y
```
Instala: o Python 3, o gerenciador de pacotes do Python (`pip`), a
ferramenta de ambientes virtuais (`venv`), o Git (para lidar com
repositórios) e o Java (exigido pelo OWASP ZAP mais à frente).

```bash
python3 --version
```
Confirma a instalação. Deve responder `Python 3.10` ou superior.

---

## Parte 2 — Ambiente virtual do projeto

```bash
cd ~/FIAP/aspm_ia
```
Entra na pasta do projeto. Ajuste o caminho se a sua pasta for diferente.

```bash
python3 -m venv venv
```
Cria um ambiente virtual chamado `venv` — um Python isolado só para
este projeto, sem misturar com pacotes do sistema.

```bash
source venv/bin/activate
```
Ativa o ambiente virtual. **Esse comando precisa ser repetido em todo
terminal novo que for rodar algo do projeto.**

```bash
pip install -r requirements.txt
```
Instala todas as bibliotecas Python que o projeto usa, de uma vez,
lendo a lista do arquivo `requirements.txt`.

---

## Parte 3 — Chave da IA (Gemini, gratuita)

1. Acesse **https://aistudio.google.com/apikey** no navegador.
2. Faça login com uma conta Google.
3. Clique em **"Create API key"**.
4. Copie a chave gerada (uma string começando com `AIzaSy...`).

```bash
cp .env.example .env
```
Cria o arquivo de configuração real (`.env`) a partir do modelo
(`.env.example`).

```bash
nano .env
```
Abre o arquivo para edição. Deixe assim, colando sua chave real:
```
AI_PROVIDER=gemini
GEMINI_API_KEY=AIzaSy...sua-chave-aqui
```
Para salvar no `nano`: `Ctrl+O`, depois `Enter`, depois `Ctrl+X`.

```bash
python verificar_chave.py
```
Testa o provedor configurado isoladamente, sem rodar o projeto
inteiro. Precisa aparecer `✅ Gemini respondeu: OK`.

### Parte 3.1 — Alternativa: IA local com Ollama (offline, sem chave)

Se preferir rodar os 3 Agentes sem depender de internet nem de
cadastro — útil também como plano B se a cota gratuita do Gemini
esgotar em pleno ensaio da apresentação:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```
Instala o Ollama no sistema.

```bash
sudo systemctl enable ollama
sudo systemctl start ollama
```
Garante que o serviço sobe sozinho e já está rodando.

```bash
ollama pull llama3.1:8b
```
Baixa o modelo usado por padrão pelo projeto (uns 4–5 GB; a primeira
resposta depois do download também demora, porque o modelo precisa
carregar na memória).

```bash
nano .env
```
Troque a primeira linha:
```
AI_PROVIDER=ollama
```
As variáveis `OLLAMA_URL`, `OLLAMA_MODEL` e `OLLAMA_TIMEOUT` já vêm
com valor padrão no `.env.example` — só mude se usar outro modelo ou
outra porta.

```bash
python verificar_chave.py
```
Com `AI_PROVIDER=ollama`, este mesmo comando confere se o serviço está
de pé, se o modelo foi baixado, e testa uma resposta de verdade.

> Rodando em CPU (sem placa de vídeo dedicada), cada achado pode levar
> de 10 segundos a 1 minuto para ser analisado pelos 3 Agentes — é
> normal, e o `OLLAMA_TIMEOUT` já vem generoso por causa disso.

---

## Parte 4 — Primeiro teste, sem scanners

```bash
python orchestrator.py --demo
```
Roda o pipeline inteiro (Risk Agent, Explanation Agent, Remediation
Agent) usando 4 vulnerabilidades de exemplo já prontas, sem precisar
de nenhum scanner instalado ainda. A primeira linha impressa confirma
qual provedor de IA está em uso. Ao final, cria o arquivo
`resultado.json`.

```bash
streamlit run dashboard.py
```
Abre o dashboard no navegador (`http://localhost:8501`), mostrando a
tabela de vulnerabilidades priorizadas pela IA. Pressione `Ctrl+C` no
terminal para encerrar quando quiser sair.

> Alternativa: a **Parte 11** deste guia mostra como subir a API HTTP
> e o painel web novo (`http://localhost:8000`), que substitui este
> dashboard com filtros, progresso em tempo real e o detalhe visual da
> trava de ±25 em cada achado.

---

## Parte 5 — Trivy (SCA)

```bash
sudo apt install wget gnupg -y
```
Instala ferramentas usadas para baixar e validar o pacote do Trivy.

```bash
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
```
Baixa a chave de assinatura oficial do Trivy e a converte para o
formato que o `apt` entende.

```bash
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
```
Registra o repositório oficial do Trivy no sistema. O nome `generic`
funciona em qualquer distribuição baseada em Debian — em alguns
sistemas, usar o codinome da versão (ex: `noble`, `bookworm`) causa
erro 404, por isso `generic` é o mais seguro.

Se o seu sistema já tiver um `trivy` de outra origem instalado (por
exemplo, vindo direto da distribuição), garanta que o pacote oficial
seja o escolhido:
```bash
sudo tee /etc/apt/preferences.d/trivy-aqua > /dev/null <<'EOF'
Package: trivy
Pin: origin aquasecurity.github.io
Pin-Priority: 1001
EOF
```
Isso diz ao `apt` para sempre preferir o Trivy vindo do repositório
oficial da Aqua Security, mesmo que exista outro pacote com prioridade
alta.

```bash
sudo apt update
sudo apt install trivy -y
```
Atualiza a lista de pacotes (agora incluindo o repositório novo) e
instala o Trivy.

```bash
trivy --version
```
Confirma a instalação, mostrando o número da versão.

---

## Parte 6 — OWASP ZAP (DAST)

```bash
cd ~/Downloads
```
Entra na pasta de downloads (pode ser qualquer pasta de sua escolha).

```bash
wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz
```
Baixa o instalador do ZAP.

```bash
tar -xvzf ZAP_2.17.0_Linux.tar.gz
```
Extrai o arquivo baixado.

```bash
cd ZAP_2.17.0
```
Entra na pasta extraída.

```bash
./zap.sh -daemon -port 8090 -config api.disablekey=true
```
Inicia o ZAP em modo daemon (sem interface gráfica, pronto para ser
controlado por código), na porta 8090. Essa porta específica evita
conflito com o DefectDojo, que usa 8080 ou 8085. Deixe este terminal
aberto rodando — ele não deve ser fechado enquanto o ZAP for usado.

Ao escanear com a flag `--defectdojo` (Parte 8), o relatório do ZAP é
salvo e importado em **XML** — o parser "ZAP Scan" do DefectDojo exige
esse formato. Isso já é automático, não precisa configurar nada.

---

## Parte 7 — Docker

```bash
sudo apt install ca-certificates curl gnupg -y
```
Instala pré-requisitos para adicionar o repositório do Docker com
segurança.

```bash
sudo install -m 0755 -d /etc/apt/keyrings
```
Cria a pasta onde a chave de assinatura do Docker será guardada.

```bash
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
```
Baixa e prepara a chave oficial do Docker.

```bash
sudo chmod a+r /etc/apt/keyrings/docker.gpg
```
Garante que todos os usuários do sistema possam ler essa chave.

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```
Registra o repositório do Docker. O nome `trixie` corresponde ao
Debian 13. Em distribuições derivadas do Debian, o comando automático
para descobrir esse nome costuma devolver um valor que não existe no
repositório do Docker — por isso o nome é escrito direto aqui. Se o
seu sistema for baseado em outra versão do Debian, troque `trixie`
pelo codinome correspondente.

```bash
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
```
Atualiza a lista de pacotes e instala o Docker e o plugin do
`docker compose`.

```bash
sudo usermod -aG docker $USER
```
Adiciona seu usuário ao grupo `docker`, permitindo rodar comandos
Docker sem precisar de `sudo` toda vez.

**Feche a sessão e entre de novo (ou reinicie)** para essa mudança de
grupo valer. Depois, confirme:
```bash
docker --version
docker compose version
```

---

## Parte 8 — DefectDojo

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git ~/DefectDojo
```
Baixa o código do DefectDojo para dentro da sua pasta pessoal.

```bash
cd ~/DefectDojo
```
Entra na pasta baixada.

```bash
docker compose build
```
Monta as imagens Docker do DefectDojo a partir do código-fonte. Pode
demorar alguns minutos.

```bash
docker compose up -d
```
Sobe todos os serviços do DefectDojo (banco de dados, aplicação web,
etc.) em segundo plano.

```bash
docker compose logs initializer | grep "Admin password:"
```
Mostra a senha de administrador gerada automaticamente na primeira
inicialização. Copie e guarde essa senha.

Acesse **http://localhost:8080** no navegador e faça login com o
usuário `admin` e a senha copiada.

No painel: clique no seu usuário (canto superior direito), depois em
**API v2 Key**, e copie o token mostrado — apenas a sequência de
caracteres, **sem** a palavra "Token" na frente.

```bash
cd ~/FIAP/aspm_ia
nano .env
```
Adicione estas linhas, com o token real:
```
DEFECTDOJO_URL=http://localhost:8080/api/v2
DEFECTDOJO_API_TOKEN=seu-token-aqui
DEFECTDOJO_PRODUCT_TYPE_NAME=Challenge Pride 2026
```

```bash
source venv/bin/activate
python integrations/testar_defectdojo.py
```
Roda um teste isolado: escaneia a pasta `demo_app` com o Bandit,
envia o resultado para o DefectDojo e confirma se os achados voltaram.
Precisa aparecer `✅ ... Finding(s) retornado(s)`.

---

## Parte 9 — Wazuh (SIEM)

### 9.1 — No Manager (VM ou outra máquina)

Confirme a versão instalada nessa máquina:
```bash
sudo /var/ossec/bin/wazuh-control info
```
Anote o número mostrado (ex: `4.14.0`).

### 9.2 — No Parrot/Debian, instalar o Agente na mesma versão

```bash
sudo apt-get install gnupg apt-transport-https -y
```
Instala pré-requisitos.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
```
Baixa e importa a chave oficial do Wazuh.

```bash
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
```
Ajusta a permissão da chave para leitura geral.

```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
```
Registra o repositório do Wazuh.

```bash
sudo apt-get update
```
Atualiza a lista de pacotes.

```bash
apt-cache madison wazuh-agent
```
Lista as versões disponíveis do agente. Confira o número exato que
bate com a versão do Manager, anotada no passo 9.1.

```bash
WAZUH_MANAGER="IP_DO_MANAGER" sudo -E apt-get install wazuh-agent=VERSAO-1 -y
```
Instala o agente já configurado para apontar para o Manager. Troque
`IP_DO_MANAGER` pelo IP real, e `VERSAO-1` pela versão exata (ex:
`4.14.0-1`).

```bash
sudo apt-mark hold wazuh-agent
```
Impede que uma atualização futura do sistema troque a versão do
agente sem querer, o que quebraria a conexão com o Manager.

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
Configura o agente para iniciar automaticamente e o inicia agora.

```bash
sudo tail -20 /var/ossec/logs/ossec.log
```
Mostra as últimas linhas do log do agente. Procure pela frase
`Connected to the manager`.

### 9.3 — Configurar o que o agente vai vigiar

```bash
sudo nano /var/ossec/etc/ossec.conf
```
Adicione, dentro da tag `<ossec_config>`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/SEU_USUARIO/aspm_wazuh_alerts.json</location>
</localfile>
```
Troque `SEU_USUARIO` pelo valor real (confira com `echo $HOME`).

```bash
sudo systemctl restart wazuh-agent
```
Reinicia o agente para aplicar a mudança.

### 9.4 — Regras customizadas (no Manager)

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
Cole o conteúdo do arquivo `integrations/wazuh_rules.xml`, deste
projeto, sem apagar o que já existir no arquivo.

```bash
sudo systemctl restart wazuh-manager
```
Reinicia o Manager para aplicar as novas regras.

---

## Parte 10 — Rodar tudo junto

**Terminal 1 — app vulnerável de demonstração:**
```bash
cd ~/FIAP/aspm_ia
source venv/bin/activate
python demo_app/app.py
```
Deixe rodando. Confirme em `http://localhost:5000`.

**Terminal 2 — OWASP ZAP** (se ainda não estiver rodando da Parte 6):
```bash
cd ~/Downloads/ZAP_2.17.0
./zap.sh -daemon -port 8090 -config api.disablekey=true
```

**Terminal 3 — orquestrador e dashboard:**
```bash
cd ~/FIAP/aspm_ia
source venv/bin/activate
python orchestrator.py --path demo_app --dast-url http://localhost:5000 --exposto-internet --dados-sensiveis --wazuh --defectdojo
```
Executa o fluxo inteiro: escaneia com Bandit, Trivy e ZAP, envia os
achados brutos para o DefectDojo, analisa cada um com os 3 Agentes de
IA, grava o resultado, anota de volta no DefectDojo e envia os
achados relevantes para o Wazuh.

```bash
streamlit run dashboard.py
```
Abre o dashboard local com o resultado final. (Ou, em vez disso, suba
a API e o painel web novo — Parte 11.)

---

## Onde conferir o resultado

| Painel | Endereço |
|---|---|
| Painel web + API (FastAPI) | `http://localhost:8000` |
| Dashboard Streamlit (alternativa) | `http://localhost:8501` |
| DefectDojo | `http://localhost:8080` |
| Wazuh | `https://IP_DO_MANAGER` |

---

## Tabela de referência rápida — comandos do dia a dia

| Ação | Comando |
|---|---|
| Ativar o ambiente virtual | `source venv/bin/activate` |
| Testar o provedor de IA configurado | `python verificar_chave.py` |
| Rodar com dados de exemplo | `python orchestrator.py --demo` |
| Rodar o fluxo completo | `python orchestrator.py --path demo_app --dast-url http://localhost:5000 --exposto-internet --dados-sensiveis --wazuh --defectdojo` |
| Abrir o dashboard Streamlit | `streamlit run dashboard.py` |
| Subir a API + painel web | `uvicorn api:app --reload` |
| Reinstalar dependências | `pip install -r requirements.txt` |

---

## Parte 11 — API HTTP e painel web

`api.py` expõe o mesmo pipeline do `orchestrator.py` como serviço, para
que qualquer cliente — o painel web, outra ferramenta, a própria CI —
consuma o motor pela rede. A camada **não reimplementa nada**: importa
`coletar_achados`, `coletar_via_defectdojo` e `processar_com_agentes`
do orquestrador. A linha de comando (Partes 1–10) continua funcionando
exatamente como antes, sem depender da API.

```bash
uvicorn api:app --reload
```
Sobe os dois juntos, numa origem só (sem CORS no caminho):
- Painel: `http://localhost:8000`
- Documentação interativa (Swagger): `http://localhost:8000/docs`

### Endpoints

| Método | Rota | Para quê |
|---|---|---|
| `GET` | `/health` | Serviço de pé, provedor de IA e se a chave está configurada |
| `POST` | `/scans` | Dispara um escaneamento. Devolve `scan_id` na hora (202) |
| `GET` | `/scans` | Lista os escaneamentos, mais recente primeiro |
| `GET` | `/scans/{id}` | Status, progresso e contagem por prioridade |
| `GET` | `/scans/{id}/findings` | Achados, com filtros — alimenta a tabela do painel |
| `GET` | `/scans/{id}/findings/{fid}` | Um achado, com explicação e remediação da IA |
| `DELETE` | `/scans/{id}` | Remove o escaneamento e seu arquivo de resultado |

Filtros de `/findings`: `prioridade` (repetível), `ferramenta`, `score_min`
e `busca` (texto livre em título e descrição).

### Escaneamentos são assíncronos

Um scan real leva minutos — scanners e uma chamada de IA por achado. Então o
`POST /scans` responde **202 Accepted** imediatamente com o `scan_id`, e o
cliente acompanha:

```
na_fila → coletando → analisando → concluido
                          ↑
              progresso: {analisados, total}
```

O campo `progresso` existe porque `processar_com_agentes` aceita um callback
opcional `on_progress(analisados, total)`. Quem não passa o callback — o CLI —
não muda em nada.

Com `AI_PROVIDER=ollama`, o campo `variavel_esperada` de `/health` vem
`null` e `chave_configurada` vem sempre `true` — o Ollama não usa chave.

### Exemplo

```bash
# dispara em modo demo (não precisa de scanner instalado)
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"modo":"demo","exposto_internet":true,"dados_sensiveis":true}'
# -> {"scan_id":"a1b2c3d4e5f6","status":"na_fila",...}

# acompanha
curl http://localhost:8000/scans/a1b2c3d4e5f6

# só o que é crítico ou alto
curl "http://localhost:8000/scans/a1b2c3d4e5f6/findings?prioridade=CRITICA&prioridade=ALTA"
```

### Persistência

Os resultados ficam em memória e são gravados em `resultados/{scan_id}.json`,
recarregados quando o servidor sobe. É proposital não haver banco de dados:
para o escopo do projeto, arquivo resolve e mantém tudo inspecionável.

### O painel web (`web/`)

HTML, CSS e JavaScript puros — **sem framework e sem build**. Servido
pela própria FastAPI (por isso um comando só sobe os dois).

O que a tela faz:

- **Dispara escaneamentos** nos três modos (demo, diretório, DefectDojo),
  com os interruptores de contexto que alimentam o Risk Agent — "exposto à
  internet" e "lida com dado sensível".
- **Acompanha o progresso** em tempo real: `coletando → analisando`, com o
  contador de achados já processados vindo do `on_progress` da API.
- **Contagem por severidade** em painéis no topo.
- **Tabela priorizada**, com filtro por severidade, por ferramenta e busca
  textual. Os filtros são aplicados **no servidor**, pela própria API — a tela
  não filtra em memória.
- **Detalhe de cada achado**, com a explicação e a remediação escritas pela IA.

No detalhe de cada achado há uma **régua de 0 a 100** mostrando:

- a **âncora** (`CVSS × 10`), como linha vertical;
- a **faixa permitida** à IA (âncora ±25), em destaque;
- **onde a IA pontuou**, como marcador colorido pela prioridade;
- e o desvio em pontos, escrito por extenso.

É a trava de ±25 (Parte 13 abaixo) deixando de ser um parágrafo de
documentação e virando algo que dá para apontar na tela.

**Nota de segurança do próprio painel:** títulos e descrições exibidos
vêm dos scanners, ou seja, podem conter texto controlado por quem
escreveu o código analisado. Por isso **todo conteúdo dinâmico é
inserido via `textContent`** — o `app.js` não usa `innerHTML`,
`insertAdjacentHTML` nem `document.write` em lugar nenhum. Um painel de
segurança vulnerável a XSS seria uma ironia cara.

---

## Parte 12 — CI: segurança na esteira

O workflow em `.github/workflows/seguranca.yml` roda **Bandit** (SAST) e
**Trivy** (SCA) a cada push e pull request, publicando os relatórios como
artefatos da execução, na aba **Actions** do GitHub.

Os jobs usam `continue-on-error` de propósito: a `demo_app` é vulnerável por
definição, então achados **não** devem quebrar o build. O objetivo é gerar
evidência contínua de que a análise roda dentro do ciclo, não bloquear merge.

---

## Parte 13 — A trava de ±25 pontos

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
- Se o modelo devolver algo que nem é número (ex: campo vazio, texto), o
  score cai para o CVSS puro em vez de quebrar o pipeline.

As faixas de prioridade seguem o padrão oficial do CVSS: Crítica ≥ 90,
Alta 70–89, Média 40–69, Baixa < 40.

> A IA opina, o CVSS ancora.

### Outros cuidados de segurança já implementados

- Sanitização de texto antes de qualquer chamada aos agentes de IA
  (`BaseAgent.sanitize`), reduzindo risco de prompt injection vindo de
  descrições de vulnerabilidades controláveis por atacante.
- Fallback determinístico no Risk Agent caso a API de IA falhe.
- `.env` fora do controle de versão (já coberto pelo `.gitignore`).

---

## Parte 14 — Problemas comuns já resolvidos

Erros reais que apareceram rodando o projeto num Debian/Parrot OS de verdade,
e o que resolveu cada um. Confira aqui antes de abrir uma issue.

| Sintoma | Causa | Solução |
|---|---|---|
| `python: comando não encontrado` | O venv não foi ativado | `source venv/bin/activate` (ou `.venv\Scripts\activate` no Windows) |
| `ModuleNotFoundError` | Pacote não instalado *nesse* venv | Confirme que o venv está ativo, depois `pip install -r requirements.txt` |
| ZAP: porta em uso | Conflito com o DefectDojo (8080/8085) | Suba o ZAP em `-port 8090`, nunca 8080/8085 |
| Wazuh: versão do agente incompatível | Agente mais novo que o Manager | Instale a mesma versão do Manager: `apt-cache madison wazuh-agent` mostra as disponíveis |
| Gemini: `404 model not found` | Nome de modelo descontinuado | Já resolvido — `agents/base_agent.py` usa `gemini-3.5-flash` / `gemini-3.1-flash-lite` |
| Gemini: `429 RESOURCE_EXHAUSTED` | Limite do free tier (RPM) | Já tratado: espera com backoff e troca para o modelo de reserva automaticamente |
| Gemini: `API key not valid` | Chave errada, revogada, ou ainda com o texto de exemplo | Mensagem já aponta a causa direto — corrija a chave ou troque para `AI_PROVIDER=ollama` |
| Risk Agent: `KeyError` em 'justificativa' | A IA devolveu JSON sem esse campo | Já corrigido em `risk_agent.py` com `.get("justificativa", "")` |
| Risk Agent: score não numérico da IA | A IA devolveu texto no lugar de um número | Já corrigido: cai para o CVSS puro em vez de quebrar |
| Ollama: `ConnectionError` | O serviço não está rodando | `sudo systemctl start ollama` |
| Ollama: erro ao gerar resposta / modelo ausente | O modelo configurado não foi baixado | `ollama pull llama3.1:8b` (ou o nome em `OLLAMA_MODEL`) |
| DefectDojo: `400 Bad Request` no import | Faltava `product_type_name` no payload | Já corrigido em `defectdojo_client.py` — o campo é obrigatório e sempre enviado |
| DefectDojo: erro ao importar o scan do ZAP | O parser "ZAP Scan" exige XML, não JSON | Já corrigido: `dast_scanner.py` salva com `zap.core.xmlreport()`, e o orquestrador importa `zap_raw.xml` |
| DefectDojo: token rejeitado | Colou a linha inteira, incluindo a palavra "Token" | Cole só o valor que vem depois de "Token " |

---

## Roadmap

- [x] API HTTP própria (FastAPI)
- [x] Painel web consumindo essa API
- [x] Provedor de IA local (Ollama), sem depender de internet
- [ ] Mais scanners (Semgrep)
- [ ] Ambiente de produção real, não só demonstração local

---

## Licença

Licenciado sob a **Licença BSD de 3 Cláusulas** (SPDX: `BSD-3-Clause`) — texto
completo em [`LICENSE.md`](LICENSE.md).

**Dependências de terceiros.** O projeto usa ferramentas e bibliotecas de
terceiros (Bandit, Trivy, OWASP ZAP, DefectDojo, Wazuh, Streamlit, Flask).
Elas **não são distribuídas dentro deste repositório**: são instaladas
separadamente (veja `requirements.txt` e este README) e cada uma continua
sob a sua própria licença.

**Aplicação de demonstração.** A pasta `demo_app/` contém uma aplicação
**propositalmente vulnerável**, criada apenas como alvo de testes. Não a
utilize em produção nem a exponha à internet.

---

## Equipe

Enzo Seixas · Gabriel Cirone · Guilherme Reis · João Pedro · Matheus Silva

FIAP Paulista — Challenge Pride 2026
