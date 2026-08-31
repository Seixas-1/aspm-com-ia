/* ASPM com IA — front-end
 *
 * Consome a API do api.py. Sem framework e sem build: é servido pela própria
 * FastAPI, então a origem é a mesma e não há CORS envolvido.
 *
 * Nota de segurança: os títulos e descrições exibidos aqui vêm de scanners,
 * ou seja, podem conter texto controlado por quem escreveu o código analisado.
 * Por isso todo conteúdo dinâmico entra via textContent — nunca innerHTML.
 * Um painel de segurança com XSS seria uma ironia cara.
 */

const $ = (sel) => document.querySelector(sel);

const estado = {
  scanId: null,
  polling: null,
  prioridades: new Set(),
};

const PRIORIDADES = ["CRITICA", "ALTA", "MEDIA", "BAIXA"];
const ROTULO = { CRITICA: "Crítica", ALTA: "Alta", MEDIA: "Média", BAIXA: "Baixa" };
const COR = {
  CRITICA: "var(--crit)", ALTA: "var(--alta)",
  MEDIA: "var(--media)", BAIXA: "var(--baixa)",
};

/* ── Cliente HTTP ──────────────────────────────────────── */

async function api(caminho, opcoes = {}) {
  const resp = await fetch(caminho, {
    headers: { "Content-Type": "application/json" },
    ...opcoes,
  });
  if (!resp.ok) {
    let detalhe = `HTTP ${resp.status}`;
    try {
      const corpo = await resp.json();
      if (corpo.detail) detalhe = corpo.detail;
    } catch { /* resposta sem JSON */ }
    throw new Error(detalhe);
  }
  return resp.status === 204 ? null : resp.json();
}

/* ── Saúde do serviço ──────────────────────────────────── */

async function verificarSaude() {
  const el = $("#saude");
  try {
    const s = await api("/health");
    if (s.chave_configurada) {
      el.textContent = `${s.provider_ia} · chave ok`;
      el.className = "ok";
    } else {
      el.textContent = `${s.variavel_esperada} ausente`;
      el.className = "erro";
      $("#btn-scan").disabled = true;
      $("#btn-scan").title = "Configure a chave no arquivo .env";
    }
  } catch {
    el.textContent = "API fora do ar";
    el.className = "erro";
    $("#btn-scan").disabled = true;
  }
}

/* ── Lista de escaneamentos ────────────────────────────── */

async function carregarScans(selecionar = null) {
  const select = $("#lista-scans");
  const scans = await api("/scans");
  select.textContent = "";

  if (!scans.length) {
    select.append(new Option("nenhum ainda", ""));
    return;
  }

  for (const s of scans) {
    const quando = new Date(s.criado_em).toLocaleString("pt-BR");
    const opt = new Option(`${s.modo} · ${quando} · ${s.status}`, s.scan_id);
    select.append(opt);
  }

  const alvo = selecionar || scans[0].scan_id;
  select.value = alvo;
  if (alvo) await abrirScan(alvo);
}

/* ── Disparar escaneamento ─────────────────────────────── */

async function iniciarScan() {
  const botao = $("#btn-scan");
  botao.disabled = true;
  botao.textContent = "Iniciando…";

  const corpo = {
    modo: $("#modo").value,
    path: $("#path").value || ".",
    dast_url: $("#dast").value || null,
    exposto_internet: $("#exposto").checked,
    dados_sensiveis: $("#sensiveis").checked,
    enviar_wazuh: $("#wazuh").checked,
  };

  try {
    const scan = await api("/scans", { method: "POST", body: JSON.stringify(corpo) });
    estado.scanId = scan.scan_id;
    await carregarScans(scan.scan_id);
    acompanhar(scan.scan_id);
  } catch (e) {
    mostrarErro(e.message);
  } finally {
    botao.disabled = false;
    botao.textContent = "Iniciar escaneamento";
  }
}

/* ── Acompanhamento do progresso ───────────────────────── */

function acompanhar(scanId) {
  clearTimeout(estado.polling);

  const passo = async () => {
    let scan;
    try {
      scan = await api(`/scans/${scanId}`);
    } catch {
      return; // scan removido enquanto acompanhávamos
    }

    renderProgresso(scan);

    if (scan.status === "concluido") {
      $("#progresso").hidden = true;
      renderTiles(scan.por_prioridade);
      await carregarAchados();
      carregarScans(scanId);
      return;
    }
    if (scan.status === "erro") {
      $("#progresso").hidden = true;
      mostrarErro(scan.erro || "O escaneamento falhou.");
      return;
    }
    estado.polling = setTimeout(passo, 1500);
  };

  passo();
}

function renderProgresso(scan) {
  const nomes = {
    na_fila: "na fila", coletando: "coletando com os scanners",
    analisando: "analisando com os agentes de IA",
  };
  if (!(scan.status in nomes)) return;

  $("#progresso").hidden = false;
  $("#fase").textContent = nomes[scan.status];

  const { analisados, total } = scan.progresso;
  $("#contador").textContent = total ? `${analisados} / ${total}` : "";
  $("#barra-preenchida").style.width = total ? `${(analisados / total) * 100}%` : "0%";
}

/* ── Abrir um escaneamento já existente ────────────────── */

async function abrirScan(scanId) {
  estado.scanId = scanId;
  const scan = await api(`/scans/${scanId}`);

  if (scan.status === "concluido") {
    $("#progresso").hidden = true;
    renderTiles(scan.por_prioridade);
    await carregarAchados();
  } else if (scan.status === "erro") {
    renderTiles({});
    limparTabela("Este escaneamento falhou.");
    mostrarErro(scan.erro || "Falhou.");
  } else {
    acompanhar(scanId);
  }
}

/* ── Contagem por prioridade ───────────────────────────── */

function renderTiles(porPrioridade) {
  const alvo = $("#tiles");
  alvo.textContent = "";

  const total = Object.values(porPrioridade).reduce((a, b) => a + b, 0);
  if (!total) return;

  for (const p of PRIORIDADES) {
    const div = document.createElement("div");
    div.className = "tile";
    div.dataset.p = p;

    const n = document.createElement("div");
    n.className = "n";
    n.textContent = porPrioridade[p] || 0;

    const r = document.createElement("div");
    r.className = "r";
    r.textContent = ROTULO[p];

    div.append(n, r);
    alvo.append(div);
  }

  const div = document.createElement("div");
  div.className = "tile";
  const n = document.createElement("div");
  n.className = "n";
  n.textContent = total;
  const r = document.createElement("div");
  r.className = "r";
  r.textContent = "Total";
  div.append(n, r);
  alvo.append(div);
}

/* ── Tabela de achados ─────────────────────────────────── */

async function carregarAchados() {
  if (!estado.scanId) return;

  const params = new URLSearchParams();
  estado.prioridades.forEach((p) => params.append("prioridade", p));
  if ($("#filtro-ferramenta").value) params.set("ferramenta", $("#filtro-ferramenta").value);
  if ($("#filtro-busca").value.trim()) params.set("busca", $("#filtro-busca").value.trim());

  const achados = await api(`/scans/${estado.scanId}/findings?${params}`);
  renderTabela(achados);
}

function limparTabela(mensagem) {
  $("#corpo-tabela").textContent = "";
  const vazio = $("#vazio");
  vazio.hidden = false;
  vazio.textContent = mensagem;
}

function renderTabela(achados) {
  const corpo = $("#corpo-tabela");
  corpo.textContent = "";

  if (!achados.length) {
    limparTabela("Nenhum achado com os filtros atuais.");
    return;
  }
  $("#vazio").hidden = true;

  for (const a of achados) {
    const tr = document.createElement("tr");
    tr.tabIndex = 0;
    tr.dataset.id = a.id;

    // Prioridade
    const tdP = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.dataset.p = a.prioridade || "";
    pill.textContent = ROTULO[a.prioridade] || "—";
    tdP.append(pill);

    // Score
    const tdS = document.createElement("td");
    tdS.className = "score";
    tdS.style.color = COR[a.prioridade] || "var(--ink)";
    tdS.textContent = a.score_ia ?? "—";

    // Título e localização
    const tdT = document.createElement("td");
    const titulo = document.createElement("div");
    titulo.textContent = a.titulo;
    const local = document.createElement("div");
    local.className = "local";
    local.textContent = a.linha ? `${a.arquivo}:${a.linha}` : (a.arquivo || "");
    tdT.append(titulo, local);

    // Origem
    const tdF = document.createElement("td");
    tdF.className = "ferramenta";
    tdF.textContent = a.ferramenta;

    tr.append(tdP, tdS, tdT, tdF);
    tr.addEventListener("click", () => abrirDetalhe(a.id, tr));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); abrirDetalhe(a.id, tr); }
    });
    corpo.append(tr);
  }
}

/* ── Gaveta de detalhe ─────────────────────────────────── */

async function abrirDetalhe(findingId, linha) {
  document.querySelectorAll("tbody tr[aria-selected]").forEach((tr) =>
    tr.removeAttribute("aria-selected"));
  if (linha) linha.setAttribute("aria-selected", "true");

  const a = await api(`/scans/${estado.scanId}/findings/${findingId}`);
  const corpo = $("#gaveta-corpo");
  corpo.textContent = "";
  $("#gaveta-titulo").textContent = a.titulo;

  corpo.append(
    blocoMeta(a),
    blocoTrava(a),
    bloco("Por que este score", a.justificativa_risco),
    bloco("O que é, em português", a.explicacao_ia),
    bloco("Como corrigir", a.remediacao_ia, true),
  );

  $("#gaveta").classList.add("aberto");
  $("#gaveta").setAttribute("aria-hidden", "false");
  $("#fundo").classList.add("aberto");
  $("#btn-fechar").focus();
}

function fecharGaveta() {
  $("#gaveta").classList.remove("aberto");
  $("#gaveta").setAttribute("aria-hidden", "true");
  $("#fundo").classList.remove("aberto");
}

function bloco(titulo, texto, monoespacado = false) {
  const sec = document.createElement("section");
  sec.className = "bloco";

  const h = document.createElement("h4");
  h.textContent = titulo;

  const p = document.createElement(monoespacado ? "pre" : "p");
  p.textContent = texto || "—";

  sec.append(h, p);
  return sec;
}

function blocoMeta(a) {
  const sec = document.createElement("section");
  sec.className = "bloco";

  const dl = document.createElement("dl");
  dl.className = "meta";

  const campos = [
    ["Prioridade", ROTULO[a.prioridade] || "—"],
    ["Score da IA", a.score_ia ?? "—"],
    ["CVSS", a.cvss ?? "—"],
    ["Ferramenta", a.ferramenta],
    ["CVE", a.cve || "—"],
    ["Local", a.linha ? `${a.arquivo}:${a.linha}` : (a.arquivo || "—")],
  ];

  for (const [rotulo, valor] of campos) {
    const div = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = rotulo;
    const dd = document.createElement("dd");
    dd.textContent = valor;
    if (rotulo === "Prioridade") dd.style.color = COR[a.prioridade] || "var(--ink)";
    div.append(dt, dd);
    dl.append(div);
  }

  sec.append(dl);
  return sec;
}

/* A régua que mostra a trava de ±25: onde o CVSS ancorou, qual faixa a IA
   podia usar, e onde ela de fato pontuou. É o diferencial do projeto,
   visível em cada achado. */
function blocoTrava(a) {
  const sec = document.createElement("section");
  sec.className = "bloco trava";

  const h = document.createElement("h4");
  h.textContent = "Trava de ±25 sobre o CVSS";
  sec.append(h);

  if (a.cvss == null || a.score_ia == null) {
    const p = document.createElement("p");
    p.textContent = "Sem CVSS ou score para comparar.";
    sec.append(p);
    return sec;
  }

  const base = a.cvss * 10;
  const min = Math.max(0, base - 25);
  const max = Math.min(100, base + 25);

  const regua = document.createElement("div");
  regua.className = "regua";

  const fundo = document.createElement("div");
  fundo.className = "fundo";

  const faixa = document.createElement("div");
  faixa.className = "faixa";
  faixa.style.left = `${min}%`;
  faixa.style.width = `${max - min}%`;

  const ancora = document.createElement("div");
  ancora.className = "ancora";
  ancora.style.left = `${base}%`;
  ancora.title = `Âncora: CVSS ${a.cvss} × 10 = ${base}`;

  const agulha = document.createElement("div");
  agulha.className = "agulha";
  agulha.style.left = `${a.score_ia}%`;
  agulha.style.background = COR[a.prioridade] || "var(--ink)";
  agulha.title = `Score da IA: ${a.score_ia}`;

  regua.append(fundo, faixa, ancora, agulha);

  const legenda = document.createElement("div");
  legenda.className = "regua-legenda";
  ["0", "25", "50", "75", "100"].forEach((n) => {
    const s = document.createElement("span");
    s.textContent = n;
    legenda.append(s);
  });

  const nota = document.createElement("p");
  nota.className = "trava-nota";
  const desvio = a.score_ia - base;
  const sinal = desvio > 0 ? "+" : "";
  nota.textContent =
    `Âncora ${base} (CVSS ${a.cvss} × 10). Faixa permitida: ${min} a ${max}. ` +
    `A IA pontuou ${a.score_ia} — desvio de ${sinal}${desvio.toFixed(0)} ponto(s).`;

  sec.append(regua, legenda, nota);
  return sec;
}

/* ── Erros ─────────────────────────────────────────────── */

function mostrarErro(mensagem) {
  const alvo = $("#tiles");
  const box = document.createElement("div");
  box.className = "erro-box";
  box.style.gridColumn = "1 / -1";

  const t = document.createElement("strong");
  t.textContent = "Não foi possível concluir.";
  const p = document.createElement("pre");
  p.textContent = mensagem;

  box.append(t, p);
  alvo.textContent = "";
  alvo.append(box);
}

/* ── Ligações de eventos ───────────────────────────────── */

function alternarCamposDoModo() {
  const modo = $("#modo").value;
  $("#campo-path").hidden = modo === "demo";
  $("#campo-dast").hidden = modo === "demo";
}

let debounce;

function ligarEventos() {
  $("#modo").addEventListener("change", alternarCamposDoModo);
  $("#btn-scan").addEventListener("click", iniciarScan);
  $("#btn-recarregar").addEventListener("click", () => carregarScans());
  $("#lista-scans").addEventListener("change", (e) => {
    if (e.target.value) abrirScan(e.target.value);
  });

  $("#filtro-prioridade").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    const p = chip.dataset.p;
    const ativo = chip.getAttribute("aria-pressed") === "true";
    chip.setAttribute("aria-pressed", String(!ativo));
    ativo ? estado.prioridades.delete(p) : estado.prioridades.add(p);
    carregarAchados();
  });

  $("#filtro-ferramenta").addEventListener("change", carregarAchados);
  $("#filtro-busca").addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(carregarAchados, 300);
  });

  $("#btn-fechar").addEventListener("click", fecharGaveta);
  $("#fundo").addEventListener("click", fecharGaveta);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") fecharGaveta();
  });
}

/* ── Início ────────────────────────────────────────────── */

(async function iniciar() {
  ligarEventos();
  alternarCamposDoModo();
  await verificarSaude();
  try {
    await carregarScans();
  } catch (e) {
    mostrarErro(e.message);
  }
})();
