"""
API HTTP do ASPM com IA
=======================

Expõe o pipeline do `orchestrator.py` como serviço, para que qualquer cliente
(front-end web, outra ferramenta, CI) consuma o mesmo motor — do mesmo jeito
que o DefectDojo e o Wazuh já consomem a saída.

Esta camada NÃO reimplementa nada: importa as funções que já existem no
orquestrador. A linha de comando continua funcionando exatamente como antes.

Uso:
    uvicorn api:app --reload
    # documentação interativa em http://localhost:8000/docs

Escaneamentos rodam em segundo plano: o POST devolve na hora um `scan_id`,
e o cliente acompanha o progresso consultando GET /scans/{scan_id}.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
import os
import traceback
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from orchestrator import (
    coletar_achados,
    coletar_via_defectdojo,
    processar_com_agentes,
)

BASE_DIR = Path(__file__).resolve().parent
RESULTADOS_DIR = BASE_DIR / "resultados"
RESULTADOS_DIR.mkdir(exist_ok=True)

load_dotenv(BASE_DIR / ".env")


# ─────────────────────────────────────────────────────────────
#  Modelos
# ─────────────────────────────────────────────────────────────

class ModoScan(str, Enum):
    demo = "demo"                # usa sample_data/, não precisa de scanner instalado
    path = "path"                # roda Bandit + Trivy (+ ZAP) sobre um diretório
    defectdojo = "defectdojo"    # ingestão e dedup pelo DefectDojo


class StatusScan(str, Enum):
    na_fila = "na_fila"
    coletando = "coletando"
    analisando = "analisando"
    concluido = "concluido"
    erro = "erro"


class NovoScan(BaseModel):
    modo: ModoScan = ModoScan.demo
    path: str = Field(default=".", description="Diretório a escanear (modos path/defectdojo)")
    dast_url: str | None = Field(
        default=None, description="URL da aplicação no ar, para o DAST. Ex: http://localhost:5000"
    )
    exposto_internet: bool = Field(
        default=False, description="Contexto para o Risk Agent: o alvo está exposto à internet"
    )
    dados_sensiveis: bool = Field(
        default=False, description="Contexto para o Risk Agent: o alvo lida com dado sensível"
    )
    enviar_wazuh: bool = Field(
        default=False, description="Encaminha os achados priorizados ao Wazuh ao final"
    )


class Progresso(BaseModel):
    analisados: int = 0
    total: int = 0


class ResumoScan(BaseModel):
    scan_id: str
    status: StatusScan
    modo: ModoScan
    criado_em: datetime
    concluido_em: datetime | None = None
    progresso: Progresso = Progresso()
    total_achados: int = 0
    por_prioridade: dict[str, int] = {}
    erro: str | None = None


class Achado(BaseModel):
    id: str
    ferramenta: str
    titulo: str
    descricao: str | None = None
    arquivo: str | None = None
    linha: int | None = None
    cve: str | None = None
    cvss: float | None = None
    severidade_original: str | None = None
    score_ia: int | None = None
    prioridade: str | None = None
    justificativa_risco: str | None = None
    explicacao_ia: str | None = None
    remediacao_ia: str | None = None

    @property
    def score_base(self) -> float | None:
        return round(self.cvss * 10, 1) if self.cvss is not None else None


# ─────────────────────────────────────────────────────────────
#  Registro em memória
#
#  Proposital: um dicionário, não um banco. O resultado de cada scan
#  também é gravado em resultados/{scan_id}.json, então sobrevive a
#  reinício do servidor — os scans são recarregados na subida.
# ─────────────────────────────────────────────────────────────

_scans: dict[str, dict[str, Any]] = {}
_lock = Lock()

ORDEM_PRIORIDADE = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAIXA": 3}


def _agora() -> datetime:
    return datetime.now(timezone.utc)


def _status_chave_ia() -> tuple[str, str | None, bool]:
    """
    Devolve (provider, variavel_esperada, configurada).

    `variavel_esperada` é None para "ollama", que não usa chave — sem essa
    distinção, o provider ollama era erroneamente tratado como se precisasse
    de ANTHROPIC_API_KEY (mesmo bug que já existiu no orchestrator.py).
    """
    provider = os.getenv("AI_PROVIDER", "gemini").lower()
    variaveis = {"gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
    variavel = variaveis.get(provider)
    if variavel is None:
        return provider, None, True  # ollama não precisa de chave

    valor = os.getenv(variavel, "")
    configurada = bool(valor) and not valor.startswith("sua-chave")
    return provider, variavel, configurada


def _contar_por_prioridade(achados: list[dict]) -> dict[str, int]:
    contagem: dict[str, int] = {}
    for achado in achados:
        chave = (achado.get("prioridade") or "SEM_PRIORIDADE").upper()
        contagem[chave] = contagem.get(chave, 0) + 1
    return dict(sorted(contagem.items(), key=lambda kv: ORDEM_PRIORIDADE.get(kv[0], 99)))


def _atualizar(scan_id: str, **campos: Any) -> None:
    with _lock:
        if scan_id in _scans:
            _scans[scan_id].update(campos)


def _carregar_scans_do_disco() -> None:
    """Recupera scans concluídos gravados em execuções anteriores."""
    for arquivo in sorted(RESULTADOS_DIR.glob("*.json")):
        try:
            dados = json.loads(arquivo.read_text(encoding="utf-8"))
            scan_id = dados["scan_id"]
            _scans[scan_id] = dados
            _scans[scan_id]["criado_em"] = datetime.fromisoformat(dados["criado_em"])
            if dados.get("concluido_em"):
                _scans[scan_id]["concluido_em"] = datetime.fromisoformat(dados["concluido_em"])
        except Exception:
            continue  # arquivo corrompido não derruba a subida do servidor


def _gravar_em_disco(scan_id: str) -> None:
    with _lock:
        dados = dict(_scans.get(scan_id, {}))
    if not dados:
        return
    dados["criado_em"] = dados["criado_em"].isoformat()
    if dados.get("concluido_em"):
        dados["concluido_em"] = dados["concluido_em"].isoformat()
    (RESULTADOS_DIR / f"{scan_id}.json").write_text(
        json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ─────────────────────────────────────────────────────────────
#  Execução do pipeline
# ─────────────────────────────────────────────────────────────

def _executar_scan(scan_id: str, req: NovoScan) -> None:
    """Roda o pipeline completo. Chamado em segundo plano."""
    try:
        _atualizar(scan_id, status=StatusScan.coletando)

        if req.modo is ModoScan.demo:
            caminho = BASE_DIR / "sample_data" / "sample_findings.json"
            achados = json.loads(caminho.read_text(encoding="utf-8"))
        elif req.modo is ModoScan.defectdojo:
            achados = coletar_via_defectdojo(req.path, dast_url=req.dast_url)
        else:
            achados = coletar_achados(req.path, dast_url=req.dast_url)

        _atualizar(
            scan_id,
            status=StatusScan.analisando,
            progresso={"analisados": 0, "total": len(achados)},
        )

        contexto = {
            "exposto_internet": req.exposto_internet,
            "dados_sensiveis": req.dados_sensiveis,
            "ambiente": "producao" if req.exposto_internet else "desenvolvimento",
        }

        def _progresso(analisados: int, total: int) -> None:
            _atualizar(scan_id, progresso={"analisados": analisados, "total": total})

        priorizados = processar_com_agentes(achados, contexto, on_progress=_progresso)

        _atualizar(
            scan_id,
            status=StatusScan.concluido,
            concluido_em=_agora(),
            achados=priorizados,
            total_achados=len(priorizados),
            por_prioridade=_contar_por_prioridade(priorizados),
        )
        _gravar_em_disco(scan_id)

        if req.enviar_wazuh:
            try:
                from integrations.wazuh_forwarder import enviar_para_wazuh
                enviar_para_wazuh(priorizados)
            except Exception as e:
                # Falha de integração não invalida o scan — mesmo critério do CLI
                print(f"[wazuh] Falha ao enviar: {e}")

    except Exception:
        _atualizar(
            scan_id,
            status=StatusScan.erro,
            concluido_em=_agora(),
            erro=traceback.format_exc(limit=3),
        )
        _gravar_em_disco(scan_id)


# ─────────────────────────────────────────────────────────────
#  Aplicação
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Recupera scans de execuções anteriores ao subir o servidor."""
    _carregar_scans_do_disco()
    yield


app = FastAPI(
    title="ASPM com IA",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "Agrega achados de Bandit (SAST), Trivy (SCA) e OWASP ZAP (DAST), "
        "normaliza num schema único e prioriza com três agentes de IA, "
        "ancorados no CVSS por uma trava de ±25 pontos."
    ),
)

# O front-end roda em outra porta durante o desenvolvimento.
# Em produção, troque por a lista de origens reais.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.get("/health", tags=["sistema"])
def health() -> dict[str, Any]:
    """Diz se o serviço está de pé e se a chave de IA está configurada."""
    provider, variavel, configurada = _status_chave_ia()
    return {
        "status": "ok",
        "provider_ia": provider,
        "chave_configurada": configurada,
        "variavel_esperada": variavel,
        "scans_em_memoria": len(_scans),
    }


@app.post("/scans", response_model=ResumoScan, status_code=202, tags=["scans"])
def criar_scan(req: NovoScan, tarefas: BackgroundTasks) -> ResumoScan:
    """
    Dispara um escaneamento e devolve na hora o `scan_id`.

    O processamento roda em segundo plano — acompanhe por GET /scans/{scan_id}.
    """
    provider, variavel, configurada = _status_chave_ia()
    if not configurada:
        raise HTTPException(
            status_code=503,
            detail=f"Variável {variavel} não configurada. Preencha o arquivo .env "
                    f"(ou troque para AI_PROVIDER=ollama para rodar sem chave).",
        )

    if req.modo is not ModoScan.demo and not Path(req.path).exists():
        raise HTTPException(status_code=400, detail=f"Caminho não encontrado: {req.path}")

    scan_id = uuid.uuid4().hex[:12]
    with _lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "status": StatusScan.na_fila,
            "modo": req.modo,
            "criado_em": _agora(),
            "concluido_em": None,
            "progresso": {"analisados": 0, "total": 0},
            "achados": [],
            "total_achados": 0,
            "por_prioridade": {},
            "erro": None,
        }

    tarefas.add_task(_executar_scan, scan_id, req)
    return _resumo(scan_id)


@app.get("/scans", response_model=list[ResumoScan], tags=["scans"])
def listar_scans() -> list[ResumoScan]:
    """Lista os escaneamentos, do mais recente para o mais antigo."""
    with _lock:
        ids = sorted(_scans, key=lambda i: _scans[i]["criado_em"], reverse=True)
    return [_resumo(i) for i in ids]


@app.get("/scans/{scan_id}", response_model=ResumoScan, tags=["scans"])
def obter_scan(scan_id: str) -> ResumoScan:
    """Status, progresso e contagem por prioridade de um escaneamento."""
    _exigir_scan(scan_id)
    return _resumo(scan_id)


@app.get("/scans/{scan_id}/findings", response_model=list[Achado], tags=["achados"])
def listar_achados(
    scan_id: str,
    prioridade: list[str] | None = Query(
        default=None, description="Filtra por prioridade. Repetível: ?prioridade=CRITICA&prioridade=ALTA"
    ),
    ferramenta: str | None = Query(default=None, description="bandit, trivy ou dast"),
    score_min: int | None = Query(default=None, ge=0, le=100),
    busca: str | None = Query(default=None, description="Texto livre em título e descrição"),
) -> list[Achado]:
    """
    Achados do escaneamento, já ordenados por score (maior primeiro).

    É este endpoint que alimenta a tabela do front-end.
    """
    scan = _exigir_scan(scan_id)
    achados = scan.get("achados", [])

    if prioridade:
        alvos = {p.upper() for p in prioridade}
        achados = [a for a in achados if (a.get("prioridade") or "").upper() in alvos]
    if ferramenta:
        achados = [a for a in achados if (a.get("ferramenta") or "").lower() == ferramenta.lower()]
    if score_min is not None:
        achados = [a for a in achados if (a.get("score_ia") or 0) >= score_min]
    if busca:
        termo = busca.lower()
        achados = [
            a for a in achados
            if termo in (a.get("titulo") or "").lower()
            or termo in (a.get("descricao") or "").lower()
        ]

    return [Achado(**a) for a in achados]


@app.get("/scans/{scan_id}/findings/{finding_id}", response_model=Achado, tags=["achados"])
def obter_achado(scan_id: str, finding_id: str) -> Achado:
    """Um achado específico, com explicação e remediação escritas pela IA."""
    scan = _exigir_scan(scan_id)
    for achado in scan.get("achados", []):
        if achado.get("id") == finding_id:
            return Achado(**achado)
    raise HTTPException(status_code=404, detail=f"Achado '{finding_id}' não encontrado.")


@app.delete("/scans/{scan_id}", status_code=204, tags=["scans"])
def remover_scan(scan_id: str) -> None:
    """Remove o escaneamento da memória e o arquivo de resultado."""
    _exigir_scan(scan_id)
    with _lock:
        _scans.pop(scan_id, None)
    (RESULTADOS_DIR / f"{scan_id}.json").unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────
#  Auxiliares
# ─────────────────────────────────────────────────────────────

def _exigir_scan(scan_id: str) -> dict[str, Any]:
    with _lock:
        scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' não encontrado.")
    return scan


def _resumo(scan_id: str) -> ResumoScan:
    with _lock:
        s = _scans[scan_id]
        return ResumoScan(
            scan_id=s["scan_id"],
            status=s["status"],
            modo=s["modo"],
            criado_em=s["criado_em"],
            concluido_em=s.get("concluido_em"),
            progresso=Progresso(**s.get("progresso", {})),
            total_achados=s.get("total_achados", 0),
            por_prioridade=s.get("por_prioridade", {}),
            erro=s.get("erro"),
        )


# ─────────────────────────────────────────────────────────────
#  Interface web
#
#  Servida pela própria API, de propósito: uma origem só, sem CORS
#  no caminho e um único comando para subir tudo. Precisa ficar no
#  fim do arquivo — as rotas declaradas acima têm precedência sobre
#  este mount na raiz.
# ─────────────────────────────────────────────────────────────

_WEB_DIR = BASE_DIR / "web"
if _WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")
