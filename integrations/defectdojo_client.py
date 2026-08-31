"""
Integração com DefectDojo (projeto flagship da OWASP para gestão de
vulnerabilidades / ASPM).

Em vez de reinventar a ingestão e deduplicação (nosso normalizer.py faz
isso "na mão"), esta integração delega essa parte pro DefectDojo, que já
tem parsers nativos para Bandit, Trivy e ZAP. Nossos 3 Agentes de IA
continuam sendo o diferencial: eles leem os achados JÁ deduplicados pelo
DefectDojo e fazem o que ele não faz sozinho — pontuação contextual,
explicação em linguagem natural e sugestão de remediação.

Fluxo:
  scanners (relatório bruto) -> importar_scan() -> DefectDojo processa
  -> listar_findings() -> nossos Agentes de IA analisam
  -> anotar_finding_com_ia() escreve o resultado de volta no DefectDojo

Pré-requisitos:
  1. DefectDojo rodando (ver README, seção DefectDojo) — padrão: localhost:8080
  2. Token de API: no DefectDojo, clique no seu usuário (canto superior
     direito) > API v2 Key, copie o token
  3. No .env:
       DEFECTDOJO_URL=http://localhost:8080/api/v2
       DEFECTDOJO_API_TOKEN=seu-token-aqui
       DEFECTDOJO_PRODUCT_TYPE_NAME=Challenge Pride 2026
"""
import os
import requests

BASE_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080/api/v2")
TOKEN = os.getenv("DEFECTDOJO_API_TOKEN", "")
PRODUCT_NAME = os.getenv("DEFECTDOJO_PRODUCT_NAME", "ASPM com IA - Tomahawks")
PRODUCT_TYPE_NAME = os.getenv("DEFECTDOJO_PRODUCT_TYPE_NAME", "Challenge Pride 2026")

HEADERS = {"Authorization": f"Token {TOKEN}"}


def importar_scan(
    caminho_arquivo: str,
    scan_type: str,
    engagement_name: str = "Challenge Pride 2026",
) -> dict:
    """
    Envia um relatório BRUTO de scanner (o arquivo JSON original, não a
    lista já processada) pro DefectDojo via API de import.

    scan_type precisa ser um dos nomes reconhecidos pelo DefectDojo:
      'Bandit Scan', 'Trivy Scan', 'ZAP Scan'

    Cria Produto/Engagement automaticamente se não existirem
    (auto_create_context). Retorna a resposta da API — o campo "test"
    é o ID usado depois em listar_findings().
    """
    if not TOKEN:
        raise RuntimeError("DEFECTDOJO_API_TOKEN não definido no .env")

    with open(caminho_arquivo, "rb") as f:
        resp = requests.post(
            f"{BASE_URL}/import-scan/",
            headers=HEADERS,
            data={
                "scan_type": scan_type,
                "product_type_name": PRODUCT_TYPE_NAME,
                "product_name": PRODUCT_NAME,
                "engagement_name": engagement_name,
                "auto_create_context": "true",
                "minimum_severity": "Info",
                "active": "true",
                "verified": "true",
            },
            files={"file": f},
            timeout=60,
        )

    if not resp.ok:
        # Mostra a mensagem REAL de erro que o DefectDojo devolveu, em vez
        # de só "400 Bad Request" genérico — geralmente aponta o campo exato
        print(f"[defectdojo] Erro {resp.status_code} do DefectDojo: {resp.text}")
    resp.raise_for_status()

    resultado = resp.json()
    print(f"[defectdojo] Importado '{scan_type}' -> test id {resultado.get('test')}")
    return resultado


def listar_findings(test_id: int) -> list[dict]:
    """Busca todos os Findings de um Test específico já processado pelo DefectDojo."""
    achados = []
    url = f"{BASE_URL}/findings/?test={test_id}&limit=100"
    while url:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        pagina = resp.json()
        achados.extend(pagina.get("results", []))
        url = pagina.get("next")
    return achados


def anotar_finding_com_ia(finding_id: int, achado_ia: dict) -> None:
    """
    Escreve o resultado da análise de IA de volta no Finding do DefectDojo:
    uma nota com o texto completo (explicação + remediação) e uma tag
    resumida (ex: "ia-critica") pra facilitar filtro visual no painel.
    """
    nota = (
        "Análise da IA (ASPM com IA - Tomahawks)\n"
        f"Score: {achado_ia.get('score_ia')}/100 | Prioridade: {achado_ia.get('prioridade')}\n\n"
        f"Justificativa: {achado_ia.get('justificativa_risco')}\n\n"
        f"Explicação: {achado_ia.get('explicacao_ia')}\n\n"
        f"Remediação sugerida: {achado_ia.get('remediacao_ia')}"
    )
    try:
        requests.post(
            f"{BASE_URL}/findings/{finding_id}/notes/",
            headers=HEADERS,
            json={"entry": nota},
            timeout=30,
        ).raise_for_status()

        requests.patch(
            f"{BASE_URL}/findings/{finding_id}/",
            headers=HEADERS,
            json={"tags": [f"ia-{(achado_ia.get('prioridade') or '').lower()}"]},
            timeout=30,
        ).raise_for_status()
    except requests.RequestException as e:
        print(f"[defectdojo] Falha ao anotar finding {finding_id}: {e}")
