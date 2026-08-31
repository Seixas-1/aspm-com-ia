"""
Enriquecimento - NVD (National Vulnerability Database)
Consulta a API pública e gratuita do NVD para obter score CVSS
e descrição oficial de um CVE.

API gratuita, sem necessidade de chave (mas com chave o rate-limit sobe
de 5 para 50 requisições / 30s): https://nvd.nist.gov/developers/request-an-api-key
"""
import os
import time
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cve_details(cve_id: str) -> dict | None:
    """Busca detalhes (CVSS, descrição) de um CVE específico, ex: 'CVE-2023-12345'."""
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(
            NVD_BASE_URL, params={"cveId": cve_id}, headers=headers, timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[nvd] Erro ao consultar {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    metrics = cve.get("metrics", {})

    cvss_score = None
    for versao in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if versao in metrics:
            cvss_score = metrics[versao][0]["cvssData"]["baseScore"]
            break

    descricao = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
    )

    # Sem chave de API, respeite o rate limit público (5 req / 30s)
    if not api_key:
        time.sleep(6)

    return {"cve_id": cve_id, "cvss": cvss_score, "descricao": descricao}


if __name__ == "__main__":
    print(get_cve_details("CVE-2021-44228"))  # exemplo: Log4Shell
