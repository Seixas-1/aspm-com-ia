"""
Agente de Correlação de Dados
Converte os formatos distintos do Bandit, Trivy, ZAP e DefectDojo em um
schema único, para que os Agentes de IA processem tudo da mesma forma.

Schema normalizado (dict):
{
  "id": str,
  "ferramenta": "bandit" | "trivy" | "dast",
  "titulo": str,
  "descricao": str,
  "arquivo": str,
  "linha": int | None,
  "cve": str | None,
  "cvss": float,
  "severidade_original": str,
}
"""
import hashlib


def _make_id(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def normalize_bandit(achados_brutos: list[dict]) -> list[dict]:
    normalizados = []
    severidade_para_cvss = {"HIGH": 8.5, "MEDIUM": 5.5, "LOW": 2.5}

    for item in achados_brutos:
        normalizados.append({
            "id": _make_id("bandit", item.get("filename", ""), item.get("line_number", "")),
            "ferramenta": "bandit",
            "titulo": item.get("issue_text", "Vulnerabilidade em código"),
            "descricao": item.get("issue_text", ""),
            "arquivo": item.get("filename"),
            "linha": item.get("line_number"),
            "cve": None,
            "cvss": severidade_para_cvss.get(item.get("issue_severity", "LOW"), 2.5),
            "severidade_original": item.get("issue_severity"),
        })
    return normalizados


def normalize_trivy(achados_brutos: list[dict]) -> list[dict]:
    normalizados = []

    for item in achados_brutos:
        cvss = None
        cvss_data = item.get("CVSS", {})
        for fonte in cvss_data.values():
            if "V3Score" in fonte:
                cvss = fonte["V3Score"]
                break

        normalizados.append({
            "id": _make_id("trivy", item.get("VulnerabilityID", ""), item.get("PkgName", "")),
            "ferramenta": "trivy",
            "titulo": f"{item.get('PkgName')} - {item.get('VulnerabilityID')}",
            "descricao": item.get("Description", "")[:500],
            "arquivo": item.get("_target"),
            "linha": None,
            "cve": item.get("VulnerabilityID"),
            "cvss": cvss or 5.0,
            "severidade_original": item.get("Severity"),
        })
    return normalizados


def normalize_dast(alertas_zap: list[dict]) -> list[dict]:
    """Converte alertas brutos do OWASP ZAP para o schema normalizado."""
    normalizados = []
    risco_para_cvss = {"High": 8.0, "Medium": 5.5, "Low": 3.0, "Informational": 1.0}

    for item in alertas_zap:
        risco = item.get("risk", "Low")
        normalizados.append({
            "id": _make_id("dast", item.get("alertRef", ""), item.get("url", "")),
            "ferramenta": "dast",
            "titulo": item.get("alert", "Achado DAST"),
            "descricao": item.get("description", "")[:500],
            "arquivo": item.get("url"),  # no DAST, o "arquivo" é a URL testada
            "linha": None,
            "cve": item.get("cweid") and f"CWE-{item['cweid']}",
            "cvss": risco_para_cvss.get(risco, 3.0),
            "severidade_original": risco,
        })
    return normalizados


def normalize_defectdojo(findings_dd: list[dict], ferramenta_origem: str) -> list[dict]:
    """
    Converte Findings retornados pela API do DefectDojo (já deduplicados
    por ele) para o nosso schema comum, pra que os Agentes de IA processem
    exatamente como processariam achados dos scanners locais.
    """
    normalizados = []
    severidade_para_cvss = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5, "Info": 1.0}

    for f in findings_dd:
        cvss = f.get("cvssv3_score") or severidade_para_cvss.get(f.get("severity"), 5.0)
        normalizados.append({
            "id": f"dd-{f.get('id')}",
            "defectdojo_finding_id": f.get("id"),
            "ferramenta": ferramenta_origem,
            "titulo": f.get("title", "Achado DefectDojo"),
            "descricao": (f.get("description") or "")[:500],
            "arquivo": f.get("file_path") or f.get("component_name"),
            "linha": f.get("line"),
            "cve": f.get("cve"),
            "cvss": cvss,
            "severidade_original": f.get("severity"),
        })
    return normalizados


def merge_and_deduplicate(*listas_normalizadas: list[dict]) -> list[dict]:
    """Junta achados de várias ferramentas e remove duplicados pelo id."""
    vistos = {}
    for lista in listas_normalizadas:
        for item in lista:
            vistos[item["id"]] = item
    return list(vistos.values())
