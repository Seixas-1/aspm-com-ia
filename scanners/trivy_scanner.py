"""
Agente de Coleta - Trivy (SCA / Container Scanning)
Executa o Trivy sobre um diretório (dependências) ou uma imagem Docker
e retorna vulnerabilidades conhecidas (CVEs) de bibliotecas de terceiros.

Instalação (gratuita, binário único):
  Linux:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  Mac:    brew install trivy
  Windows: choco install trivy
Documentação: https://aquasecurity.github.io/trivy
"""
import json
import subprocess
from pathlib import Path


def run_trivy_fs(target_path: str, salvar_bruto_em: str | None = None) -> list[dict]:
    """Escaneia dependências (requirements.txt, package.json, etc.) em um diretório."""
    cmd = ["trivy", "fs", "--format", "json", "--scanners", "vuln", target_path]
    return _run_and_parse(cmd, salvar_bruto_em)


def run_trivy_image(image_name: str, salvar_bruto_em: str | None = None) -> list[dict]:
    """Escaneia uma imagem Docker (ex: 'python:3.11-slim')."""
    cmd = ["trivy", "image", "--format", "json", image_name]
    return _run_and_parse(cmd, salvar_bruto_em)


def _run_and_parse(cmd: list[str], salvar_bruto_em: str | None = None) -> list[dict]:
    result = subprocess.run(cmd, capture_output=True, text=True)

    if not result.stdout.strip():
        print(f"[trivy] Nenhuma saída recebida. stderr: {result.stderr}")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[trivy] Falha ao decodificar JSON de saída.")
        return []

    if salvar_bruto_em:
        Path(salvar_bruto_em).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        print(f"[trivy] Relatório bruto salvo em {salvar_bruto_em}")

    achados = []
    for resultado in data.get("Results", []):
        for vuln in resultado.get("Vulnerabilities", []) or []:
            vuln["_target"] = resultado.get("Target")
            achados.append(vuln)
    return achados


if __name__ == "__main__":
    import sys
    alvo = sys.argv[1] if len(sys.argv) > 1 else "."
    achados = run_trivy_fs(alvo)
    print(f"{len(achados)} vulnerabilidade(s) de dependência encontradas")
