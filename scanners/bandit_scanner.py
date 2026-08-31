"""
Agente de Coleta - Bandit (SAST)
Executa o Bandit sobre um diretório de código Python e retorna
os achados em formato bruto (JSON), prontos para o normalizador.

Instalação: pip install bandit
Documentação: https://bandit.readthedocs.io
"""
import json
import subprocess
from pathlib import Path


def run_bandit(target_path: str, salvar_bruto_em: str | None = None) -> list[dict]:
    """
    Executa o Bandit recursivamente em `target_path` e devolve
    a lista de resultados brutos (um dict por vulnerabilidade encontrada).

    Se `salvar_bruto_em` for passado, salva o JSON COMPLETO (com as chaves
    "results", "errors" e "metrics") nesse caminho — necessário para
    integrações que exigem o formato original do Bandit, como o DefectDojo.
    """
    if not Path(target_path).exists():
        raise FileNotFoundError(f"Caminho não encontrado: {target_path}")

    cmd = ["bandit", "-r", target_path, "-f", "json"]

    # Bandit retorna exit code != 0 quando encontra issues -> não é erro nosso
    result = subprocess.run(cmd, capture_output=True, text=True)

    if not result.stdout.strip():
        print(f"[bandit] Nenhuma saída recebida. stderr: {result.stderr}")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[bandit] Falha ao decodificar JSON de saída.")
        return []

    if salvar_bruto_em:
        Path(salvar_bruto_em).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        print(f"[bandit] Relatório bruto salvo em {salvar_bruto_em}")

    return data.get("results", [])


if __name__ == "__main__":
    import sys
    alvo = sys.argv[1] if len(sys.argv) > 1 else "."
    achados = run_bandit(alvo)
    print(f"{len(achados)} achado(s) do Bandit em '{alvo}'")
    print(json.dumps(achados[:2], indent=2, ensure_ascii=False))
