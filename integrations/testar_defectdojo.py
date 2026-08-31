"""
Teste rápido e isolado da integração com o DefectDojo.
Roda o Bandit contra a própria app de demo (rápido, sempre acha algo),
importa o relatório pro DefectDojo, e confere se os Findings voltaram.

Uso:
    python integrations/testar_defectdojo.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from scanners.bandit_scanner import run_bandit
from integrations.defectdojo_client import importar_scan, listar_findings


def main():
    print("1) Rodando Bandit na app de demo (demo_app/)...")
    os.makedirs("tmp_scans", exist_ok=True)
    run_bandit("demo_app", salvar_bruto_em="tmp_scans/teste_bandit.json")

    print("2) Importando o relatório pro DefectDojo...")
    resposta = importar_scan(
        "tmp_scans/teste_bandit.json", "Bandit Scan", engagement_name="Teste de Integracao"
    )
    test_id = resposta.get("test")
    if not test_id:
        print("❌ O import não retornou um test id. Resposta completa:")
        print(resposta)
        return

    print(f"3) Listando Findings do test {test_id}...")
    findings = listar_findings(test_id)

    if not findings:
        print("⚠️  Import funcionou, mas vieram 0 Findings.")
        print("   (Pode ser que o Bandit não tenha achado nada em demo_app/ — confira no painel.)")
        return

    print(f"✅ {len(findings)} Finding(s) retornado(s) pelo DefectDojo:")
    for f in findings[:5]:
        print(f"   - [{f.get('severity')}] {f.get('title')}")

    print("\nTudo certo! Pode rodar o pipeline completo com --defectdojo.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Erro: {e}")
        print("Confira: o DefectDojo está rodando ('docker compose ps' na pasta dele)?")
        print("O DEFECTDOJO_API_TOKEN no .env está certo e sem espaços extras?")
