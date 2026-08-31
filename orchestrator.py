"""
Orquestrador Central
Coordena o fluxo completo: Descoberta -> Scanners -> Normalização ->
Agentes de IA -> Priorização -> Saída (+ opcionalmente -> Wazuh SIEM)

Uso:
    python orchestrator.py --path ./meu_projeto
    python orchestrator.py --demo        (usa dados de exemplo, sem precisar rodar scanners)
    python orchestrator.py --demo --wazuh   (também envia os achados como alertas ao Wazuh)
    python orchestrator.py --path ./meu_projeto --defectdojo   (usa o DefectDojo p/ ingestão/dedup)
"""
import argparse
import json
import os
from pathlib import Path
from dotenv import load_dotenv

from scanners.bandit_scanner import run_bandit
from scanners.trivy_scanner import run_trivy_fs
from normalizer import (
    normalize_bandit, normalize_trivy, normalize_dast, normalize_defectdojo,
    merge_and_deduplicate,
)
from agents import RiskAgent, ExplanationAgent, RemediationAgent

load_dotenv()

SCORE_MINIMO_PARA_ANALISE_IA_COMPLETA = 35  # abaixo disso, poupa chamadas de IA


def coletar_via_defectdojo(target_path: str, dast_url: str | None = None) -> list[dict]:
    """
    Roda os scanners salvando o relatório BRUTO de cada um, envia pro
    DefectDojo (que faz o parsing e a deduplicação nativamente) e devolve
    a lista já normalizada, pronta pros Agentes de IA.
    """
    from integrations.defectdojo_client import importar_scan, listar_findings

    os.makedirs("tmp_scans", exist_ok=True)
    achados_dd: list[dict] = []

    print("[1/3] Bandit (SAST) -> relatório bruto -> DefectDojo...")
    run_bandit(target_path, salvar_bruto_em="tmp_scans/bandit_raw.json")
    resposta = importar_scan("tmp_scans/bandit_raw.json", "Bandit Scan")
    achados_dd += normalize_defectdojo(listar_findings(resposta["test"]), "bandit")

    print("[2/3] Trivy (SCA) -> relatório bruto -> DefectDojo...")
    try:
        run_trivy_fs(target_path, salvar_bruto_em="tmp_scans/trivy_raw.json")
        resposta = importar_scan("tmp_scans/trivy_raw.json", "Trivy Scan")
        achados_dd += normalize_defectdojo(listar_findings(resposta["test"]), "trivy")
    except FileNotFoundError:
        print("  Trivy não encontrado no PATH — pulando.")

    if dast_url:
        print("[3/3] OWASP ZAP (DAST) -> relatório bruto -> DefectDojo...")
        try:
            from scanners.dast_scanner import run_zap_scan, salvar_relatorio_zap
            run_zap_scan(dast_url)
            salvar_relatorio_zap("tmp_scans/zap_raw.json")
            resposta = importar_scan("tmp_scans/zap_raw.json", "ZAP Scan")
            achados_dd += normalize_defectdojo(listar_findings(resposta["test"]), "dast")
        except Exception as e:
            print(f"  DAST via DefectDojo falhou: {e}")
    else:
        print("[3/3] Nenhuma --dast-url informada — pulando etapa de DAST.")

    print(f"[defectdojo] Total de achados (já deduplicados pelo DefectDojo): {len(achados_dd)}")
    return achados_dd


def coletar_achados(target_path: str, dast_url: str | None = None) -> list[dict]:
    print(f"[1/4] Coletando com Bandit (SAST) em '{target_path}'...")
    brutos_bandit = run_bandit(target_path)

    print(f"[2/4] Coletando com Trivy (SCA) em '{target_path}'...")
    try:
        brutos_trivy = run_trivy_fs(target_path)
    except FileNotFoundError:
        print("  Trivy não encontrado no PATH — pulando (instale para SCA completo).")
        brutos_trivy = []

    brutos_dast = []
    if dast_url:
        print(f"[3/4] Coletando com OWASP ZAP (DAST) contra '{dast_url}'...")
        try:
            from scanners.dast_scanner import run_zap_scan
            brutos_dast = run_zap_scan(dast_url)
        except Exception as e:
            print(f"  DAST falhou (ZAP está rodando? veja scanners/dast_scanner.py): {e}")
    else:
        print("[3/4] Nenhuma --dast-url informada — pulando etapa de DAST.")

    print("[4/4] Normalizando e removendo duplicados...")
    normalizados = merge_and_deduplicate(
        normalize_bandit(brutos_bandit),
        normalize_trivy(brutos_trivy),
        normalize_dast(brutos_dast),
    )
    return normalizados


def processar_com_agentes(achados: list[dict], contexto_ativo: dict | None = None) -> list[dict]:
    risk_agent = RiskAgent()
    explanation_agent = ExplanationAgent()
    remediation_agent = RemediationAgent()

    resultado = []
    total = len(achados)

    for i, vuln in enumerate(achados, start=1):
        print(f"  Analisando {i}/{total}: {vuln['titulo'][:60]}...")

        risco = risk_agent.avaliar(vuln, contexto_ativo)
        vuln["score_ia"] = risco.get("score")
        vuln["prioridade"] = risco.get("prioridade")
        vuln["justificativa_risco"] = risco.get("justificativa")

        # Otimização de custo: só gera explicação/remediação detalhada
        # para o que realmente importa (MEDIA pra cima)
        if (risco.get("score") or 0) >= SCORE_MINIMO_PARA_ANALISE_IA_COMPLETA:
            vuln["explicacao_ia"] = explanation_agent.explicar(vuln)
            vuln["remediacao_ia"] = remediation_agent.sugerir_correcao(vuln)
        else:
            vuln["explicacao_ia"] = "Risco baixo — análise detalhada não priorizada."
            vuln["remediacao_ia"] = "N/A"

        resultado.append(vuln)

    resultado.sort(key=lambda v: v.get("score_ia") or 0, reverse=True)
    return resultado


def main():
    parser = argparse.ArgumentParser(description="Orquestrador ASPM com IA")
    parser.add_argument("--path", default=".", help="Diretório do código a escanear")
    parser.add_argument("--demo", action="store_true", help="Usa dados de exemplo (sample_data/)")
    parser.add_argument("--out", default="resultado.json", help="Arquivo de saída")
    parser.add_argument("--exposto-internet", action="store_true")
    parser.add_argument("--dados-sensiveis", action="store_true")
    parser.add_argument(
        "--dast-url", default=None,
        help="URL da app rodando para escanear com DAST (ex: http://localhost:5000)"
    )
    parser.add_argument(
        "--wazuh", action="store_true",
        help="Envia os achados priorizados (score >= 40) como alertas para o Wazuh SIEM"
    )
    parser.add_argument(
        "--defectdojo", action="store_true",
        help="Usa o DefectDojo para ingestão/dedup dos scanners, em vez do normalizer próprio"
    )
    args = parser.parse_args()

    provider = os.getenv("AI_PROVIDER", "gemini").lower()
    chave_necessaria = "GEMINI_API_KEY" if provider == "gemini" else "ANTHROPIC_API_KEY"
    if not os.getenv(chave_necessaria):
        print(f"AVISO: variável {chave_necessaria} não definida. Configure o arquivo .env")
        return

    if args.demo:
        achados = json.loads(Path("sample_data/sample_findings.json").read_text(encoding="utf-8"))
        print(f"[demo] Carregados {len(achados)} achados de exemplo.")
    elif args.defectdojo:
        achados = coletar_via_defectdojo(args.path, dast_url=args.dast_url)
    else:
        achados = coletar_achados(args.path, dast_url=args.dast_url)
        print(f"Total de achados normalizados: {len(achados)}")

    contexto = {
        "exposto_internet": args.exposto_internet,
        "dados_sensiveis": args.dados_sensiveis,
        "ambiente": "producao" if args.exposto_internet else "desenvolvimento",
    }

    print("\nAnalisando com os Agentes de IA (Risk / Explanation / Remediation)...")
    priorizados = processar_com_agentes(achados, contexto)

    Path(args.out).write_text(
        json.dumps(priorizados, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\nConcluído! Resultado salvo em '{args.out}'.")

    if args.defectdojo:
        try:
            from integrations.defectdojo_client import anotar_finding_com_ia
            for achado in priorizados:
                if achado.get("defectdojo_finding_id"):
                    anotar_finding_com_ia(achado["defectdojo_finding_id"], achado)
            print("[defectdojo] Achados anotados de volta no DefectDojo (nota + tag).")
        except Exception as e:
            print(f"[defectdojo] Falha ao anotar de volta (não interrompe o restante): {e}")

    if args.wazuh:
        try:
            from integrations.wazuh_forwarder import enviar_para_wazuh
            enviar_para_wazuh(priorizados)
        except Exception as e:
            print(f"[wazuh] Falha ao enviar para o Wazuh (não interrompe o restante): {e}")

    print("Rode 'streamlit run dashboard.py' para visualizar.")


if __name__ == "__main__":
    main()
