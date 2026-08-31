"""
Agente de Coleta - OWASP ZAP (DAST)
Ataca uma aplicação REALMENTE RODANDO e observa o comportamento,
encontrando falhas que só existem em runtime (XSS refletido, headers
de segurança ausentes, etc.) — diferente de Bandit/Trivy, que analisam
código e dependências sem executar nada.

Pré-requisitos (gratuitos):
  1. Baixe e instale o OWASP ZAP: https://www.zaproxy.org/download/
  2. Inicie em modo daemon com a API habilitada (porta 8090, não 8080 —
     8080 já é usada pelo painel web do DefectDojo neste projeto):
       zap.sh -daemon -port 8090 -config api.disablekey=true      (Linux/Mac)
       zap.bat -daemon -port 8090 -config api.disablekey=true     (Windows)
     (Ou abra o ZAP Desktop normalmente — a API já roda junto por padrão.)
  3. pip install python-owasp-zap-v2.4

Documentação da API: https://www.zaproxy.org/docs/api/
"""
import os
import time
from zapv2 import ZAPv2

# Porta configurável via .env (ZAP_PROXY), padrão 8090 pra não colidir com o DefectDojo (8080)
ZAP_PROXY_PADRAO = os.getenv("ZAP_PROXY", "http://localhost:8090")

RISCO_PARA_CVSS_ESTIMADO = {
    "High": 8.0,
    "Medium": 5.5,
    "Low": 3.0,
    "Informational": 1.0,
}


def run_zap_scan(
    target_url: str,
    zap_proxy: str = ZAP_PROXY_PADRAO,
    api_key: str | None = None,
    spider_primeiro: bool = True,
    timeout_segundos: int = 180,
) -> list[dict]:
    """
    Executa um scan DAST completo contra `target_url` usando um ZAP
    já em execução (daemon ou desktop) e retorna os alertas brutos.
    """
    zap = ZAPv2(apikey=api_key, proxies={"http": zap_proxy, "https": zap_proxy})

    print(f"[zap] Conectando ao ZAP em {zap_proxy}...")

    if spider_primeiro:
        print(f"[zap] Rastreando (spider) {target_url}...")
        scan_id = zap.spider.scan(target_url)
        inicio = time.time()
        while int(zap.spider.status(scan_id)) < 100:
            if time.time() - inicio > timeout_segundos:
                print("[zap] Timeout no spider, seguindo para o scan ativo.")
                break
            time.sleep(1)

    print(f"[zap] Iniciando scan ativo (ataques reais) contra {target_url}...")
    scan_id = zap.ascan.scan(target_url)
    inicio = time.time()
    while int(zap.ascan.status(scan_id)) < 100:
        progresso = zap.ascan.status(scan_id)
        print(f"  progresso: {progresso}%")
        if time.time() - inicio > timeout_segundos:
            print("[zap] Timeout no scan ativo, coletando alertas parciais.")
            break
        time.sleep(2)

    alertas = zap.core.alerts(baseurl=target_url)
    print(f"[zap] Scan concluído: {len(alertas)} alerta(s) encontrado(s).")
    return alertas


def salvar_relatorio_zap(
    caminho_arquivo: str,
    zap_proxy: str = ZAP_PROXY_PADRAO,
    api_key: str | None = None,
) -> None:
    """
    Salva o relatório OFICIAL do ZAP em JSON (via zap.core.jsonreport()),
    no formato completo que integrações como o DefectDojo esperam —
    diferente da lista simplificada de zap.core.alerts() usada em run_zap_scan().
    Chame isso DEPOIS de um scan já ter rodado (via run_zap_scan).
    """
    import json as json_lib
    from pathlib import Path

    zap = ZAPv2(apikey=api_key, proxies={"http": zap_proxy, "https": zap_proxy})
    relatorio = zap.core.jsonreport()
    Path(caminho_arquivo).write_text(relatorio, encoding="utf-8")
    print(f"[zap] Relatório completo salvo em {caminho_arquivo}")


if __name__ == "__main__":
    import sys
    import json

    alvo = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    achados = run_zap_scan(alvo)
    print(json.dumps(achados[:2], indent=2, ensure_ascii=False))
