"""
Integração com Wazuh (SIEM)
Escreve os achados priorizados como eventos JSON em um arquivo de log
monitorado pelo Agente do Wazuh, para que virem alertas/incidentes reais
no painel do Wazuh — fechando o ciclo "achado técnico -> alerta operacional".

Como funciona, de ponta a ponta:
  orchestrator.py
      -> grava 1 linha JSON por achado neste arquivo (LOG_PATH)
      -> Wazuh AGENT (rodando nesta máquina) monitora esse arquivo via <localfile>
      -> Wazuh MANAGER decodifica com o decoder json nativo
      -> local_rules.xml (arquivo wazuh_rules.xml deste projeto) classifica
         por "prioridade" e define o nível/severidade do alerta
      -> aparece no Wazuh Dashboard como um alerta de verdade

Pré-requisitos (ver README, seção Wazuh):
  1. Wazuh Agent instalado e rodando nesta máquina, já enrolado no seu Manager
  2. Bloco <localfile> adicionado no ossec.conf do AGENTE apontando pro LOG_PATH
  3. Conteúdo de wazuh_rules.xml colado no local_rules.xml do MANAGER
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Caminho do arquivo de log que o Agente do Wazuh vai monitorar.
# Padrão: pasta pessoal do usuário (evita problema de permissão em /var/log).
# Pode ser sobrescrito via variável de ambiente WAZUH_LOG_PATH no .env.
LOG_PATH = Path(os.getenv("WAZUH_LOG_PATH", str(Path.home() / "aspm_wazuh_alerts.json")))

# Só envia pro SIEM achados a partir desse score, pra não gerar ruído com BAIXA
SCORE_MINIMO_PARA_ALERTA = 40  # alinhado com o piso da faixa MEDIA


def enviar_para_wazuh(achados_priorizados: list[dict]) -> int:
    """
    Grava cada achado (score >= SCORE_MINIMO_PARA_ALERTA) como uma linha
    JSON em LOG_PATH. Retorna quantos eventos foram escritos.
    """
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    enviados = 0
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        for achado in achados_priorizados:
            if (achado.get("score_ia") or 0) < SCORE_MINIMO_PARA_ALERTA:
                continue

            evento = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "origem": "aspm-ia-tomahawks",
                "id": achado.get("id"),
                "ferramenta": achado.get("ferramenta"),
                "titulo": achado.get("titulo"),
                "arquivo": achado.get("arquivo"),
                "cve": achado.get("cve"),
                "cvss": achado.get("cvss"),
                "score_ia": achado.get("score_ia"),
                "prioridade": achado.get("prioridade"),
                "justificativa": achado.get("justificativa_risco"),
                "remediacao": achado.get("remediacao_ia"),
            }
            f.write(json.dumps(evento, ensure_ascii=False) + "\n")
            enviados += 1

    if enviados:
        print(f"[wazuh] {enviados} achado(s) escrito(s) em {LOG_PATH}")
        print("[wazuh] Confira no Wazuh Dashboard em Módulos > Eventos de segurança")
    else:
        print(f"[wazuh] Nenhum achado com score >= {SCORE_MINIMO_PARA_ALERTA}, nada enviado.")
    return enviados


if __name__ == "__main__":
    # Teste manual rápido: gera 1 evento de exemplo e mostra o caminho usado
    exemplo = [{
        "id": "teste001", "ferramenta": "dast", "titulo": "Teste de integração Wazuh",
        "arquivo": "http://localhost:5000/teste", "cve": None, "cvss": 9.0,
        "score_ia": 95, "prioridade": "CRITICA",
        "justificativa_risco": "Evento de teste manual.", "remediacao_ia": "N/A",
    }]
    print(f"Escrevendo evento de teste em: {LOG_PATH}")
    enviar_para_wazuh(exemplo)
