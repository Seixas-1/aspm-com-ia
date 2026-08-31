"""
Dashboard Final (slide 3/7 - último estágio do fluxo)
Interface web em Streamlit que exibe a fila de vulnerabilidades
priorizadas pela IA, igual ao mockup do slide 5.

Rodar: streamlit run dashboard.py
"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ASPM com IA — Tomahawks", layout="wide")

CORES_PRIORIDADE = {
    "CRITICA": "🔴",
    "ALTA": "🟠",
    "MEDIA": "🔵",
    "BAIXA": "🟢",
}

st.title("🛡️ ASPM com IA — Fila de Priorização de Riscos")
st.caption("Challenge Pride 2026 · Tomahawks · FIAP Paulista")

caminho_arquivo = st.sidebar.text_input("Arquivo de resultado (JSON)", value="resultado.json")

if not Path(caminho_arquivo).exists():
    st.warning(
        f"Arquivo '{caminho_arquivo}' não encontrado. "
        "Rode antes: `python orchestrator.py --demo` para gerar dados de teste."
    )
    st.stop()

dados = json.loads(Path(caminho_arquivo).read_text(encoding="utf-8"))
df = pd.DataFrame(dados)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total de achados", len(df))
col2.metric("Críticas", int((df["prioridade"] == "CRITICA").sum()))
col3.metric("Altas", int((df["prioridade"] == "ALTA").sum()))
col4.metric("Score médio", round(df["score_ia"].mean(), 1) if len(df) else 0)

st.divider()

df_exibicao = df.copy()
df_exibicao["prioridade"] = df_exibicao["prioridade"].apply(
    lambda p: f"{CORES_PRIORIDADE.get(p, '')} {p}"
)

st.dataframe(
    df_exibicao[["titulo", "ferramenta", "cvss", "score_ia", "prioridade"]].rename(
        columns={
            "titulo": "Vulnerabilidade",
            "ferramenta": "Ferramenta",
            "cvss": "CVSS",
            "score_ia": "Score IA",
            "prioridade": "Prioridade",
        }
    ),
    use_container_width=True,
    hide_index=True,
)

st.divider()
st.subheader("Detalhamento por vulnerabilidade")

for _, row in df.iterrows():
    emoji = CORES_PRIORIDADE.get(row["prioridade"], "")
    with st.expander(f"{emoji} [{row['prioridade']}] {row['titulo']}"):
        st.markdown(f"**Arquivo/Alvo:** `{row.get('arquivo', 'N/A')}`")
        if row.get("cve"):
            st.markdown(f"**CVE:** {row['cve']}")
        st.markdown(f"**Score IA:** {row['score_ia']}/100 (CVSS base: {row['cvss']})")
        st.markdown(f"**Justificativa do risco:** {row.get('justificativa_risco', '')}")
        st.markdown("**🧠 Explicação da IA:**")
        st.info(row.get("explicacao_ia", ""))
        st.markdown("**🔧 Sugestão de correção:**")
        st.success(row.get("remediacao_ia", ""))
