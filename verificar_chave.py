"""
Teste rápido e isolado da chave da API (Gemini ou Anthropic).
Roda em segundos, sem precisar executar scanners nem o projeto inteiro.

Uso:
    python verificar_chave.py
"""
import os
from dotenv import load_dotenv

load_dotenv()


def testar_gemini():
    from google import genai
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "sua-chave-gemini-aqui":
        print("❌ GEMINI_API_KEY não está preenchida no .env")
        return False

    try:
        client = genai.Client(api_key=api_key)
        resposta = client.models.generate_content(
            model="gemini-3.1-flash-lite",
            contents="Responda apenas com a palavra: OK",
        )
        print(f"✅ Gemini respondeu: {resposta.text.strip()}")
        return True
    except Exception as e:
        print(f"❌ Erro ao chamar a API do Gemini: {e}")
        return False


def testar_anthropic():
    import anthropic
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("❌ ANTHROPIC_API_KEY não está preenchida no .env")
        return False

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resposta = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=10,
            messages=[{"role": "user", "content": "Responda apenas com a palavra: OK"}],
        )
        print(f"✅ Claude respondeu: {resposta.content[0].text.strip()}")
        return True
    except Exception as e:
        print(f"❌ Erro ao chamar a API da Anthropic: {e}")
        return False


if __name__ == "__main__":
    provider = os.getenv("AI_PROVIDER", "gemini").lower()
    print(f"Testando provedor configurado no .env: '{provider}'\n")

    ok = testar_gemini() if provider == "gemini" else testar_anthropic()

    if ok:
        print("\nTudo certo! Pode rodar: python orchestrator.py --demo")
    else:
        print("\nCorrija o .env e rode este script de novo antes de seguir.")
