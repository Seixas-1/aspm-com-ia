"""
Teste rápido e isolado do provedor de IA (Gemini, Ollama ou Anthropic).
Roda sem executar scanners nem o projeto inteiro.

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


def testar_ollama():
    import requests
    url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    modelo = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    # 1) O servidor do Ollama está de pé?
    try:
        tags = requests.get(f"{url}/api/tags", timeout=10)
        tags.raise_for_status()
    except requests.RequestException:
        print(f"❌ Não consegui falar com o Ollama em {url}")
        print("   Ele está rodando? Tente: sudo systemctl start ollama")
        return False
    print(f"✅ Servidor do Ollama respondendo em {url}")

    # 2) O modelo configurado já foi baixado?
    baixados = [m.get("name", "") for m in tags.json().get("models", [])]
    if modelo not in baixados and f"{modelo}:latest" not in baixados:
        print(f"❌ O modelo '{modelo}' não foi baixado. Rode: ollama pull {modelo}")
        print(f"   Modelos disponíveis aqui: {baixados or 'nenhum'}")
        return False
    print(f"✅ Modelo '{modelo}' encontrado")

    # 3) Ele consegue responder? (a primeira chamada carrega o modelo na RAM e demora)
    print("   Testando uma resposta (a primeira vez pode levar de 10s a 1 min)...")
    try:
        resp = requests.post(
            f"{url}/api/chat",
            json={
                "model": modelo,
                "messages": [{"role": "user", "content": "Responda apenas com a palavra: OK"}],
                "stream": False,
                "options": {"num_predict": 10},
            },
            timeout=int(os.getenv("OLLAMA_TIMEOUT", "300")),
        )
        resp.raise_for_status()
        print(f"✅ Ollama respondeu: {resp.json()['message']['content'].strip()}")
        return True
    except Exception as e:
        print(f"❌ Erro ao gerar resposta no Ollama: {e}")
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

    testes = {"gemini": testar_gemini, "ollama": testar_ollama, "anthropic": testar_anthropic}
    if provider not in testes:
        print(f"❌ AI_PROVIDER '{provider}' desconhecido. Use gemini, ollama ou anthropic.")
        raise SystemExit(1)

    ok = testes[provider]()

    if ok:
        print("\nTudo certo! Pode rodar: python orchestrator.py --demo")
    else:
        print("\nCorrija o que apareceu acima e rode este script de novo antes de seguir.")
