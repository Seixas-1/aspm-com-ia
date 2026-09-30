"""
Classe base para todos os agentes de IA.
Centraliza a chamada ao provedor de IA e a proteção contra prompt injection
(sanitização básica dos dados antes de irem para o prompt).

Provedor controlado pela variável de ambiente AI_PROVIDER no .env:
  - "gemini"    (padrão, GRATUITO na nuvem — Google AI Studio, sem cartão de crédito)
  - "ollama"    (GRATUITO e OFFLINE — modelo local rodando na sua própria máquina)
  - "anthropic" (pago — usa créditos da API Claude)
"""
import os
import json

from dotenv import load_dotenv

# Precisa rodar ANTES de ler AI_PROVIDER: este módulo é importado antes de o
# orchestrator chamar load_dotenv(), e sem isso o .env seria ignorado aqui.
load_dotenv()

PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()

GEMINI_MODEL_RISCO = "gemini-3.5-flash"        # mais raciocínio, RPM menor (5/min no free tier)
GEMINI_MODEL_TEXTO = "gemini-3.1-flash-lite"   # RPM maior (15/min), suficiente p/ explicação e remediação
ANTHROPIC_MODEL = "claude-sonnet-4-6"

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "300"))  # CPU é lenta: dá tempo de sobra


class BaseAgent:
    MODEL_GEMINI = GEMINI_MODEL_TEXTO  # cada agente pode sobrescrever isso

    def __init__(self):
        if PROVIDER == "gemini":
            from google import genai
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "GEMINI_API_KEY não definida no .env. "
                    "Gere uma gratuitamente em https://aistudio.google.com/apikey"
                )
            self._client = genai.Client(api_key=api_key)

        elif PROVIDER == "anthropic":
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError("ANTHROPIC_API_KEY não definida no .env.")
            self._client = anthropic.Anthropic(api_key=api_key)

        elif PROVIDER == "ollama":
            pass  # sem chave: roda localmente. A conexão é verificada na primeira chamada.

        else:
            raise ValueError(
                f"AI_PROVIDER desconhecido: '{PROVIDER}' (use 'gemini', 'ollama' ou 'anthropic')"
            )

    @staticmethod
    def sanitize(texto: str, max_len: int = 800) -> str:
        """
        Sanitização simples de entrada: corta tamanho e remove tentativas
        óbvias de prompt injection vindas de descrições de vulnerabilidades
        (que podem conter texto controlado por um atacante, ex: nome de pacote malicioso).
        """
        if not texto:
            return ""
        texto = texto.replace("```", "'''")
        for gatilho in ["ignore previous instructions", "ignore as instruções anteriores",
                         "system:", "you are now"]:
            texto = texto.replace(gatilho, "[removido]")
        return texto[:max_len]

    def _call_ia(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 500, json_mode: bool = False) -> str:
        """
        Chama o provedor de IA configurado. Mesma assinatura, motor intercambiável.
        json_mode=True pede resposta em JSON válido (usado pelo Ollama; os outros
        provedores já seguem o formato pelo prompt).
        """
        if PROVIDER == "gemini":
            import time
            from google.genai import types

            # Plano B: se o modelo principal estiver sobrecarregado, usa o modelo leve
            modelos = [self.MODEL_GEMINI]
            if self.MODEL_GEMINI != GEMINI_MODEL_TEXTO:
                modelos.append(GEMINI_MODEL_TEXTO)

            codigos_temporarios = (429, 500, 503, 504)
            palavras_temporarias = ("RESOURCE_EXHAUSTED", "UNAVAILABLE", "DEADLINE_EXCEEDED")
            ultimo_erro = None

            for modelo in modelos:
                for tentativa in range(3):
                    try:
                        resposta = self._client.models.generate_content(
                            model=modelo,
                            contents=user_prompt,
                            config=types.GenerateContentConfig(
                                system_instruction=system_prompt,
                                max_output_tokens=max_tokens,
                                temperature=0.2,
                            ),
                        )
                        return resposta.text
                    except Exception as e:
                        if "API_KEY_INVALID" in str(e) or "API key not valid" in str(e):
                            raise RuntimeError(
                                "O Google recusou a GEMINI_API_KEY do .env (chave inválida, revogada "
                                "ou ainda com o texto de exemplo). Corrija a chave ou use "
                                "AI_PROVIDER=ollama no .env."
                            ) from None
                        temporario = (
                            getattr(e, "code", None) in codigos_temporarios
                            or any(p in str(e) for p in palavras_temporarias)
                        )
                        if not temporario:
                            raise
                        ultimo_erro = e
                        espera = 10 * (tentativa + 1)
                        print(f"  [ia] {modelo} temporariamente indisponível ou no limite, aguardando {espera}s...")
                        time.sleep(espera)
                print(f"  [ia] {modelo} não respondeu, tentando o modelo de reserva...")

            raise RuntimeError(f"Falha ao chamar a IA após várias tentativas: {ultimo_erro}")

        elif PROVIDER == "ollama":
            import requests

            payload = {
                "model": OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": max_tokens, "num_ctx": 4096},
            }
            if json_mode:
                payload["format"] = "json"

            try:
                resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT)
            except requests.ConnectionError:
                raise RuntimeError(
                    f"Não consegui conectar ao Ollama em {OLLAMA_URL}. "
                    "Ele está rodando? Tente: sudo systemctl start ollama"
                )
            if not resp.ok:
                raise RuntimeError(
                    f"Ollama respondeu com erro {resp.status_code}: {resp.text[:200]} "
                    f"— o modelo '{OLLAMA_MODEL}' foi baixado? Rode: ollama pull {OLLAMA_MODEL}"
                )
            return resp.json()["message"]["content"]

        elif PROVIDER == "anthropic":
            resposta = self._client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return resposta.content[0].text

    @staticmethod
    def _parse_json_safely(texto: str) -> dict:
        texto = texto.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        try:
            return json.loads(texto)
        except json.JSONDecodeError:
            return {"erro": "resposta_nao_json", "bruto": texto}
