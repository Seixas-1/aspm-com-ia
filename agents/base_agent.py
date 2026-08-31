"""
Classe base para todos os agentes de IA.
Centraliza a chamada ao provedor de IA e a proteção contra prompt injection
(sanitização básica dos dados antes de irem para o prompt).

Provedor controlado pela variável de ambiente AI_PROVIDER no .env:
  - "gemini"    (padrão, GRATUITO — Google AI Studio, sem cartão de crédito)
  - "anthropic" (pago, usa créditos da API Claude — mesma arquitetura, só troca o motor)
"""
import os
import json

PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()

GEMINI_MODEL_RISCO = "gemini-3.5-flash"        # mais raciocínio, RPM menor (5/min no free tier)
GEMINI_MODEL_TEXTO = "gemini-3.1-flash-lite"   # RPM maior (15/min), suficiente p/ explicação e remediação
ANTHROPIC_MODEL = "claude-sonnet-4-6"


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

        else:
            raise ValueError(f"AI_PROVIDER desconhecido: '{PROVIDER}' (use 'gemini' ou 'anthropic')")

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

    def _call_ia(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
        """Chama o provedor de IA configurado. Mesma assinatura, motor intercambiável."""
        if PROVIDER == "gemini":
            import time
            from google.genai import types

            for tentativa in range(3):
                try:
                    resposta = self._client.models.generate_content(
                        model=self.MODEL_GEMINI,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            max_output_tokens=max_tokens,
                            temperature=0.2,
                        ),
                    )
                    return resposta.text
                except Exception as e:
                    if "RESOURCE_EXHAUSTED" in str(e) or "429" in str(e):
                        espera = 20 * (tentativa + 1)
                        print(f"  [ia] Limite de requisições/min atingido, aguardando {espera}s...")
                        time.sleep(espera)
                        continue
                    raise
            raise RuntimeError("Falha ao chamar a IA após 3 tentativas (limite de cota persistente).")

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
