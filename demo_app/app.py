"""
App de Demonstração — PROPOSITALMENTE VULNERÁVEL
Usada apenas como alvo de teste para o DAST (OWASP ZAP) na apresentação.

NUNCA implante isso em produção ou exponha à internet.

Vulnerabilidades presentes de propósito (mesma história do dashboard):
1. SQL Injection em /login   (equivalente ao achado do Bandit em login.py)
2. XSS refletido em /contato  (equivalente ao achado "XSS em formulário contato")
3. Debug mode habilitado      (equivalente ao achado "informação de debug exposta")
4. Headers de segurança ausentes (o ZAP detecta isso automaticamente)

Rodar:
    pip install flask
    python demo_app/app.py
Acessa em: http://localhost:5000
"""
import sqlite3
from pathlib import Path
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config["DEBUG"] = True  # Vulnerabilidade 3: nunca em produção

DB_PATH = Path(__file__).parent / "demo.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS usuarios (username TEXT, senha TEXT)")
    conn.execute("DELETE FROM usuarios")
    conn.execute("INSERT INTO usuarios VALUES ('admin', 'senha_super_secreta_123')")
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>App de Demonstração ASPM</h1>
    <p>Alvo intencionalmente vulnerável para testes do DAST (OWASP ZAP).</p>
    <ul>
      <li><a href="/login">/login</a> — formulário com SQL Injection</li>
      <li><a href="/contato">/contato</a> — formulário com XSS refletido</li>
    </ul>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    resultado = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        senha = request.form.get("senha", "")

        # VULNERABILIDADE 1: SQL Injection proposital (concatenação direta)
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT * FROM usuarios WHERE username = '{username}' AND senha = '{senha}'"
        cursor = conn.execute(query)  # nosec - vulnerabilidade proposital para demo
        usuario = cursor.fetchone()
        conn.close()

        resultado = "Login OK!" if usuario else "Usuário ou senha inválidos."

    return f"""
    <h2>Login</h2>
    <form method="post">
      Usuário: <input name="username"><br>
      Senha: <input name="senha" type="password"><br>
      <button type="submit">Entrar</button>
    </form>
    <p>{resultado}</p>
    <p><small>Dica de ataque para demo: usuário = <code>' OR '1'='1</code></small></p>
    """


@app.route("/contato", methods=["GET", "POST"])
def contato():
    mensagem_html = ""
    if request.method == "POST":
        mensagem = request.form.get("mensagem", "")
        # VULNERABILIDADE 2: XSS refletido (renderiza input sem sanitizar)
        mensagem_html = render_template_string(f"<p>Sua mensagem: {mensagem}</p>")

    return f"""
    <h2>Fale Conosco</h2>
    <form method="post">
      Mensagem: <input name="mensagem" size="50"><br>
      <button type="submit">Enviar</button>
    </form>
    {mensagem_html}
    <p><small>Dica de ataque para demo: &lt;script&gt;alert('xss')&lt;/script&gt;</small></p>
    """


if __name__ == "__main__":
    init_db()
    print("App de demo rodando em http://localhost:5000")
    print("ATENÇÃO: app propositalmente vulnerável, use apenas em ambiente local/isolado.")
    app.run(host="0.0.0.0", port=5000, debug=True)
