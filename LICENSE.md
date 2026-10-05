# Licença

**ASPM com IA** — projeto do Challenge Pride 2026, FIAP Paulista (Turma 1TDCPF).

Este projeto é licenciado sob a **Licença BSD de 3 Cláusulas**
(*BSD 3-Clause License*, identificador SPDX: `BSD-3-Clause`).

---

BSD 3-Clause License

Copyright (c) 2026, Tomahawks (Enzo Seixas, Gabriel Cirone, Guilherme Reis, João Pedro, Matheus Silva)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

## Dependências de terceiros

Este projeto utiliza ferramentas e bibliotecas de terceiros (por exemplo
Bandit, Trivy, OWASP ZAP, DefectDojo, Wazuh, Streamlit e Flask). Elas **não
são distribuídas dentro deste repositório**: são instaladas separadamente
(veja `requirements.txt` e o `README.md`) e cada uma continua sob a sua
própria licença.

## Aviso sobre a aplicação de demonstração

A pasta `demo_app/` contém uma aplicação **propositalmente vulnerável**,
criada apenas como alvo de testes. Não a utilize em produção nem a exponha
à internet.
