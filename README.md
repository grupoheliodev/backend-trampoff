# backend-trampoff

Este repositório contém a API do backend usada pelo projeto TrampOff.

## Deploy no Render

Instruções rápidas para conectar este repositório ao Render (https://render.com):

1. No painel do Render, clique em "New" → "Web Service".
2. Conecte o repositório GitHub/GitLab e selecione este repositório e a branch `main`.
3. O Render detectará o arquivo `render.yaml` na raiz e usará as configurações dele (build: `npm install`, start: `npm start`).
4. Antes de fazer deploy, configure as variáveis de ambiente necessárias no painel do serviço:
	- `DB_HOST` — host do banco MySQL (ex: `db.example.com`)
	- `DB_PORT` — porta do MySQL (padrão `3306`)
	- `DB_USER` — usuário do banco
	- `DB_PASSWORD` — senha do banco (pode ficar vazia em dev local)
	- `DB_DATABASE` — nome do database
	- `NODE_ENV` — `production` (opcional)

Observações importantes:

- O `server.js` valida que `DB_HOST`, `DB_USER` e `DB_DATABASE` estejam definidos e abortará a inicialização se algum destes estiver faltando. Configure-os no painel antes do primeiro deploy.
- O Render injeta a variável `PORT` com a porta pública disponível; o `server.js` já usa `process.env.PORT || 3000`.

Se preferir usar Docker, posso adicionar um `Dockerfile` e atualizar o `render.yaml` para `env: docker`.

---

Se quiser, eu já posso: criar um `Dockerfile`, adicionar secrets via GitHub Actions, ou gerar o `render.yaml` com variáveis preenchidas (se você me informar os valores ou fornecer secrets).
<<<<<<< HEAD
=======
# backend
>>>>>>> ccf2f66 (ot)
