# backend-trampoff

API backend do projeto TrampOff, agora com fluxo de cadastro simplificado (sem confirmação de e-mail por código e sem confirmação de senha).

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

Se preferir usar Docker, podemos adicionar um `Dockerfile` e atualizar o `render.yaml` para `env: docker`.

---

## Fluxo de Registro Simplificado

O cadastro foi reduzido para um único passo:

1. Chamada `POST /api/register/:usertype` (`freelancer` ou `contratante`).
2. Campos mínimos obrigatórios: `name`, `email`, `password` e `phone` (mais `companyName` para `contratante`).
3. A senha é aceita diretamente (não há mais `passwordConfirmation`).
4. O e-mail é marcado como verificado automaticamente.
5. Em modo offline (sem banco), o backend salva em `data/users.json` e retorna sucesso com mensagem de fallback.

### Rotas de E-mail

As rotas antigas de confirmação foram mantidas por compatibilidade, mas agora apenas garantem `emailVerified = true`:

- `POST /api/email/resend-confirmation` – marca o email como verificado se o usuário existir.
- `POST /api/email/confirm` – idem; não exige código.

### Diferenciação de Usuário

O campo `:usertype` na rota de registro determina inserção em tabela ou fallback correspondente:

- `freelancer`: insere habilidades/experiência quando disponíveis.
- `contratante`: exige `companyName`.

### Fallback Offline

Se a conexão com o banco falhar (`dbAvailable = false`), o servidor cria o usuário em arquivo JSON, garantindo funcionamento mínimo.

## Execução Local

Instale dependências e execute:

```powershell
cd backend-trampoff
npm install
node server.js
```

Variáveis de ambiente de banco podem ser omitidas para usar fallback sem MySQL.

## Próximos Passos Possíveis

- Adicionar `Dockerfile` para deploy containerizado.
- Remover rotas de e-mail se nenhum cliente legado mais depender delas.
- Unificar logs e reduzir verbosidade em produção.

---

## Registro da Sessão – 02/12/2025 (noite)

### O que foi modificado
- Remoção definitiva de qualquer validação ou UI de código/confirmar senha nas rotas de cadastro (`/api/register/:usertype`).
- Adição de fallback robusto para criação de usuários quando o MySQL está indisponível (`data/users.json`).
- Nova rota `/api/reset-password` com hash `bcrypt`, resposta detalhada (`success`, `updatedIn`, `ms`) e gravação segura em arquivo.
- Autenticação protegida contra crash fora do `AuthProvider` adicionando valores padrão no contexto (lado front) e retornos offline no backend.
- Ajustes de infraestrutura: service worker ignorando protocolos de extensão, `AccessibilityPanel` com destaque de links desligado por padrão e botões "Voltar" nas telas de login.

### O que funcionou
- Reset de senha: rota `/api/reset-password` atualiza corretamente no banco/fallback e retorna `success` com `updatedIn` (confirmado via testes de terminal).
- Login baseado em banco continua validando `bcrypt` normalmente; logs confirmam hash e comparação corretas.
- Cadastro base (sem campos específicos) ainda cria usuários no banco quando disponível.

### O que não funcionou (motivo)
- **Envio de e-mail**: como removemos o fluxo de confirmação, nenhuma mensagem real é disparada; as rotas apenas marcam o usuário como verificado. Se precisar voltar a enviar e-mails, será necessário reintroduzir serviço de disparo ou integrar SMTP.
- **Cadastro de contratantes no fallback**: quando o banco está indisponível, a rota `/api/register/contratante` só grava os campos básicos em `users.json`, ignorando `companyName`/`description`. O frontend espera a inserção na tabela `contratante`, então o cadastro aparenta falhar. Precisamos estender o fallback para armazenar/retornar esses dados (ou garantir o banco ativo).
- **Execução local sem DB/Firebase**: o servidor ainda encerra se `node server.js` for iniciado sem credenciais válidas porque o `pool` não é criado; ajustes parciais foram feitos, mas a inicialização completa requer revisar a criação condicional do pool. Enquanto isso, defina as variáveis ou ative `SKIP_DB_TEST=true` + `SKIP_FIREBASE_CHECK=true` para contornar.

---

Para solicitar próximos ajustes ou esclarecer pendências acima, abra uma issue ou descreva aqui.
