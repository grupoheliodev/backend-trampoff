// server.js
/*
  Arquivo principal do backend (API).

  Sessões principais (comentadas abaixo):
  1) Carregamento de variáveis de ambiente e verificação
  2) Importação de bibliotecas e configuração do Express
  3) Configuração do banco de dados (pool + timeouts)
  4) Funções utilitárias para conexão / teste
  5) Endpoints: status, registro, login
  6) Inicialização do servidor

  Objetivo: servir endpoints REST para o frontend e comunicar com o banco MySQL.
*/
const path = require('path');
// 1) Carrega variáveis de ambiente do arquivo .env localizado na pasta do backend
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

// Verifica se as variáveis de ambiente essenciais estão definidas
// Permitir ignorar a verificação em desenvolvimento definindo SKIP_DB_TEST=true
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_DATABASE'];
if (process.env.SKIP_DB_TEST === 'true') {
    console.warn('SKIP_DB_TEST=true detectado — pulando verificação de variáveis de ambiente do banco (apenas para dev).');
} else {
    for (const envVar of requiredEnvVars) {
        if (!process.env[envVar]) {
            console.error(`Erro: Variável de ambiente ${envVar} não está definida!`);
            process.exit(1);
        }
    }
}
// DB_PASSWORD pode ser vazia para desenvolvimento local
process.env.DB_PASSWORD = process.env.DB_PASSWORD || '';

console.log('Configurações do banco de dados (iniciando):', {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || '8181',
    user: process.env.DB_USER,
    database: process.env.DB_DATABASE
});

// 2) Importação de bibliotecas principais
// - express: servidor HTTP e roteamento
// - mysql2/promise: driver MySQL com suporte a async/await
// - cors: habilita CORS para o frontend
// - bcrypt: hash de senhas
// - jsonwebtoken: tokens JWT para autenticação
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 2.1) Inicializa o app Express, habilita CORS e JSON parsing
const app = express();
app.use(cors({
    origin: 'http://localhost:5173', // origem do frontend Vite
    credentials: true
}));
app.use(express.json());

// Middleware para logar todas as requisições
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// --- 3. Configuração do Banco de Dados e Segurança ---
// Objeto que armazena as credenciais do banco de dados, lidas do arquivo .env.

const dbConfig = {
    host: (process.env.DB_HOST || '').split(':')[0] || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    connectTimeout: 10000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
}

const saltRounds = 10 //Define a "complexidade" da criptografia da senha.
const JWT_SECRET = 'IvyLindaMeuAmor'// Chave secreta para assinar os tokens JWT. Mude isso para algo aleatório e seguro.


// --- 4. Função Auxiliar para Conexão ---
// Cria um pool de conexões com o banco de dados
const pool = mysql.createPool(dbConfig);
// Flag que indica se o banco de dados está disponível; usado para ativar fallbacks em dev
let dbAvailable = true;

// Função para testar a conexão
async function testConnection() {
    try {
        console.log('Tentando conectar ao banco de dados...');
        console.log('Configurações:', {
            host: dbConfig.host,
            port: dbConfig.port,
            user: dbConfig.user,
            database: dbConfig.database
        });
        const connection = await pool.getConnection();
        console.log('\x1b[32m%s\x1b[0m', '✓ Conexão com o banco de dados estabelecida com sucesso!');
        connection.release();
        return true;
    } catch (error) {
        console.error('\x1b[31m%s\x1b[0m', '✗ Erro ao conectar com o banco de dados:', error.message);
        console.error('Detalhes do erro:', error);
        return false;
    }
}

async function getDbConnection() {
    try {
        const connection = await pool.getConnection();
        return connection;
    } catch (error) {
        console.error('\x1b[31m%s\x1b[0m', '✗ Erro ao obter conexão do pool:', error.message);
        throw new Error('Erro ao conectar com o banco de dados')
    
     }
}

// Rota de status do servidor e banco de dados
app.get('/api/status', async (req, res) => {
    try {
        const connection = await getDbConnection();
            // release pooled connection instead of ending it
            try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }
        res.json({ 
            status: 'online',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'online',
            database: 'disconnected',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// --- 5. Rota de Registro de Usuário (POST) ---
// Endpoint de registro em dois passos
// 1) /api/register-base  -> cria o registro base na tabela `usuario` com tipo temporário 'pendente'
// 2) /api/register/complete/:usertype -> completa o cadastro inserindo na tabela específica
// Nota: a coluna `tipo` na tabela `usuario` precisa aceitar o valor 'pendente' (ou NULL).
// Se o seu schema atual não tem 'pendente' no ENUM, execute o SQL abaixo no phpMyAdmin:
// ALTER TABLE usuario MODIFY tipo ENUM('freelancer','contratante','pendente') DEFAULT 'pendente';

// 1) Cria usuário base (sem dados específicos do perfil)
app.post('/api/register-base', async (req, res) => {
    let connection;
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
        }

        connection = await getDbConnection();
        await connection.beginTransaction();

        // Verifica se o email já existe
        const [existingUsers] = await connection.execute(
            'SELECT id_usuario FROM usuario WHERE email = ?',
            [email]
        );
        if (existingUsers.length > 0) {
            await connection.release();
            return res.status(400).json({ error: 'Email já cadastrado.' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insere o usuário com tipo pendente
        const [result] = await connection.execute(
            'INSERT INTO usuario (email, nome, senha, tipo, data_criacao) VALUES (?, ?, ?, ?, CURDATE())',
            [email, name, hashedPassword, 'pendente']
        );

        const userId = result.insertId;
        await connection.commit();

        // Gera token mínimo para usar na segunda etapa (pode conter apenas userId)
        const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '24h' });

        return res.status(201).json({ message: 'Usuário base criado.', userId, token });
    } catch (error) {
        console.error('Erro em /api/register-base:', error.message || error);
        if (connection) {
            try { await connection.rollback(); } catch (e) {}
        }
        return res.status(500).json({ error: 'Erro ao criar usuário base.', details: error.message });
    } finally {
        if (connection) try { await connection.release(); } catch (e) {}
    }
});

// 2) Completa o cadastro: insere na tabela específica (freelancer ou contratante)
app.post('/api/register/complete/:usertype', async (req, res) => {
    let connection;
    try {
        const userType = req.params.usertype; // 'freelancer' ou 'contratante'
        // aceita userId no body ou token Bearer
        let { userId, companyName, description, skills, experience } = req.body;

        // tenta extrair userId do token se não foi enviado no body
        if (!userId && req.headers.authorization) {
            const token = req.headers.authorization.replace(/^Bearer\s+/i, '');
            try {
                const payload = jwt.verify(token, JWT_SECRET);
                userId = payload.userId;
            } catch (e) {
                // ignore, será tratado abaixo
            }
        }

        if (!userId) return res.status(400).json({ error: 'userId é necessário (no body ou no token Authorization).' });
        if (userType !== 'freelancer' && userType !== 'contratante') return res.status(400).json({ error: 'Tipo inválido.' });

        connection = await getDbConnection();
        await connection.beginTransaction();

        // Verifica usuário existente e status
        const [rows] = await connection.execute('SELECT id_usuario, tipo FROM usuario WHERE id_usuario = ?', [userId]);
        if (rows.length === 0) {
            await connection.release();
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        const usuario = rows[0];
        if (usuario.tipo && usuario.tipo !== 'pendente') {
            await connection.release();
            return res.status(400).json({ error: 'Cadastro já foi completado para este usuário.' });
        }

        // Insere na tabela específica e atualiza tipo
        if (userType === 'freelancer') {
            await connection.execute(
                'INSERT INTO freelancer (id_usuario, experiencia, habilidades, descricao) VALUES (?, ?, ?, ?)',
                [userId, experience || '', skills || '', description || '']
            );
        } else {
            if (!companyName) {
                await connection.release();
                return res.status(400).json({ error: 'companyName é obrigatório para contratantes.' });
            }
            await connection.execute(
                'INSERT INTO contratante (id_usuario, nome_empresa, descricao) VALUES (?, ?, ?)',
                [userId, companyName || '', description || '']
            );
        }

        await connection.execute('UPDATE usuario SET tipo = ? WHERE id_usuario = ?', [userType, userId]);
        await connection.commit();

        return res.status(200).json({ message: 'Cadastro completado com sucesso.', userId, userType });
    } catch (error) {
        console.error('Erro em /api/register/complete:', error.message || error);
        if (connection) try { await connection.rollback(); } catch (e) {}
        return res.status(500).json({ error: 'Erro ao completar cadastro.', details: error.message });
    } finally {
        if (connection) try { await connection.release(); } catch (e) {}
    }
});

// Rota dinâmica que aceita 'freelancer' ou 'contratante' como tipo de usuário.
app.post('/api/register/:usertype', async (req, res) => {
    let connection;
    try {
        console.log('Iniciando registro de usuário:', req.body);
        const userType = req.params.usertype;
        const { 
            name, 
            email, 
            password,
            passwordConfirmation,
            phone,
            companyName,  // apenas para contratante
            description, 
            skills,       // apenas para freelancer
            experience    // apenas para freelancer
        } = req.body;

        // Validações básicas
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
        }

        // Aceita diferentes nomes de campo para confirmação de senha (camelCase, snake_case, aliases)
        const pwdConfirm = passwordConfirmation || req.body.password_confirmation || req.body.passwordConfirm || req.body.confirmPassword || req.body.confirmation;
        console.log('Password confirmation received (normalized):', pwdConfirm !== undefined ? '[present]' : '[missing]');
        if (!pwdConfirm || password !== pwdConfirm) {
            return res.status(400).json({ error: 'Confirmação de senha inválida.' });
        }

        // Aceita alias de telefone também, para compatibilidade com clientes antigos
        const phoneVal = phone || req.body.phone_number || req.body.telefone || req.body.telefone_celular;
        if (!phoneVal) {
            return res.status(400).json({ error: 'Número de telefone é obrigatório.' });
        }

        if (userType !== 'freelancer' && userType !== 'contratante') {
            return res.status(400).json({ error: 'Tipo de usuário inválido.' });
        }

        // Validações específicas por tipo
        if (userType === 'contratante' && !companyName) {
            return res.status(400).json({ error: 'Nome da empresa é obrigatório para contratantes.' });
        }

        // If DB is not available, use file-backed users storage
        if (!dbAvailable) {
            // create fallback user
            try {
                const users = await readJsonFile('users.json');
                const id = generateId();
                const createdAt = new Date().toISOString();
                const newUser = { id, name, email, phone, userType, createdAt };
                users.push(newUser);
                await writeJsonFile('users.json', users);
                return res.status(201).json({ message: 'Usuário criado em modo offline (fallback).', userId: id, user: newUser });
            } catch (e) {
                console.error('Erro ao salvar usuário no fallback (file):', e);
                return res.status(500).json({ error: 'Erro interno ao salvar usuário (fallback).' });
            }
        }

        connection = await getDbConnection();
        await connection.beginTransaction();

        // Verifica se o email já existe
        const [existingUsers] = await connection.execute(
            'SELECT id_usuario FROM usuario WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }
            return res.status(400).json({ error: 'Email já cadastrado.' });
        }

        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Inicia a transação
        await connection.beginTransaction();
        console.log('Transação iniciada');

        try {
            // Insere o usuário base
            console.log('Tentando inserir usuário com os dados:', {
                email,
                name,
                userType,
                hashedPassword: 'SENHA_HASHEADA'
            });
            
            // Insere o usuário base
            const [userResult] = await connection.execute(
                'INSERT INTO usuario (email, nome, senha, tipo, data_criacao) VALUES (?, ?, ?, ?, CURDATE())',
                [email, name, hashedPassword, userType]
            );
            const userId = userResult.insertId;
            console.log('Usuário inserido com sucesso, ID:', userId);

            // Tenta salvar telefone na tabela `usuario` caso a coluna exista
            try {
                await connection.execute('UPDATE usuario SET telefone = ? WHERE id_usuario = ?', [phone, userId]);
            } catch (e) {
                console.warn('Não foi possível salvar telefone na tabela `usuario` (coluna possivelmente ausente). Salvando no fallback de usuários.');
                try {
                    const users = await readJsonFile('users.json');
                    users.push({ id: userId, name, email, phone, userType, createdAt: new Date().toISOString() });
                    await writeJsonFile('users.json', users);
                } catch (err) {
                    console.error('Erro ao salvar telefone no fallback:', err);
                }
            }

            // Insere dados específicos baseado no tipo de usuário
            if (userType === 'freelancer') {
                await connection.execute(
                    'INSERT INTO freelancer (id_usuario, experiencia, habilidades, descricao) VALUES (?, ?, ?, ?)',
                    [userId, experience || '', skills || '', description || '']
                );
                console.log('Dados do freelancer inseridos com sucesso');
            } else {
                await connection.execute(
                    'INSERT INTO contratante (id_usuario, nome_empresa, descricao) VALUES (?, ?, ?)',
                    [userId, companyName, description || '']
                );
                console.log('Dados do contratante inseridos com sucesso');
            }

            // Confirma a transação
            await connection.commit();
            console.log('Transação confirmada com sucesso');

            // Gera o token JWT
            const token = jwt.sign(
                { userId, userType, email, name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(201).json({
                message: 'Usuário registrado com sucesso',
                token,
                user: {
                    id: userId,
                    name,
                    email,
                    userType
                }
            });

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }
        }
    try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }
    try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }

    } catch (error) {
        console.error('Erro no registro:', error);
        console.error('Detalhes do erro:', {
            message: error.message,
            code: error.code,
            sqlMessage: error.sqlMessage
        });
        res.status(500).json({ 
            error: 'Erro interno do servidor',
            details: error.sqlMessage || error.message
        });
    }
});

// Rota de login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
        }

        console.log(`[login] tentativa de login para email=${email}, passwordPresent=${!!password}`);

        const connection = await getDbConnection();

        // Busca o usuário pelo email
        const [users] = await connection.execute(
            'SELECT id_usuario, nome, email, senha, tipo FROM usuario WHERE email = ?',
            [email]
        );

        try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }

        if (users.length === 0) {
            return res.status(401).json({ error: 'Usuário não encontrado.' });
        }

    const user = users[0];
    console.log(`[login] encontrado usuário id=${user.id_usuario}, hashLen=${user.senha ? user.senha.length : 0}`);

    // Verifica a senha
    const validPassword = await bcrypt.compare(password, user.senha);
    console.log(`[login] password match for email=${email}: ${validPassword}`);
        if (!validPassword) {
            return res.status(401).json({ error: 'Senha incorreta.' });
        }

        // Gera o token JWT
        const token = jwt.sign(
            { 
                userId: user.id_usuario, 
                userType: user.tipo, 
                email: user.email 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id_usuario,
                name: user.nome,
                email: user.email,
                userType: user.tipo
            }
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Rota para buscar usuários por tipo
app.get('/api/users/:userType', async (req, res) => {
    const { userType } = req.params;
    const validTypes = ['freelancer', 'contratante'];

    if (!validTypes.includes(userType)) {
        return res.status(400).json({ error: 'Tipo de usuário inválido.' });
    }

    let connection;
    try {
        connection = await getDbConnection();
        // Busca usuários e seus dados específicos (nome da empresa para contratante)
        let query;
        if (userType === 'contratante') {
            query = `
                SELECT u.id_usuario as id, u.nome as name, u.email, c.nome_empresa as companyName
                FROM usuario u
                JOIN contratante c ON u.id_usuario = c.id_usuario
                WHERE u.tipo = ?
            `;
        } else {
            query = `
                SELECT id_usuario as id, nome as name, email
                FROM usuario
                WHERE tipo = ?
            `;
        }
        
        const [users] = await connection.execute(query, [userType]);
        
        res.json(users);
    } catch (error) {
        console.error(`Erro ao buscar usuários (${userType}):`, error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

// Rota para buscar mensagens entre dois usuários
<<<<<<< HEAD
app.get('/api/messages/:userId/:contactId', async (req, res) => {
    const { userId, contactId } = req.params;
=======
// Suporte a query params: /api/messages?user1=...&user2=... (frontend antigo usa esse formato)
app.get('/api/messages', async (req, res) => {
    const { user1, user2 } = req.query;
    if (!user1 || !user2) {
        return res.status(400).json({ error: 'Parâmetros user1 e user2 são necessários.' });
    }
    // If DB not available, fallback to file storage
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(user1) && String(m.receiverId) === String(user2)) || (String(m.senderId) === String(user2) && String(m.receiverId) === String(user1)));
            return res.json(filtered);
        } catch (e) {
            console.error('Erro ao ler mensagens do fallback (file):', e);
            return res.status(500).json({ error: 'Erro interno' });
        }
    }

    let connection;
    try {
        connection = await getDbConnection();
        const [messages] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, mensagem as content, data_envio as createdAt
             FROM mensagem
             WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
             ORDER BY data_envio ASC`,
            [user1, user2, user2, user1]
        );
        res.json(messages);
    } catch (error) {
        console.error('Erro ao buscar mensagens (query):', error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] Detected ER_BAD_FIELD_ERROR (possible schema mismatch). Switching to file fallback mode.');
            dbAvailable = false;
        }
        // fallback to file storage on SQL errors
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(user1) && String(m.receiverId) === String(user2)) || (String(m.senderId) === String(user2) && String(m.receiverId) === String(user1)));
            return res.json(filtered);
        } catch (e) {
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

app.get('/api/messages/:userId/:contactId', async (req, res) => {
    const { userId, contactId } = req.params;
    // Fallback to file storage when DB unavailable
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(userId) && String(m.receiverId) === String(contactId)) || (String(m.senderId) === String(contactId) && String(m.receiverId) === String(userId)));
            return res.json(filtered);
        } catch (e) {
            console.error('Erro ao ler mensagens do fallback (file):', e);
            return res.status(500).json({ error: 'Erro interno' });
        }
    }

>>>>>>> 29de3da (ta indo)
    let connection;
    try {
        connection = await getDbConnection();
        const [messages] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, conteudo as content, data_envio as createdAt
             FROM mensagem
             WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
             ORDER BY data_envio ASC`,
            [userId, contactId, contactId, userId]
        );
        res.json(messages);
    } catch (error) {
        console.error('Erro ao buscar mensagens:', error);
<<<<<<< HEAD
        res.status(500).json({ error: 'Erro interno do servidor' });
=======
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] Detected ER_BAD_FIELD_ERROR (possible schema mismatch). Switching to file fallback mode.');
            dbAvailable = false;
        }
        // fallback to file storage on SQL errors
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(userId) && String(m.receiverId) === String(contactId)) || (String(m.senderId) === String(contactId) && String(m.receiverId) === String(userId)));
            return res.json(filtered);
        } catch (e) {
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
>>>>>>> 29de3da (ta indo)
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

// Rota para enviar uma mensagem
app.post('/api/messages', async (req, res) => {
<<<<<<< HEAD
    const { senderId, receiverId, content } = req.body;
    if (!senderId || !receiverId || !content) {
        return res.status(400).json({ error: 'Dados da mensagem incompletos.' });
=======
    let { senderId, receiverId, content } = req.body || {};
    console.log('[POST /api/messages] body:', req.body);

    // Compatibilidade: em alguns fluxos o frontend envia um objeto 'content' vindo do Firebase.
    if (!senderId || !receiverId || content === undefined || content === null) {
        return res.status(400).json({ error: 'Dados da mensagem incompletos. senderId, receiverId e content são necessários.' });
    }

    // Se content for objeto (ex: Firebase timestamp ou estrutura), stringify para armazenar no SQL
    if (typeof content === 'object') {
        try {
            content = JSON.stringify(content);
        } catch (e) {
            content = String(content);
        }
    }

    // Garantir ids numéricos quando possível
    const sId = Number(senderId);
    const rId = Number(receiverId);

    // If DB not available, write to file-backed messages storage
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const id = generateId();
            const newMessage = { id, senderId: isNaN(sId) ? senderId : sId, receiverId: isNaN(rId) ? receiverId : rId, content, createdAt: new Date().toISOString() };
            msgs.push(newMessage);
            await writeJsonFile('messages.json', msgs);
            return res.status(201).json(newMessage);
        } catch (e) {
            console.error('Erro ao gravar mensagem no fallback (file):', e && e.stack ? e.stack : e);
            return res.status(500).json({ error: 'Erro interno ao gravar mensagem (fallback)', details: e && e.message ? e.message : String(e) });
        }
>>>>>>> 29de3da (ta indo)
    }

    let connection;
    try {
        connection = await getDbConnection();
        const [result] = await connection.execute(
<<<<<<< HEAD
            'INSERT INTO mensagem (id_remetente, id_destinatario, conteudo, data_envio) VALUES (?, ?, ?, NOW())',
            [senderId, receiverId, content]
        );
        
        const newMessage = {
            id: result.insertId,
            senderId,
            receiverId,
=======
            'INSERT INTO mensagem (id_remetente, id_destinatario, mensagem, data_envio) VALUES (?, ?, ?, NOW())',
            [isNaN(sId) ? senderId : sId, isNaN(rId) ? receiverId : rId, content]
        );

        const newMessage = {
            id: result.insertId,
            senderId: isNaN(sId) ? senderId : sId,
            receiverId: isNaN(rId) ? receiverId : rId,
>>>>>>> 29de3da (ta indo)
            content,
            createdAt: new Date().toISOString()
        };
        res.status(201).json(newMessage);
    } catch (error) {
<<<<<<< HEAD
        console.error('Erro ao enviar mensagem:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
=======
        console.error('Erro ao enviar mensagem:', error && error.stack ? error.stack : error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] Detected ER_BAD_FIELD_ERROR on INSERT (possible schema mismatch). Switching to file fallback mode.');
            dbAvailable = false;
        }
        // Fallback: persist message to file storage and return success so frontend can continue
        try {
            const msgs = await readJsonFile('messages.json');
            const id = generateId();
            const fallbackMessage = { id, senderId: isNaN(sId) ? senderId : sId, receiverId: isNaN(rId) ? receiverId : rId, content, createdAt: new Date().toISOString() };
            msgs.push(fallbackMessage);
            try {
                await writeJsonFile('messages.json', msgs);
                console.info('[POST /api/messages] mensagem salva no fallback (file) com id=', id);
                return res.status(201).json(fallbackMessage);
            } catch (writeErr) {
                console.error('Erro ao salvar fallback de mensagem:', writeErr && writeErr.stack ? writeErr.stack : writeErr);
                return res.status(500).json({ error: 'Erro interno ao salvar mensagem (fallback)', details: writeErr && writeErr.message ? writeErr.message : String(writeErr) });
            }
        } catch (e) {
            console.error('Erro ao preparar fallback de mensagem:', e && e.stack ? e.stack : e);
            return res.status(500).json({ error: 'Erro interno do servidor', details: error && error.message ? error.message : String(error) });
        }
>>>>>>> 29de3da (ta indo)
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

<<<<<<< HEAD
=======
// === Simple JSON file storage fallback (dev) ===
const fs = require('fs').promises;
const DATA_DIR = path.resolve(__dirname, 'data');

async function ensureDataDir() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
    } catch (e) {}
}

async function readJsonFile(name) {
    await ensureDataDir();
    const p = path.join(DATA_DIR, name);
    try {
        const raw = await fs.readFile(p, 'utf8');
        return JSON.parse(raw || '[]');
    } catch (e) {
        return [];
    }
}

async function writeJsonFile(name, data) {
    await ensureDataDir();
    const p = path.join(DATA_DIR, name);
    await fs.writeFile(p, JSON.stringify(data, null, 2), 'utf8');
}

function generateId() {
    return Date.now() + Math.floor(Math.random() * 10000);
}

// --- Jobs endpoints (file-backed for dev) ---
app.get('/api/jobs', async (req, res) => {
    try {
        const jobs = await readJsonFile('jobs.json');
        res.json(jobs);
    } catch (e) {
        console.error('Erro em GET /api/jobs', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/api/jobs', async (req, res) => {
    try {
        const { ownerId, title, description, category, budget, price } = req.body;
        if (!ownerId || !title) return res.status(400).json({ error: 'ownerId e title obrigatórios' });
        const jobs = await readJsonFile('jobs.json');
        const id = generateId();
        const job = {
            id,
            ownerId,
            title,
            description: description || '',
            category: category || '',
            budget: budget || null,
            price: price != null ? price : (budget ? Number(String(budget).replace(/[^0-9\.\,]/g, '').replace(/,/g, '.')) : 0),
            status: 'open',
            createdAt: new Date().toISOString()
        };
        jobs.unshift(job);
        await writeJsonFile('jobs.json', jobs);
        res.status(201).json(job);
    } catch (e) {
        console.error('Erro em POST /api/jobs', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.put('/api/jobs/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        const updates = req.body || {};
        const jobs = await readJsonFile('jobs.json');
        const idx = jobs.findIndex(j => Number(j.id) === id);
        if (idx === -1) return res.status(404).json({ error: 'Job não encontrado' });
        jobs[idx] = { ...jobs[idx], ...updates, updatedAt: new Date().toISOString() };
        await writeJsonFile('jobs.json', jobs);
        res.json(jobs[idx]);
    } catch (e) {
        console.error('Erro em PUT /api/jobs/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.delete('/api/jobs/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        let jobs = await readJsonFile('jobs.json');
        jobs = jobs.filter(j => Number(j.id) !== id);
        await writeJsonFile('jobs.json', jobs);
        res.json({ success: true });
    } catch (e) {
        console.error('Erro em DELETE /api/jobs/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// --- Projects endpoints (file-backed for dev) ---
app.get('/api/projects', async (req, res) => {
    try {
        const ownerId = req.query.ownerId;
        const projects = await readJsonFile('projects.json');
        if (ownerId) return res.json(projects.filter(p => String(p.ownerId) === String(ownerId)));
        res.json(projects);
    } catch (e) {
        console.error('Erro em GET /api/projects', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/api/projects', async (req, res) => {
    try {
        const { ownerId, title, description } = req.body;
        if (!ownerId || !title) return res.status(400).json({ error: 'ownerId e title obrigatórios' });
        const projects = await readJsonFile('projects.json');
        const id = generateId();
        const project = { id, ownerId, title, description: description || '', createdAt: new Date().toISOString() };
        projects.unshift(project);
        await writeJsonFile('projects.json', projects);
        res.status(201).json(project);
    } catch (e) {
        console.error('Erro em POST /api/projects', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.put('/api/projects/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const updates = req.body || {};
        const projects = await readJsonFile('projects.json');
        const idx = projects.findIndex(p => String(p.id) === String(id));
        if (idx === -1) return res.status(404).json({ error: 'Project not found' });
        projects[idx] = { ...projects[idx], ...updates, updatedAt: new Date().toISOString() };
        await writeJsonFile('projects.json', projects);
        res.json(projects[idx]);
    } catch (e) {
        console.error('Erro em PUT /api/projects/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.delete('/api/projects/:id', async (req, res) => {
    try {
        const id = req.params.id;
        let projects = await readJsonFile('projects.json');
        projects = projects.filter(p => String(p.id) !== String(id));
        await writeJsonFile('projects.json', projects);
        res.json({ success: true });
    } catch (e) {
        console.error('Erro em DELETE /api/projects/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// --- Applications endpoints ---
app.get('/api/jobs/:jobId/applications', async (req, res) => {
    try {
        const jobId = req.params.jobId;
        const apps = await readJsonFile('applications.json');
        res.json(apps.filter(a => String(a.jobId) === String(jobId)));
    } catch (e) {
        console.error('Erro em GET /api/jobs/:jobId/applications', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/api/jobs/:jobId/applications', async (req, res) => {
    try {
        const jobId = req.params.jobId;
        const { userId, coverLetter } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
        const apps = await readJsonFile('applications.json');
        if (apps.find(a => String(a.jobId) === String(jobId) && String(a.userId) === String(userId))) {
            return res.status(409).json({ error: 'Já aplicada' });
        }
        const application = { id: generateId(), jobId, userId, coverLetter: coverLetter || '', status: 'pending', createdAt: new Date().toISOString() };
        apps.push(application);
        await writeJsonFile('applications.json', apps);
        res.status(201).json(application);
    } catch (e) {
        console.error('Erro em POST /api/jobs/:jobId/applications', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// --- Project applications (similar to job applications) ---
app.get('/api/projects/:projectId/applications', async (req, res) => {
    try {
        const projectId = req.params.projectId;
        const apps = await readJsonFile('project_applications.json');
        res.json(apps.filter(a => String(a.projectId) === String(projectId)));
    } catch (e) {
        console.error('Erro em GET /api/projects/:projectId/applications', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/api/projects/:projectId/applications', async (req, res) => {
    try {
        const projectId = req.params.projectId;
        const { userId, message } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId obrigatório' });

        const projects = await readJsonFile('projects.json');
        const project = projects.find(p => String(p.id) === String(projectId));
        if (!project) return res.status(404).json({ error: 'Projeto não encontrado' });

        const apps = await readJsonFile('project_applications.json');
        if (apps.find(a => String(a.projectId) === String(projectId) && String(a.userId) === String(userId))) {
            return res.status(409).json({ error: 'Já inscrito neste projeto' });
        }

        const application = { id: generateId(), projectId, userId, message: message || '', status: 'pending', createdAt: new Date().toISOString() };
        apps.push(application);
        await writeJsonFile('project_applications.json', apps);

        // create a notification for the project owner
        try {
            const notifications = await readJsonFile('notifications.json');
            const note = { id: generateId(), userId: project.ownerId, type: 'project_application', data: { projectId, applicantId: userId, applicationId: application.id }, read: false, createdAt: new Date().toISOString() };
            notifications.push(note);
            await writeJsonFile('notifications.json', notifications);
        } catch (e) {
            console.warn('Falha ao criar notificação (não crítica):', e && e.message ? e.message : e);
        }

        res.status(201).json(application);
    } catch (e) {
        console.error('Erro em POST /api/projects/:projectId/applications', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// Notifications endpoints
app.get('/api/notifications', async (req, res) => {
    try {
        const userId = req.query.userId;
        const notes = await readJsonFile('notifications.json');
        if (userId) return res.json(notes.filter(n => String(n.userId) === String(userId)));
        res.json(notes);
    } catch (e) {
        console.error('Erro em GET /api/notifications', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.put('/api/notifications/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const updates = req.body || {};
        const notes = await readJsonFile('notifications.json');
        const idx = notes.findIndex(n => String(n.id) === String(id));
        if (idx === -1) return res.status(404).json({ error: 'Notification not found' });
        notes[idx] = { ...notes[idx], ...updates, updatedAt: new Date().toISOString() };
        await writeJsonFile('notifications.json', notes);
        res.json(notes[idx]);
    } catch (e) {
        console.error('Erro em PUT /api/notifications/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.put('/api/applications/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        const updates = req.body || {};
        const apps = await readJsonFile('applications.json');
        const idx = apps.findIndex(a => Number(a.id) === id);
        if (idx === -1) return res.status(404).json({ error: 'Application not found' });
        apps[idx] = { ...apps[idx], ...updates, updatedAt: new Date().toISOString() };
        await writeJsonFile('applications.json', apps);
        res.json(apps[idx]);
    } catch (e) {
        console.error('Erro em PUT /api/applications/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// --- Contracts endpoints ---
app.post('/api/contracts', async (req, res) => {
    try {
        const { jobId, employerId, freelancerId, agreedAt, price } = req.body;
        if (!jobId || !employerId || !freelancerId) return res.status(400).json({ error: 'Dados incompletos' });
        const contracts = await readJsonFile('contracts.json');
        const contract = { id: generateId(), jobId, employerId, freelancerId, price: price || 0, status: 'active', agreedAt: agreedAt || new Date().toISOString() };
        contracts.push(contract);
        await writeJsonFile('contracts.json', contracts);
        res.status(201).json(contract);
    } catch (e) {
        console.error('Erro em POST /api/contracts', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.get('/api/contracts', async (req, res) => {
    try {
        const userId = req.query.userId;
        const contracts = await readJsonFile('contracts.json');
        if (userId) {
            return res.json(contracts.filter(c => String(c.employerId) === String(userId) || String(c.freelancerId) === String(userId)));
        }
        res.json(contracts);
    } catch (e) {
        console.error('Erro em GET /api/contracts', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.put('/api/contracts/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        const updates = req.body || {};
        const contracts = await readJsonFile('contracts.json');
        const idx = contracts.findIndex(c => Number(c.id) === id);
        if (idx === -1) return res.status(404).json({ error: 'Contract not found' });
        contracts[idx] = { ...contracts[idx], ...updates, updatedAt: new Date().toISOString() };
        await writeJsonFile('contracts.json', contracts);
        res.json(contracts[idx]);
    } catch (e) {
        console.error('Erro em PUT /api/contracts/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// --- Reviews endpoints ---
app.post('/api/reviews', async (req, res) => {
    try {
        const { reviewerId, targetUserId, contractId, jobId, rating, comment } = req.body;
        if (!reviewerId || !targetUserId) return res.status(400).json({ error: 'Dados incompletos' });
        const reviews = await readJsonFile('reviews.json');
        const review = { id: generateId(), reviewerId, targetUserId, contractId: contractId || null, jobId: jobId || null, rating: rating || 5, comment: comment || '', createdAt: new Date().toISOString() };
        reviews.push(review);
        await writeJsonFile('reviews.json', reviews);
        res.status(201).json(review);
    } catch (e) {
        console.error('Erro em POST /api/reviews', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.get('/api/reviews', async (req, res) => {
    try {
        const userId = req.query.userId;
        const jobId = req.query.jobId;
        const reviews = await readJsonFile('reviews.json');
        if (userId) return res.json(reviews.filter(r => String(r.targetUserId) === String(userId)));
        if (jobId) return res.json(reviews.filter(r => String(r.jobId) === String(jobId)));
        res.json(reviews);
    } catch (e) {
        console.error('Erro em GET /api/reviews', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.get('/api/reviews/stats', async (req, res) => {
    try {
        const userId = req.query.userId;
        if (!userId) return res.status(400).json({ error: 'userId é necessário' });
        const reviews = await readJsonFile('reviews.json');
        const list = reviews.filter(r => String(r.targetUserId) === String(userId));
        const count = list.length;
        const average = count === 0 ? 0 : list.reduce((s, r) => s + (Number(r.rating) || 0), 0) / count;
        res.json({ count, average });
    } catch (e) {
        console.error('Erro em GET /api/reviews/stats', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});


>>>>>>> 29de3da (ta indo)
// Inicialização do servidor
const PORT = process.env.PORT || 3000;

// Função para iniciar o servidor
async function startServer() {
    try {
        // Garantir diretório e arquivos de dados para fallback (evita erros de I/O quando SQL falha)
        try {
            await ensureDataDir();
            const filesToEnsure = ['messages.json','users.json','jobs.json','projects.json','applications.json','contracts.json','reviews.json'];
            for (const fname of filesToEnsure) {
                try {
                    const content = await readJsonFile(fname); // retorna [] se não existir
                    await writeJsonFile(fname, content);
                } catch (e) {
                    console.warn(`Não foi possível garantir arquivo ${fname}:`, e && e.message ? e.message : e);
                }
            }
            console.info('[startup] pasta de dados e arquivos iniciais garantidos.');
        } catch (e) {
            console.warn('[startup] falha ao preparar fallback de arquivos de dados:', e && e.message ? e.message : e);
        }
        // Testa a conexão com o banco antes de iniciar o servidor
        const isConnected = await testConnection();
        if (!isConnected) {
            console.warn('Não foi possível estabelecer conexão com o banco de dados. Iniciando servidor em modo fallback (arquivo local).');
            dbAvailable = false;
        } else {
            dbAvailable = true;
        }

        app.listen(PORT, () => {
            console.log('\x1b[36m%s\x1b[0m', `🚀 Servidor rodando em http://localhost:${PORT}`);
            console.log('📝 Endpoints disponíveis:');
            console.log('   POST /api/register/freelancer - Registrar freelancer');
            console.log('   POST /api/register/contratante - Registrar contratante');
            console.log('   POST /api/login - Login de usuário');
            console.log('   GET /api/status - Status do servidor');
        });
    } catch (error) {
        console.error('Erro ao iniciar o servidor:', error);
        process.exit(1);
    }
}

// Inicia o servidor
startServer();