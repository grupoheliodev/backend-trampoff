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
const fsSync = require('fs');
// 1) Carrega variáveis de ambiente conforme NODE_ENV, priorizando .env.development em dev
(() => {
    const envFromNode = process.env.NODE_ENV;
    const candidates = envFromNode && envFromNode.length
        ? [`.env.${envFromNode}`, '.env']
        : ['.env.development', '.env'];
    const envPath = candidates
        .map((f) => path.resolve(__dirname, f))
        .find((p) => {
            try { return fsSync.existsSync(p); } catch (_) { return false; }
        });
    require('dotenv').config({ path: envPath });
    if (envPath) {
        console.log(`[env] carregado: ${path.basename(envPath)} (NODE_ENV=${envFromNode || 'undefined'})`);
    } else {
        console.warn('[env] nenhum arquivo .env* encontrado; usando apenas variáveis do processo.');
    }
})();

// Verifica se as variáveis de ambiente essenciais estão definidas
// Em desenvolvimento permitimos modo fallback (sem banco) para agilizar testes
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_DATABASE'];
const missingDbVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);
const requireDb = String(process.env.REQUIRE_DB || '').toLowerCase() === 'true';
const skipDbTest = String(process.env.SKIP_DB_TEST || '').toLowerCase() === 'true';
const hasDbConfig = missingDbVars.length === 0;

if (missingDbVars.length > 0) {
    const msg = `[db] Variáveis ausentes: ${missingDbVars.join(', ')}. Iniciaremos em modo fallback (arquivo).`;
    if (requireDb && !skipDbTest) {
        console.error(`${msg} (REQUIRE_DB=true). Abortando.`);
        process.exit(1);
    }
    console.warn(msg);
    if (!skipDbTest) {
        console.warn('Defina REQUIRE_DB=true para tornar esse erro fatal ou forneça as variáveis acima.');
    } else {
        console.warn('SKIP_DB_TEST=true definido — ignorando verificação obrigatória.');
    }
} else if (skipDbTest) {
    console.warn('SKIP_DB_TEST=true definido, mas todas as variáveis foram fornecidas.');
}
// DB_PASSWORD pode ser vazia para desenvolvimento local
process.env.DB_PASSWORD = process.env.DB_PASSWORD || '';

// Normaliza host/porta: permite DB_HOST="host:porta" ou variáveis separadas.
const rawHost = process.env.DB_HOST || 'localhost';
let normalizedHost = rawHost;
let hostPortFragment;
if (rawHost.includes(':')) {
    const parts = rawHost.split(':');
    normalizedHost = parts[0];
    hostPortFragment = parts[1];
}
const normalizedPort = parseInt(process.env.DB_PORT || hostPortFragment || '3306', 10);

console.log('Configurações do banco de dados (iniciando):', {
    host: normalizedHost,
    port: normalizedPort,
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
const { db: firebaseDb, storageBucket } = require('./firebase');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

// 2.1) Inicializa o app Express, habilita CORS e JSON parsing
const app = express();
// CORS dinâmico para permitir Vercel e localhost; pode ser sobrescrito via CORS_ORIGINS
const defaultOrigins = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'https://trampoff.vercel.app'
];
const allowedOrigins = (process.env.CORS_ORIGINS || defaultOrigins.join(',')).split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        try {
            const url = new URL(origin);
            if (url.hostname.endsWith('.vercel.app')) return callback(null, true);
        } catch (_) {}
        return callback(new Error(`Not allowed by CORS: ${origin}`));
    },
    credentials: true
}));
// Aumenta limite para payloads JSON (ex.: imagens base64) e evita PayloadTooLargeError
app.use(express.json({ limit: '10mb' }));
// Simplificado: não exige mais código de confirmação; marca como verificado.
app.post('/api/email/resend-confirmation', async (req, res) => {
    try {
        const { email } = req.body || {};
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });
        const lower = String(email).toLowerCase();
        // Marca usuário como verificado se existir no arquivo ou DB
        try {
            const users = await readJsonFile('users.json');
            const idx = users.findIndex(u => String(u.email||'').toLowerCase() === lower);
            if (idx !== -1) {
                users[idx].emailVerified = true;
                await writeJsonFile('users.json', users);
                try { if (firebaseDb) await firebaseDb.collection('users').doc(String(users[idx].id)).set({ emailVerified: true }, { merge: true }); } catch {}
            }
        } catch {}
        // Também tentar no banco relacional
        try { await pool.query('UPDATE usuario SET emailVerified = 1 WHERE LOWER(email) = LOWER(?)', [lower]); } catch {}
        return res.json({ success: true, emailVerified: true });
    } catch (e) {
        console.error('Erro em POST /api/email/resend-confirmation', e);
        return res.status(500).json({ error: 'Erro interno' });
    }
});

// Simplificado: confirmação direta sem código
app.post('/api/email/confirm', async (req, res) => {
    try {
        const { email } = req.body || {};
        if (!email) return res.status(400).json({ error: 'E-mail é obrigatório' });
        const lower = String(email).toLowerCase();
        try {
            const users = await readJsonFile('users.json');
            const idx = users.findIndex(u => String(u.email||'').toLowerCase() === lower);
            if (idx !== -1) {
                users[idx].emailVerified = true;
                await writeJsonFile('users.json', users);
                try { if (firebaseDb) await firebaseDb.collection('users').doc(String(users[idx].id)).set({ emailVerified: true }, { merge: true }); } catch {}
            }
        } catch {}
        try { await pool.query('UPDATE usuario SET emailVerified = 1 WHERE LOWER(email) = LOWER(?)', [lower]); } catch {}
        return res.json({ success: true, emailVerified: true });
    } catch (e) {
        console.error('Erro em POST /api/email/confirm', e);
        return res.status(500).json({ error: 'Erro interno' });
    }
});

// (removido versão antiga de reset de senha; nova rota adicionada após inicialização do pool)

// Middleware para logar todas as requisições
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

// --- 3. Configuração do Banco de Dados e Segurança ---
// Objeto que armazena as credenciais do banco de dados, lidas do arquivo .env.

const dbConfig = {
    host: normalizedHost,
    port: normalizedPort,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    // Desativa SSL completamente
    ssl: false,
    enableKeepAlive: true,
    connectTimeout: 15000,
    waitForConnections: true,
    connectionLimit: 2,
    queueLimit: 0
};

// Em desenvolvimento reduzimos o custo do bcrypt para acelerar testes (removendo tempo de espera perceptível em erros de senha)
const saltRounds = (process.env.NODE_ENV === 'development') ? 4 : 10; // Define a complexidade da criptografia
const JWT_SECRET = 'IvyLindaMeuAmor'// Chave secreta para assinar os tokens JWT. Mude isso para algo aleatório e seguro.
const RECONNECT_INTERVAL_MS = parseInt(process.env.DB_RECONNECT_INTERVAL_MS || '60000', 10);


// --- 4. Função Auxiliar para Conexão ---
// Cria um pool de conexões com o banco de dados quando configurado
const pool = hasDbConfig ? mysql.createPool(dbConfig) : null;
// Flag que indica se o banco de dados está disponível; usado para ativar fallbacks em dev
let dbAvailable = hasDbConfig;

// Função para testar a conexão
async function testConnection() {
    if (!pool) {
        console.warn('[db] Pool indisponível (sem configuração). Teste de conexão pulado.');
        return false;
    }
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

// Testa conectividade básica com Firebase (Firestore). Faz escrita leve em documento de health.
async function testFirebase() {
    if (!firebaseDb) {
        console.error('[firebase] Instância Firestore ausente (db=null).');
        return false;
    }
    try {
        const pingDoc = firebaseDb.collection('_health').doc('startup');
        await pingDoc.set({ ts: new Date().toISOString() }, { merge: true });
        return true;
    } catch (e) {
        console.error('[firebase] Falha ao escrever ping:', e && e.message ? e.message : e);
        return false;
    }
}

// Rota segura para redefinição de senha (hash + tabela correta). Pode ser usada para "esqueci a senha" (sem exigir senha atual).
app.post('/api/reset-password', async (req, res) => {
    const startedAt = Date.now();
    try {
        const { email, newPassword } = req.body || {};
        if (!email || !newPassword) {
            return res.status(400).json({ success: false, error: 'E-mail e nova senha são obrigatórios.' });
        }

        const lower = String(email).toLowerCase();
        const hashed = await bcrypt.hash(newPassword, saltRounds);
        let updated = false;
        let source = 'unknown';

        if (dbAvailable) {
            try {
                const [rows] = await pool.query('UPDATE usuario SET senha = ? WHERE LOWER(email) = LOWER(?)', [hashed, lower]);
                if (rows && rows.affectedRows > 0) {
                    updated = true;
                    source = 'db';
                }
            } catch (e) {
                console.warn('Falha ao atualizar senha no banco, tentando fallback:', e.message || e);
            }
        }

        if (!updated) {
            // Fallback em arquivo JSON
            try {
                const users = await readJsonFile('users.json');
                const idx = users.findIndex(u => String(u.email || '').toLowerCase() === lower);
                if (idx === -1) {
                    return res.status(404).json({ success: false, error: 'E-mail não encontrado.' });
                }
                users[idx].senhaHash = hashed; // guarda hash
                if (users[idx].password) delete users[idx].password; // remove plain text se existir
                await writeJsonFile('users.json', users);
                updated = true;
                source = 'fallback';
            } catch (e) {
                console.error('Erro no fallback de redefinição de senha:', e);
                return res.status(500).json({ success: false, error: 'Erro interno ao atualizar senha (fallback).' });
            }
        }

        if (!updated) {
            return res.status(500).json({ success: false, error: 'Não foi possível atualizar a senha.' });
        }

        const ms = Date.now() - startedAt;
        return res.json({ success: true, email: lower, updatedIn: source, ms });
    } catch (e) {
        console.error('Erro em POST /api/reset-password', e);
        return res.status(500).json({ success: false, error: 'Erro interno' });
    }
});

async function getDbConnection() {
    if (!pool) {
        throw new Error('Pool de conexão indisponível (modo fallback sem banco).');
    }
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

// Lista usuários por tipo (contratante ou freelancer)
app.get('/api/users/:tipo', async (req, res) => {
    try {
        const tipo = String(req.params.tipo).toLowerCase();
        const users = await readJsonFile('users.json');
        const mappedType = tipo.includes('contrat') ? 'contratante' : (tipo.includes('free') ? 'freelancer' : tipo);
        const filtered = users.filter(u => String(u.userType).toLowerCase() === mappedType);
        res.json(filtered.map(u => ({ ...u, password: undefined })));
    } catch (e) {
        console.error('Erro em GET /api/users/:tipo', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// Social login (mock dev)
app.post('/api/social-login', async (req, res) => {
    try {
        const { provider, token } = req.body || {};
        if (!provider) return res.status(400).json({ error: 'provider é obrigatório' });
        const users = await readJsonFile('users.json');
        let user = users.find(u => u.email && String(u.email).startsWith(`social_${provider}@`));
        if (!user) {
            user = { id: generateId(), name: `Usuário ${provider}`, email: `social_${provider}@example.com`, userType: 'freelancer', createdAt: new Date().toISOString() };
            users.push(user);
            await writeJsonFile('users.json', users);
            try { if (firebaseDb) await firebaseDb.collection('users').doc(String(user.id)).set(user, { merge: true }); } catch {}
        }
        res.json({ user: { ...user, password: undefined }, token: 'mock-jwt' });
    } catch (e) {
        console.error('Erro em POST /api/social-login', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});
// Atualização de perfil do usuário (merge genérico de campos)
app.put('/api/users/:id', async (req, res) => {
    try {
        const id = String(req.params.id);
        const payload = req.body || {};
        const users = await readJsonFile('users.json');
        const idx = users.findIndex(u => String(u.id) === id);
        if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado' });
        // Campos que não devem ser sobrescritos diretamente
        const protectedKeys = new Set(['id']);
        const current = users[idx] || {};
        const updated = { ...current };
        // Merge seguro: arrays, strings e demais tipos simples
        for (const [key, value] of Object.entries(payload)) {
            if (protectedKeys.has(key)) continue;
            // normaliza alguns campos comuns
            if (key === 'languages' || key === 'skills') {
                updated[key] = Array.isArray(value) ? value : (Array.isArray(current[key]) ? current[key] : []);
            } else if (key === 'title' || key === 'bio' || key === 'name' || key === 'companyName' || key === 'photo') {
                updated[key] = value !== undefined ? value : current[key];
            } else {
                updated[key] = value !== undefined ? value : current[key];
            }
        }
        users[idx] = updated;
        await writeJsonFile('users.json', users);
        try { if (firebaseDb) await firebaseDb.collection('users').doc(id).set(updated, { merge: true }); } catch (e) {}
        res.json({ ...updated, password: undefined });
    } catch (e) {
        console.error('Erro em PUT /api/users/:id', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});
// Busca unificada: usuários, jobs, projects e mensagens (file/DB + Firebase best-effort)
app.get('/api/search', async (req, res) => {
    try {
        const q = (req.query.q || '').toString().trim().toLowerCase();
        if (!q || q.length < 2) return res.json({ users: [], jobs: [], projects: [], messages: [] });
        const users = await readJsonFile('users.json');
        const jobs = await readJsonFile('jobs.json');
        const projects = await readJsonFile('projects.json');
        const messagesLocal = await readJsonFile('messages.json');
        const usersRes = (users || []).filter(u => ((u.name||'')+(u.email||'')).toLowerCase().includes(q));
        const jobsRes = (jobs || []).filter(j => ((j.title||'')+(j.description||'')).toLowerCase().includes(q));
        const projectsRes = (projects || []).filter(p => ((p.title||'')+(p.description||'')).toLowerCase().includes(q));
        let messagesRes = (messagesLocal || []).filter(m => (m.content||'').toString().toLowerCase().includes(q));
        // Best-effort Firebase messages merge
        try {
            if (firebaseDb) {
                const snap = await firebaseDb.collection('messages').orderBy('createdAt','desc').limit(100).get();
                const fbMsgs = snap.docs.map(d => ({ id: d.id, ...(d.data()||{}) }));
                const filtered = fbMsgs.filter(m => (String(m.content||'').toLowerCase().includes(q)));
                // merge by id
                const byId = new Map(messagesRes.map(m => [String(m.id), m]));
                for (const m of filtered) { const k = String(m.id); if (!byId.has(k)) byId.set(k, m); }
                messagesRes = Array.from(byId.values());
            }
        } catch (e) {
            console.warn('[search] falha ao consultar Firebase:', e && e.message ? e.message : e);
        }
        res.json({ users: usersRes, jobs: jobsRes, projects: projectsRes, messages: messagesRes });
    } catch (e) {
        console.error('Erro em GET /api/search', e);
        res.status(500).json({ error: 'Erro interno' });
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
        let [messages] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, conteudo as content, data_envio as createdAt
             FROM mensagem
             WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
             ORDER BY data_envio ASC`,
            [user1, user2, user2, user1]
        );
        // Caso a coluna 'conteudo' não exista neste banco, tenta com possível alternativa 'mensagem'
        if (!messages || !Array.isArray(messages)) messages = [];

        // Gera token mínimo para usar na segunda etapa (pode conter apenas userId)
        const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '24h' });

        return res.status(201).json({ message: 'Usuário base criado.', userId, token });
    } catch (error) {
        console.error('Erro em /api/register-base:', error.message || error);
            // Tenta novamente com coluna alternativa 'mensagem'
            try {
                const [messagesAlt] = await getDbConnection().then(conn => conn.execute(
                    `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, mensagem as content, data_envio as createdAt
                     FROM mensagem
                     WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
                     ORDER BY data_envio ASC`,
                    [user1, user2, user2, user1]
                ).finally(conn => { try { conn.release(); } catch {} }));
                return res.json(messagesAlt);
            } catch (_) {}
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

        // Confirmação de senha removida: aceitar diretamente a senha enviada
        // (para restaurar, reintroduzir verificação de igualdade de campos)

        // Aceita alias de telefone também, para compatibilidade com clientes antigos (opcional)
        const phoneVal = phone || req.body.phone_number || req.body.telefone || req.body.telefone_celular || null;

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
            console.log('Tentando inserir usuário com os dados (confirmação de senha desativada):', {
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
                if (phoneVal) {
                    await connection.execute('UPDATE usuario SET telefone = ? WHERE id_usuario = ?', [phoneVal, userId]);
                }
            } catch (e) {
                console.warn('Não foi possível salvar telefone na tabela `usuario` (coluna possivelmente ausente). Salvando no fallback de usuários.');
                try {
                    const users = await readJsonFile('users.json');
                    users.push({ id: userId, name, email, phone: phoneVal, userType, createdAt: new Date().toISOString() });
                    await writeJsonFile('users.json', users);
                } catch (err) {
                    console.error('Erro ao salvar telefone no fallback:', err);
                }
            }

            // Insere dados específicos baseado no tipo de usuário
            if (userType === 'freelancer') {
                try {
                    await connection.execute(
                        'INSERT INTO freelancer (id_usuario, experiencia, habilidades, descricao) VALUES (?, ?, ?, ?)',
                        [userId, experience || '', skills || '', description || '']
                    );
                    console.log('Dados do freelancer inseridos com sucesso');
                } catch (e) {
                    console.warn('Falha ao inserir dados do freelancer; seguindo com cadastro básico. Motivo:', e && e.sqlMessage ? e.sqlMessage : e.message || String(e));
                    // Não aborta o cadastro: mantém usuário base criado
                }
                // Opcional: armazenar dados adicionais (cad/portfolio) no fallback file
                try {
                    const users = await readJsonFile('users.json');
                    const idx = users.findIndex(u => u.id === userId);
                    const merged = { id: userId, name, email, phone: phoneVal, userType, cad: req.body.cad || '', portfolio: req.body.portfolio || '', createdAt: new Date().toISOString() };
                    if (idx !== -1) users[idx] = { ...users[idx], ...merged }; else users.push(merged);
                    await writeJsonFile('users.json', users);
                } catch (_) {}
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

            // Confirmação de persistência: verifica se o usuário existe no banco
            try {
                const [confirmRows] = await connection.execute('SELECT id_usuario FROM usuario WHERE id_usuario = ?', [userId]);
                if (confirmRows && confirmRows.length > 0) {
                    console.log(`[registro] usuário persistido no DB com sucesso: id=${userId}`);
                } else {
                    console.warn(`[registro] usuário NÃO encontrado após commit: id=${userId} — verifique triggers/replicação.`);
                }
            } catch (confirmErr) {
                console.warn('[registro] falha ao confirmar persistência no DB:', confirmErr && confirmErr.message ? confirmErr.message : String(confirmErr));
            }

            // Gera o token JWT
            const token = jwt.sign(
                { userId, userType, email, name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Marca verificado imediatamente (fluxo sem confirmação de e-mail em dev)
            try {
                await connection.execute('UPDATE usuario SET email_verificado = 1 WHERE id_usuario = ?', [userId]);
            } catch (e) {
                console.warn('Coluna email_verificado ausente; mantendo verificação apenas na resposta.');
            }

            res.status(201).json({
                message: 'Usuário registrado com sucesso',
                token,
                user: {
                    id: userId,
                    name,
                    email,
                    userType,
                    emailVerified: true,
                    dbConfirmed: true
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

        // Busca o usuário pelo email (inclui foto quando existir)
        const [users] = await connection.execute(
            'SELECT id_usuario, nome, email, senha, tipo, foto FROM usuario WHERE email = ?',
            [email]
        );

        try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }

        if (users.length === 0) {
            // Fallback dev: busca em arquivo users.json se habilitado
            if (process.env.DEV_FILE_LOGIN === 'true') {
                try {
                    const fileUsers = await readJsonFile('users.json');
                    const fallback = fileUsers.find(u => (u.email||'').toLowerCase() === email.toLowerCase());
                    if (fallback && fallback.password === password) {
                        return res.json({
                            token: 'dev-fallback',
                            user: {
                                id: fallback.id,
                                name: fallback.name,
                                email: fallback.email,
                                userType: fallback.userType || 'contratante',
                                photo: fallback.photo || null
                            }
                        });
                    }
                } catch (e) {
                    console.warn('[login fallback] erro ao ler users.json', e.message);
                }
            }
            return res.status(401).json({ error: 'Usuário não encontrado.' });
        }

    const user = users[0];
    console.log(`[login] encontrado usuário id=${user.id_usuario}, hashLen=${user.senha ? user.senha.length : 0}`);

    // Verifica a senha
    const validPassword = await bcrypt.compare(password, user.senha);
    console.log(`[login] password match for email=${email}: ${validPassword}`);
        if (!validPassword) {
            // Fallback dev: tentar arquivo se senha hash não bate
            if (process.env.DEV_FILE_LOGIN === 'true') {
                try {
                    const fileUsers = await readJsonFile('users.json');
                    const fallback = fileUsers.find(u => (u.email||'').toLowerCase() === email.toLowerCase());
                    if (fallback && fallback.password === password) {
                        return res.json({
                            token: 'dev-fallback',
                            user: {
                                id: fallback.id,
                                name: fallback.name,
                                email: fallback.email,
                                userType: fallback.userType || users[0].tipo,
                                photo: fallback.photo || null
                            }
                        });
                    }
                } catch (e) {
                    console.warn('[login fallback senha] erro ao ler users.json', e.message);
                }
            }
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
                userType: user.tipo,
                photo: user.foto || null
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
                SELECT u.id_usuario as id, u.nome as name, u.email, u.foto as photo, c.nome_empresa as companyName
                FROM usuario u
                JOIN contratante c ON u.id_usuario = c.id_usuario
                WHERE u.tipo = ?
            `;
        } else {
            query = `
                SELECT id_usuario as id, nome as name, email, foto as photo
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

// Atualizar foto de perfil do usuário
app.put('/api/users/:id/photo', async (req, res) => {
    const userId = req.params.id;
    const { photo } = req.body || {};
    if (!photo) return res.status(400).json({ error: 'Campo photo é obrigatório (URL ou data string).' });
    let connection;
    try {
        if (!dbAvailable) {
            const users = await readJsonFile('users.json');
            const idx = users.findIndex(u => String(u.id) === String(userId));
            if (idx !== -1) {
                users[idx].photo = photo;
                await writeJsonFile('users.json', users);
            } else {
                users.push({ id: isNaN(Number(userId)) ? userId : Number(userId), photo });
                await writeJsonFile('users.json', users);
            }
            try { if (firebaseDb) await firebaseDb.collection('users').doc(String(userId)).set({ photo }, { merge: true }); } catch {}
            return res.json({ ok: true, id: userId, photo });
        }
        connection = await getDbConnection();
        // Atualiza na tabela usuario se a coluna existir
        try {
            await connection.execute('UPDATE usuario SET foto = ? WHERE id_usuario = ?', [photo, userId]);
        } catch (e) {
            console.warn('Coluna `foto` ausente em usuario; ignorando atualização no DB:', e && e.code);
        }
        try { if (firebaseDb) await firebaseDb.collection('users').doc(String(userId)).set({ photo }, { merge: true }); } catch (fbErr) {
            console.warn('Falha ao espelhar foto no Firebase:', fbErr && fbErr.message ? fbErr.message : fbErr);
        }
        res.json({ ok: true, id: userId, photo });
    } catch (error) {
        console.error('Erro ao atualizar foto:', error);
        res.status(500).json({ error: 'Erro interno ao atualizar foto' });
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

// Suporte novo e antigo: query params (user1/user2) e route params (:userId/:contactId)
app.get('/api/messages', async (req, res) => {
    const { user1, user2 } = req.query;
    if (!user1 || !user2) return res.status(400).json({ error: 'Parâmetros user1 e user2 são necessários.' });
    // Tenta buscar também no Firebase quando disponível (best-effort merge)
    try {
        if (firebaseDb) {
            const snap = await firebaseDb.collection('messages')
                .where('senderId', 'in', [Number(user1), String(user1)])
                .get();
            // Nota: consultas compostas no Firestore são limitadas; manteremos fonte principal no SQL/arquivo.
        }
    } catch {}
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(user1) && String(m.receiverId) === String(user2)) || (String(m.senderId) === String(user2) && String(m.receiverId) === String(user1)));
            return res.json(filtered);
        } catch (e) {
            console.error('Erro ao ler mensagens fallback:', e);
            return res.status(500).json({ error: 'Erro interno' });
        }
    }
    let connection;
    try {
        connection = await getDbConnection();
        const [messages] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, conteudo as content, data_envio as createdAt
             FROM mensagem
             WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
             ORDER BY data_envio ASC`,
            [user1, user2, user2, user1]
        );
        res.json(messages);
    } catch (error) {
        console.error('Erro ao buscar mensagens (query):', error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] ER_BAD_FIELD_ERROR; ativando fallback file.');
            dbAvailable = false;
        }
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(user1) && String(m.receiverId) === String(user2)) || (String(m.senderId) === String(user2) && String(m.receiverId) === String(user1)));
            return res.json(filtered);
        } catch (e) {
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
    } finally { if (connection) try { connection.release(); } catch (e) {} }
});

app.get('/api/messages/:userId/:contactId', async (req, res) => {
    const { userId, contactId } = req.params;
    // idem: fonte principal permanece SQL/arquivo; Firebase é apenas espelho de escrita
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(userId) && String(m.receiverId) === String(contactId)) || (String(m.senderId) === String(contactId) && String(m.receiverId) === String(userId)));
            return res.json(filtered);
        } catch (e) {
            console.error('Erro ao ler mensagens fallback:', e);
            return res.status(500).json({ error: 'Erro interno' });
        }
    }
    let connection;
    try {
        connection = await getDbConnection();
        let [messages] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, conteudo as content, data_envio as createdAt
             FROM mensagem
             WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
             ORDER BY data_envio ASC`,
            [userId, contactId, contactId, userId]
        );
        if (!messages || !Array.isArray(messages)) messages = [];
        res.json(messages);
    } catch (error) {
        console.error('Erro ao buscar mensagens:', error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] ER_BAD_FIELD_ERROR; ativando fallback file.');
            dbAvailable = false;
            try {
                const [messagesAlt] = await getDbConnection().then(conn => conn.execute(
                    `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, mensagem as content, data_envio as createdAt
                     FROM mensagem
                     WHERE (id_remetente = ? AND id_destinatario = ?) OR (id_remetente = ? AND id_destinatario = ?)
                     ORDER BY data_envio ASC`,
                    [userId, contactId, contactId, userId]
                ).finally(conn => { try { conn.release(); } catch {} }));
                return res.json(messagesAlt);
            } catch (_) {}
        }
        try {
            const msgs = await readJsonFile('messages.json');
            const filtered = (msgs || []).filter(m => (String(m.senderId) === String(userId) && String(m.receiverId) === String(contactId)) || (String(m.senderId) === String(contactId) && String(m.receiverId) === String(userId)));
            return res.json(filtered);
        } catch (e) { return res.status(500).json({ error: 'Erro interno do servidor' }); }
    } finally { if (connection) try { connection.release(); } catch (e) {} }
});

// Resumo de conversas: último evento por contato para um usuário
app.get('/api/messages/summary', async (req, res) => {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ error: 'userId é necessário' });

    // Fallback por arquivo
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const byOther = {};
            const uid = String(userId);
            // Ordena por createdAt desc para pegar primeiro por contato
            const sorted = (msgs || []).slice().sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
            for (const m of sorted) {
                const a = String(m.senderId);
                const b = String(m.receiverId);
                if (a !== uid && b !== uid) continue;
                const other = a === uid ? b : a;
                if (!byOther[other]) {
                    byOther[other] = {
                        otherUserId: isNaN(Number(other)) ? other : Number(other),
                        id: m.id,
                        senderId: m.senderId,
                        receiverId: m.receiverId,
                        content: m.content,
                        createdAt: m.createdAt,
                    };
                }
            }
            return res.json(Object.values(byOther));
        } catch (e) {
            console.error('Erro em GET /api/messages/summary (fallback):', e);
            return res.status(500).json({ error: 'Erro interno' });
        }
    }

    // Modo DB: buscar últimas mensagens por contato do usuário
    let connection;
    try {
        connection = await getDbConnection();
        const uid = userId;
        // Seleciona todas mensagens do usuário ordenadas (desc) e consolida por contato no Node
        let [rows] = await connection.execute(
            `SELECT id_mensagem as id, id_remetente as senderId, id_destinatario as receiverId, conteudo as content, data_envio as createdAt
             FROM mensagem
             WHERE id_remetente = ? OR id_destinatario = ?
             ORDER BY data_envio DESC`,
            [uid, uid]
        );
        // Se a coluna 'conteudo' não existir, tenta coluna 'mensagem'
        if (!rows || !Array.isArray(rows)) rows = [];
        const byOther = {};
        for (const m of rows) {
            const a = String(m.senderId);
            const b = String(m.receiverId);
            const uidS = String(uid);
            const other = a === uidS ? b : a;
            if (!byOther[other]) {
                byOther[other] = {
                    otherUserId: isNaN(Number(other)) ? other : Number(other),
                    id: m.id,
                    senderId: isNaN(Number(m.senderId)) ? m.senderId : Number(m.senderId),
                    receiverId: isNaN(Number(m.receiverId)) ? m.receiverId : Number(m.receiverId),
                    content: m.content,
                    createdAt: m.createdAt,
                };
            }
        }
        return res.json(Object.values(byOther));
    } catch (error) {
        console.error('Erro em GET /api/messages/summary (DB):', error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
            console.warn('[DB] ER_BAD_FIELD_ERROR; ativando fallback file.');
            dbAvailable = false;
            try {
                const msgs = await readJsonFile('messages.json');
                const byOther = {};
                const uid = String(userId);
                const sorted = (msgs || []).slice().sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
                for (const m of sorted) {
                    const a = String(m.senderId);
                    const b = String(m.receiverId);
                    if (a !== uid && b !== uid) continue;
                    const other = a === uid ? b : a;
                    if (!byOther[other]) {
                        byOther[other] = {
                            otherUserId: isNaN(Number(other)) ? other : Number(other),
                            id: m.id,
                            senderId: m.senderId,
                            receiverId: m.receiverId,
                            content: m.content,
                            createdAt: m.createdAt,
                        };
                    }
                }
                return res.json(Object.values(byOther));
            } catch (e) {
                return res.status(500).json({ error: 'Erro interno' });
            }
        }
        return res.status(500).json({ error: 'Erro interno do servidor' });
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

// Rota para enviar uma mensagem
app.post('/api/messages', async (req, res) => {
    let { senderId, receiverId, content } = req.body || {};
    if (!senderId || !receiverId || content === undefined || content === null) {
        return res.status(400).json({ error: 'Dados da mensagem incompletos. senderId, receiverId e content são necessários.' });
    }
    if (typeof content === 'object') { try { content = JSON.stringify(content); } catch { content = String(content); } }
    const sId = Number(senderId);
    const rId = Number(receiverId);
    if (!dbAvailable) {
        try {
            const msgs = await readJsonFile('messages.json');
            const id = generateId();
            const newMessage = { id, senderId: isNaN(sId) ? senderId : sId, receiverId: isNaN(rId) ? receiverId : rId, content, createdAt: new Date().toISOString() };
            msgs.push(newMessage);
            await writeJsonFile('messages.json', msgs);
            // também tenta persistir no Firebase (best-effort)
            try {
                if (firebaseDb) {
                    await firebaseDb.collection('messages').doc(String(newMessage.id)).set(newMessage);
                }
            } catch (fbErr) {
                console.warn('Falha ao salvar mensagem no Firebase (fallback mode):', fbErr && fbErr.message ? fbErr.message : fbErr);
            }
            return res.status(201).json(newMessage);
        } catch (e) {
            console.error('Erro ao gravar mensagem fallback:', e);
            return res.status(500).json({ error: 'Erro interno ao gravar mensagem (fallback)', details: e && e.message ? e.message : String(e) });
        }
    }

    let connection;
    try {
        connection = await getDbConnection();
                let result;
                try {
                        [result] = await connection.execute(
                            'INSERT INTO mensagem (id_remetente, id_destinatario, conteudo, data_envio) VALUES (?, ?, ?, NOW())',
                            [isNaN(sId) ? senderId : sId, isNaN(rId) ? receiverId : rId, content]
                        );
                } catch (e) {
                        if (e && e.code === 'ER_BAD_FIELD_ERROR') {
                                // Tenta inserir usando coluna alternativa 'mensagem'
                                const [resultAlt] = await connection.execute(
                                    'INSERT INTO mensagem (id_remetente, id_destinatario, mensagem, data_envio) VALUES (?, ?, ?, NOW())',
                                    [isNaN(sId) ? senderId : sId, isNaN(rId) ? receiverId : rId, content]
                                );
                                result = resultAlt;
                        } else {
                                throw e;
                        }
                }
                const newMessage = { id: result.insertId, senderId: isNaN(sId) ? senderId : sId, receiverId: isNaN(rId) ? receiverId : rId, content, createdAt: new Date().toISOString() };
                // persistência espeelho no Firebase (best-effort)
                try {
                    if (firebaseDb) {
                        await firebaseDb.collection('messages').doc(String(newMessage.id)).set(newMessage);
                    }
                } catch (fbErr) {
                    console.warn('Falha ao salvar mensagem no Firebase (DB mode):', fbErr && fbErr.message ? fbErr.message : fbErr);
                }
                res.status(201).json(newMessage);
    } catch (error) {
        console.error('Erro ao enviar mensagem:', error && error.stack ? error.stack : error);
        if (error && error.code === 'ER_BAD_FIELD_ERROR') {
          console.warn('[DB] ER_BAD_FIELD_ERROR insert; ativando fallback.');
          dbAvailable = false;
        }
        try {
          const msgs = await readJsonFile('messages.json');
          const id = generateId();
          const fallbackMessage = { id, senderId: isNaN(sId) ? senderId : sId, receiverId: isNaN(rId) ? receiverId : rId, content, createdAt: new Date().toISOString() };
          msgs.push(fallbackMessage);
                    await writeJsonFile('messages.json', msgs);
                    try {
                        if (firebaseDb) {
                            await firebaseDb.collection('messages').doc(String(fallbackMessage.id)).set(fallbackMessage);
                        }
                    } catch (fbErr) {
                        console.warn('Falha ao salvar mensagem no Firebase (on error fallback):', fbErr && fbErr.message ? fbErr.message : fbErr);
                    }
                    return res.status(201).json(fallbackMessage);
        } catch (e) {
          return res.status(500).json({ error: 'Erro interno ao salvar mensagem (fallback)', details: e && e.message ? e.message : String(e) });
        }
    } finally {
        if (connection) try { connection.release(); } catch (e) {}
    }
});

// Upload de arquivos (imagens) para Firebase Storage, retorna URL pública
const upload = multer({ storage: multer.memoryStorage() });
app.post('/api/upload', upload.single('arquivo'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
        // bucket via firebase-admin
        let bucket;
        try {
            const admin = require('firebase-admin');
            bucket = admin.storage().bucket();
        } catch (e) {
            console.error('Firebase admin indisponível para Storage:', e);
            return res.status(500).json({ error: 'Storage não configurado' });
        }
        const name = `${uuidv4()}-${(req.file.originalname || 'upload').replace(/\s+/g, '-')}`;
        const file = bucket.file(name);
        await file.save(req.file.buffer, {
            contentType: req.file.mimetype || 'application/octet-stream',
            public: true,
            metadata: { firebaseStorageDownloadTokens: uuidv4() }
        });
        const publicUrl = `https://storage.googleapis.com/${bucket.name}/${encodeURIComponent(name)}`;
        return res.json({ url: publicUrl });
    } catch (err) {
        console.error('Erro no upload:', err);
        return res.status(500).json({ error: 'Erro ao fazer upload' });
    }
});

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

function generateId() { return Date.now() + Math.floor(Math.random() * 10000); }

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

// Cria notificação de mensagem (fallback arquivo; em DB mode também usa arquivo simples)
app.post('/api/notifications', async (req, res) => {
    try {
        const { ownerId, fromId, type = 'message', content = '' } = req.body || {};
        if (!ownerId || fromId == null) {
            return res.status(400).json({ error: 'ownerId e fromId são obrigatórios' });
        }
        const notes = await readJsonFile('notifications.json');
        const note = {
            id: generateId(),
            userId: ownerId,
            ownerId,
            fromId,
            type,
            content: String(content || '').slice(0, 200),
            read: false,
            createdAt: new Date().toISOString(),
        };
        notes.push(note);
        await writeJsonFile('notifications.json', notes);
        return res.status(201).json(note);
    } catch (e) {
        console.error('Erro em POST /api/notifications:', e);
        return res.status(500).json({ error: 'Erro interno' });
    }
});

// Marca notificações de chat como lidas para um par ownerId/otherUserId
app.post('/api/notifications/mark-chat-read', async (req, res) => {
    try {
        const { ownerId, otherUserId } = req.body || {};
        if (!ownerId || otherUserId == null) {
            return res.status(400).json({ error: 'ownerId e otherUserId são obrigatórios' });
        }
        const notes = await readJsonFile('notifications.json');
        let changed = false;
        for (let i = 0; i < notes.length; i++) {
            const n = notes[i];
            if (String(n.ownerId) === String(ownerId) && String(n.fromId) === String(otherUserId) && !n.read) {
                notes[i] = { ...n, read: true, updatedAt: new Date().toISOString() };
                changed = true;
            }
        }
        if (changed) await writeJsonFile('notifications.json', notes);
        return res.json({ success: true });
    } catch (e) {
        console.error('Erro em POST /api/notifications/mark-chat-read:', e);
        return res.status(500).json({ error: 'Erro interno' });
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
 
// Inicialização do servidor
const PORT = process.env.PORT || 3000;

// Função para iniciar o servidor
async function startServer() {
    try {
        // 1. Verifica Firebase antes de qualquer coisa (pode ser pulado em dev)
        const skipFb = String(process.env.SKIP_FIREBASE_CHECK || '').toLowerCase() === 'true' || process.env.SKIP_FIREBASE_CHECK === '1';
        const requireFirebase = String(process.env.REQUIRE_FIREBASE || '').toLowerCase() === 'true';
        const firebaseConfigured = Boolean(firebaseDb);
        if (!skipFb && firebaseConfigured) {
            const firebaseOk = await testFirebase();
            if (!firebaseOk) {
                if (requireFirebase) {
                    console.error('❌ Firebase não disponível e REQUIRE_FIREBASE=true. Abortando inicialização.');
                    process.exit(1);
                }
                console.warn('⚠️ Firebase indisponível; continuando sem sincronização em tempo real. Defina REQUIRE_FIREBASE=true para tornar isso fatal.');
            } else {
                console.log('✅ Firebase verificado com sucesso. Prosseguindo.');
            }
        } else if (!firebaseConfigured) {
            console.warn('[firebase] Credenciais não configuradas — executando em modo sem Firebase.');
        } else {
            console.warn('[startup] SKIP_FIREBASE_CHECK=true — pulando verificação do Firebase (uso apenas em desenvolvimento).');
        }
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
            // Tentativa de reconexão automática ao DB quando iniciado em modo fallback
            if (!dbAvailable && pool && RECONNECT_INTERVAL_MS > 0) {
                setInterval(async () => {
                    try {
                        const ok = await testConnection();
                        if (ok) {
                            dbAvailable = true;
                            console.log('[db] conexão restabelecida; saindo do modo fallback.');
                        }
                    } catch (_) {
                        // mantém fallback
                    }
                }, RECONNECT_INTERVAL_MS);
                console.log(`[db] modo fallback ativo; tentará reconectar a cada ${RECONNECT_INTERVAL_MS}ms.`);
            }
        });
    } catch (error) {
        console.error('Erro ao iniciar o servidor:', error);
        process.exit(1);
    }
}

// Inicia o servidor
startServer();