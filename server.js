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
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_DATABASE'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Erro: Variável de ambiente ${envVar} não está definida!`);
        process.exit(1);
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
        await connection.end();
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
            companyName,  // apenas para contratante
            description, 
            skills,       // apenas para freelancer
            experience    // apenas para freelancer
        } = req.body;

        // Validações básicas
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Nome, email e senha são obrigatórios.' });
        }

        if (userType !== 'freelancer' && userType !== 'contratante') {
            return res.status(400).json({ error: 'Tipo de usuário inválido.' });
        }

        // Validações específicas por tipo
        if (userType === 'contratante' && !companyName) {
            return res.status(400).json({ error: 'Nome da empresa é obrigatório para contratantes.' });
        }

        connection = await getDbConnection();
        await connection.beginTransaction();

        // Verifica se o email já existe
        const [existingUsers] = await connection.execute(
            'SELECT id_usuario FROM usuario WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            await connection.end();
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
            await connection.end();
        }

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

        const connection = await getDbConnection();

        // Busca o usuário pelo email
        const [users] = await connection.execute(
            'SELECT id_usuario, nome, email, senha, tipo FROM usuario WHERE email = ?',
            [email]
        );

        await connection.end();

        if (users.length === 0) {
            return res.status(401).json({ error: 'Usuário não encontrado.' });
        }

        const user = users[0];

        // Verifica a senha
        const validPassword = await bcrypt.compare(password, user.senha);
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

// Inicialização do servidor
const PORT = process.env.PORT || 3000;

// Função para iniciar o servidor
async function startServer() {
    try {
        // Testa a conexão com o banco antes de iniciar o servidor
        const isConnected = await testConnection();
        if (!isConnected) {
            console.error('Não foi possível estabelecer conexão com o banco de dados. Servidor não iniciado.');
            process.exit(1);
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