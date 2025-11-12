// scripts/hash_existing_passwords.js
// Script para atualizar senhas em texto simples no banco para bcrypt-hashed.
// Uso: node scripts/hash_existing_passwords.js

const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

async function main() {
  const dbConfig = {
    host: (process.env.DB_HOST || 'localhost').split(':')[0],
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_DATABASE,
  };

  if (!dbConfig.user || !dbConfig.database) {
    console.error('Por favor defina DB_USER e DB_DATABASE no .env antes de rodar este script.');
    process.exit(1);
  }

  const pool = mysql.createPool({ ...dbConfig, waitForConnections: true, connectionLimit: 5 });
  const connection = await pool.getConnection();

  try {
    const [rows] = await connection.execute('SELECT id_usuario, senha FROM usuario');
    console.log(`Encontrados ${rows.length} usuários. Verificando senhas...`);

    const bcryptRegex = /^\$2[aby]\$/; // checks prefix like $2b$
    let updated = 0;

    for (const r of rows) {
      const id = r.id_usuario;
      const senha = r.senha || '';

      // Heurística simples: se não começa com $2b$/$2a$ então rehash
      if (!/^\$2[aby]\$/.test(senha)) {
        const hash = await bcrypt.hash(senha, 10);
        await connection.execute('UPDATE usuario SET senha = ? WHERE id_usuario = ?', [hash, id]);
        updated++;
        console.log(`Usuário ${id}: senha atualizada para hash.`);
      } else {
        console.log(`Usuário ${id}: senha já em hash, pulando.`);
      }
    }

    console.log(`Finalizado. Senhas atualizadas: ${updated}`);
  } catch (e) {
    console.error('Erro ao atualizar senhas:', e);
  } finally {
    try { connection.release(); } catch (e) { try { await connection.end(); } catch (e2) {} }
    await pool.end();
  }
}

main();
