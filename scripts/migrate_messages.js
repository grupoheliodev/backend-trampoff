const fs = require('fs')
const path = require('path')
const mysql = require('mysql2/promise')

async function main() {
  const config = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'freelas',
  }

  console.log('Conectando ao banco com configurações:', { host: config.host, port: config.port, user: config.user, database: config.database })

  const conn = await mysql.createConnection(config)
  try {
    console.log('Conectado. Inspecionando colunas da tabela `mensagem`...')
    const [cols] = await conn.execute("SHOW COLUMNS FROM mensagem")
    const columnNames = cols.map(c => c.Field)
    console.log('Colunas encontradas:', columnNames)

    // Backup the current rows to a JSON file in project folder
    const [rows] = await conn.execute('SELECT * FROM mensagem')
    const backupDir = path.resolve(__dirname, '..', 'db_backups')
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true })
    const backupFile = path.join(backupDir, `mensagem_backup_${Date.now()}.json`)
    fs.writeFileSync(backupFile, JSON.stringify(rows, null, 2), 'utf8')
    console.log('Backup de `mensagem` salvo em', backupFile)

    const alterations = []
    if (!columnNames.includes('conteudo')) {
      alterations.push('ADD COLUMN conteudo TEXT')
    }
    if (!columnNames.includes('data_envio')) {
      alterations.push("ADD COLUMN data_envio DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP")
    }

    if (alterations.length === 0) {
      console.log('Nenhuma alteração necessária — colunas já existem.')
    } else {
      const alterSql = `ALTER TABLE mensagem ${alterations.join(', ')}`
      console.log('Executando:', alterSql)
      await conn.execute(alterSql)
      console.log('ALTER TABLE executado com sucesso.')
    }

    // Optional: create an index if not present
    try {
      await conn.execute('CREATE INDEX IF NOT EXISTS idx_mensagem_pair_date ON mensagem (id_remetente, id_destinatario, data_envio)')
      console.log('Índice `idx_mensagem_pair_date` criado (ou já existia).')
    } catch (e) {
      // MySQL older versions don't support IF NOT EXISTS for CREATE INDEX — ignore duplicate index error
      if (e && e.code === 'ER_DUP_KEYNAME') {
        console.log('Índice já existe.')
      } else {
        console.log('Aviso ao criar índice:', e.message || e)
      }
    }

  } finally {
    await conn.end()
  }
}

main().catch(err => {
  console.error('Erro no script de migração:', err)
  process.exit(1)
})
