// firebase.js
const admin = require('firebase-admin');
const fs = require('fs');

// Metadados do projeto Firebase (fornecidos pelo usuário)
// Nome: trampoff
// ID do projeto: trampoff-aa483
// Número do projeto: 268221991123
const PROJECT_META = {
  name: 'trampoff',
  projectId: 'trampoff-aa483',
  projectNumber: '268221991123'
};

function loadServiceAccountFromEnv() {
  const projectId = process.env.FIREBASE_PROJECT_ID || PROJECT_META.projectId;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (privateKey && privateKey.includes('\\n')) privateKey = privateKey.replace(/\\n/g, '\n');
  if (projectId && clientEmail && privateKey) {
    return { projectId, clientEmail, privateKey };
  }
  return null;
}

try {
  let serviceAccount;
  // 1) Caminho customizado via env (GOOGLE_APPLICATION_CREDENTIALS / FIREBASE_CREDENTIALS_PATH)
  const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || process.env.FIREBASE_CREDENTIALS_PATH;
  if (credPath && fs.existsSync(credPath)) {
    serviceAccount = JSON.parse(fs.readFileSync(credPath, 'utf8'));
  }
  // 2) serviceAccountKey.json local (usar caminho absoluto)
  if (!serviceAccount) {
    try {
      const path = require('path');
      const localPath = path.join(__dirname, 'serviceAccountKey.json');
      if (fs.existsSync(localPath)) {
        serviceAccount = JSON.parse(fs.readFileSync(localPath, 'utf8'));
      }
    } catch (_) {}
  }
  // 3) Variáveis de ambiente (PROJECT_ID/CLIENT_EMAIL/PRIVATE_KEY)
  if (!serviceAccount) {
    const envCred = loadServiceAccountFromEnv();
    if (envCred) {
      serviceAccount = {
        project_id: envCred.projectId,
        client_email: envCred.clientEmail,
        private_key: envCred.privateKey
      };
    }
  }

  if (!serviceAccount) throw new Error('Credenciais do Firebase não encontradas.');

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: serviceAccount.project_id || PROJECT_META.projectId,
      clientEmail: serviceAccount.client_email,
      privateKey: serviceAccount.private_key
    }),
    projectId: serviceAccount.project_id || PROJECT_META.projectId
  });

  const db = admin.firestore();
  console.log('\x1b[32m%s\x1b[0m', '✓ Firebase Admin SDK inicializado com sucesso!');
  console.log('Projeto Firebase:', PROJECT_META);
  module.exports = { db, PROJECT_META };
} catch (error) {
  console.error('\x1b[31m%s\x1b[0m', '✗ Erro ao inicializar o Firebase Admin SDK:');
  console.error('  - Forneça credenciais via arquivo serviceAccountKey.json, GOOGLE_APPLICATION_CREDENTIALS/FIREBASE_CREDENTIALS_PATH, ou variáveis FIREBASE_PROJECT_ID/FIREBASE_CLIENT_EMAIL/FIREBASE_PRIVATE_KEY.');
  console.error('  - Detalhes do erro:', error.message);
  module.exports = { db: null, PROJECT_META };
}
