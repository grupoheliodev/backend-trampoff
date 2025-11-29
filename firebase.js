// firebase.js
const admin = require('firebase-admin');

// Metadados do projeto Firebase (fornecidos pelo usuário)
// Nome: trampoff
// ID do projeto: trampoff-aa483
// Número do projeto: 268221991123
const PROJECT_META = {
  name: 'trampoff',
  projectId: 'trampoff-aa483',
  projectNumber: '268221991123'
};

// !!! AÇÃO NECESSÁRIA !!!
// 1. Baixe o arquivo de chave de serviço da sua conta do Firebase:
//    - Vá para o Console do Firebase -> Configurações do projeto -> Contas de serviço.
//    - Clique em "Gerar nova chave privada" e baixe o arquivo JSON.
// 2. Renomeie o arquivo para "serviceAccountKey.json".
// 3. Coloque o arquivo "serviceAccountKey.json" na raiz do seu projeto backend (`backend-trampoff`).
// 4. Certifique-se de que este arquivo NÃO seja enviado para o seu repositório Git, adicionando-o ao .gitignore.

try {
  const serviceAccount = require('./serviceAccountKey.json');

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: PROJECT_META.projectId
  });

  const db = admin.firestore();
  console.log('\x1b[32m%s\x1b[0m', '✓ Firebase Admin SDK inicializado com sucesso!');
  console.log('Projeto Firebase:', PROJECT_META);
  module.exports = { db, PROJECT_META };
} catch (error) {
  console.error('\x1b[31m%s\x1b[0m', '✗ Erro ao inicializar o Firebase Admin SDK:');
  console.error('  - Certifique-se de que o arquivo "serviceAccountKey.json" existe na raiz do projeto backend.');
  console.error('  - Detalhes do erro:', error.message);
  // Se o SDK não inicializar, exportamos um objeto `db` mock para evitar que a aplicação quebre.
  // As operações do Firestore irão falhar.
  module.exports = { db: null, PROJECT_META };
}
