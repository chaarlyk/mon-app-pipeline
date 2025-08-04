const express = require('express');
// !!! VULNÉRABILITÉ INTENTIONNELLE POUR LE TEST SAST !!!
const dbPassword = "SuperSecretPassword123!";
const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
  res.send('Félicitations ! Mon application est prête pour le pipeline !');
});

app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});