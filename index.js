const express = require('express');
const oauthRoutes = require('./oauthRoutes');
const { initDB } = require('./db');
const { PORT } = require('./config');
// L'import de discordBot démarre le bot (il exporte également le client si besoin)
require('./discordBot');
require('./del');

const app = express();
app.use(express.json());

// Montage des routes OAuth2
app.use('/', oauthRoutes);

app.get("/", (req, res) => {
  res.send("Bienvenue sur l'application AutentiBot.");
});

app.listen(PORT, async () => {
  console.log(`Serveur Express démarré sur le port ${PORT}`);
  await initDB();
});
