// index.js
import express from 'express';
import oauthRoutes from './oauthRoutes.js';
import { initDB } from './db.js';
import { PORT } from './config.js';
// L'import de discordBot démarre le bot (il exporte également le client si besoin)
import './discordBot.js';

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
