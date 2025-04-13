const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { CLIENT_ID, CLIENT_SECRET, SERVER_URL } = require('./config');
const { isValidBase64, isValidToken } = require('./utils');
const { processSubmission } = require('./db');

const tempDataStore = new Map();
const router = express.Router();

// Route de login
router.get('/login:routeSuffix?', (req, res) => {
  const mode = req.query.mode === "high" ? "high" : "basic";
  if (mode !== "high") {
    return res.status(400).send("La vérification basique ne nécessite pas OAuth2.");
  }
  
  const origGuildId = req.query.guildId || "";
  const stateData = {
    guildId: origGuildId,
    nonce: crypto.randomBytes(8).toString('hex')
  };
  const state = Buffer.from(JSON.stringify(stateData)).toString('base64');

  // Ici, l'URL générée ne change pas (côté Discord, c'est le bot qui génère le lien dynamique)
  const redirectUri = encodeURIComponent(`${SERVER_URL}/callback${req.params.routeSuffix || ""}?mode=high`);
  const scope = encodeURIComponent("identify email guilds");
  const oauthUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${encodeURIComponent(state)}`;
  console.log(`[OAuth] URL générée: ${oauthUrl}`);
  res.redirect(oauthUrl);
});

// Route de callback
router.get('/callback:routeSuffix?', async (req, res) => {
  const mode = req.query.mode === "high" ? "high" : "basic";
  const code = req.query.code;
  if (!code) {
    console.log("[Callback] Aucun code reçu.");
    return res.status(400).send("Code d'autorisation manquant.");
  }
  const baseUrl = SERVER_URL.replace(/\/$/, "");
  
  let originatingGuildId = "";
  const state = req.query.state;
  if (state) {
    try {
      const decodedState = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
      originatingGuildId = decodedState.guildId || "";
    } catch (ex) {
      console.error("Erreur lors du décodage du state", ex);
    }
  }
  
  const data = new URLSearchParams();
  data.append("client_id", CLIENT_ID);
  data.append("client_secret", CLIENT_SECRET);
  data.append("grant_type", "authorization_code");
  data.append("code", code);
  data.append("redirect_uri", `${baseUrl}/callback${req.params.routeSuffix || ""}?mode=high`);
  
  try {
    const tokenResponse = await axios.post("https://discord.com/api/oauth2/token", data.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });
    const accessToken = tokenResponse.data.access_token;
    console.log("[Callback] Token obtenu:", accessToken);
    
    const userResponse = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userData = userResponse.data;
    console.log("[Callback] Données utilisateur:", userData);
    const encodedUserId = Buffer.from(userData.id, "utf8").toString("base64");
    
    let redirectUrl = "";
    if (mode === "high") {
      const guildsResponse = await axios.get("https://discord.com/api/users/@me/guilds", {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const guildList = guildsResponse.data;
      console.log("[Callback] Liste des guildes:", guildList);
      
      const tempToken = crypto.randomBytes(16).toString("hex");
      const tmpData = { email: userData.email, guilds: guildList, timestamp: Date.now() };
      tempDataStore.set(tempToken, tmpData);
      
      const encodedGuildId = originatingGuildId ? Buffer.from(originatingGuildId, "utf8").toString("base64") : "";
      // Utilisation du suffix dynamique présent dans req.params.routeSuffix (ex : "-test", "-BLZ", etc.)
      redirectUrl = `${baseUrl}/collect${req.params.routeSuffix || ""}?userId=${encodedUserId}&token=${tempToken}&mode=high${encodedGuildId ? `&guildId=${encodedGuildId}` : ""}`;
      console.log("[Callback] Mode high: données temporaires stockées, token généré.");
    }
    
    res.send(`
      <html>
        <head>
          <meta http-equiv="refresh" content="5;url=${redirectUrl || '#'}" />
        </head>
        <body>
          <p>Première étape réussie. Redirection en cours...</p>
          <p>Si la redirection ne s'effectue pas, <a href="${redirectUrl || '#'}">cliquez ici</a>.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("[Callback] Erreur durant OAuth2:", err.message);
    res.status(500).send("Erreur durant l'authentification.");
  }
});

// Route de collecte
router.get('/collect:routeSuffix?', async (req, res) => {
  const encodedUserId = req.query.userId;
  if (!encodedUserId || typeof encodedUserId !== 'string' || !isValidBase64(encodedUserId)) {
    console.error("[Collect] userId manquant ou invalide.");
    return res.status(400).send("Lien invalide.");
  }
  const encodedGuildId = req.query.guildId || "";
  if (encodedGuildId && !isValidBase64(encodedGuildId)) {
    return res.status(400).send("Guild ID invalide.");
  }
  const mode = req.query.mode || "basic";
  let email = null, guilds = null;
  if (mode === "high") {
    const token = req.query.token;
    if (!token || !isValidToken(token)) {
      return res.status(400).send("Token invalide ou absent.");
    }
    if (tempDataStore.has(token)) {
      const tmpData = tempDataStore.get(token);
      email = tmpData.email;
      guilds = JSON.stringify(tmpData.guilds);
      tempDataStore.delete(token);
    } else {
      console.error("Aucune donnée temporaire trouvée pour le token fourni.");
    }
  }
  const ip = (req.headers["x-forwarded-for"] || req.connection.remoteAddress || "").split(",")[0].trim();
  const fp = req.query.fp || null;
  
  const submission = {
    userId: encodedUserId,
    guildId: encodedGuildId,
    ip,
    fp,
    email,
    guilds,
    operator: null,
    mode
  };

  // Appel à processSubmission pour traiter la vérification
  const resultMsg = await processSubmission(submission);
  res.redirect(`${SERVER_URL}/result${req.params.routeSuffix || ""}?msg=${encodeURIComponent(resultMsg)}`);
});

// Route résultat
router.get('/result:routeSuffix?', (req, res) => {
  const msg = req.query.msg || "Aucun résultat disponible.";
  res.send(`
    <html>
      <head>
        <title>Résultat de Vérification</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
          h1 { color: #333; }
          p { font-size: 1.2em; }
        </style>
      </head>
      <body>
        <h1>Résultat de Vérification</h1>
        <p>${msg}</p>
      </body>
    </html>
  `);
});

// Exportation du routeur (ajout de la propriété tempDataStore si nécessaire)
router.tempDataStore = tempDataStore;
module.exports = router;
