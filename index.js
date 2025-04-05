/******************************************************************
 * SCRIPT FUSIONNÉ : Bot Discord + Serveur Express + Base MySQL
 *
 * Description :
 * - Ce script gère simultanément un serveur Express pour le flux
 *   OAuth2 (endpoints /login, /callback, /collect) et le bot Discord
 *   (commandes classiques et slash).
 *
 * - Les données (vérifications, alt, settings, etc.) sont stockées dans
 *   une base MySQL (utilisation de mysql2/promise).
 *
 * - Les informations sensibles récupérées durant l'OAuth2 (pour la
 *   vérification haute) sont stockées temporairement dans /tmp.
 *
 * - Les messages de notification n'affichent PAS les adresses IP.
 *
 * - Des commandes slash (/recherche et /settings) permettent de rechercher
 *   les comptes alternatifs et de modifier la configuration du serveur.
 *
 * Remarques :
 * - Le bot et le serveur web sont hébergés dans le même processus.
 * - PORT doit être laissé vide (sinon, le script utilisera le port 80).
 ******************************************************************/

// Chargement des modules et configuration
require("dotenv").config();
const express = require("express");
const axios = require("axios");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const dns = require("dns").promises;
const fs = require("fs");
const {
  Client,
  GatewayIntentBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  PermissionsBitField
} = require("discord.js");

// Variables d'environnement
const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_URL = process.env.SERVER_URL || "https://welcome-eleen-know-e88aa2cb.koyeb.app";
const ENV_PORT = process.env.PORT; // Laisser vide => port 80
const DEFAULT_NOTIFICATION_CHANNEL_ID = process.env.NOTIFICATION_CHANNEL_ID;
const DEFAULT_VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
const DEFAULT_ALT_ROLE_ID = process.env.ALT_ROLE_ID;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const HASH_SALT = process.env.HASH_SALT;

// Création du pool MySQL à partir des variables d'environnement
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST ,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USER ,
  password: process.env.MYSQL_PASSWORD ,
  database: process.env.MYSQL_DATABASE,
  ssl: { rejectUnauthorized: true },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

console.log("[VerifyBot] Configuration initiale :", {
  DEFAULT_NOTIFICATION_CHANNEL_ID,
  DEFAULT_VERIFIED_ROLE_ID,
  DEFAULT_ALT_ROLE_ID
});

// Fonctions utilitaires pour la DB MySQL
async function dbGetOne(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

async function dbRun(sql, params) {
  const [result] = await pool.execute(sql, params);
  return result;
}

async function dbAll(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// Initialisation du client Discord
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers
  ]
});

// Initialisation d'Express
const app = express();
app.use(express.json());

// ---------------------- Fonctions communes ----------------------

// Récupération ou création des settings pour une guild
async function getGuildSettings(guildId) {
  let row = await dbGetOne("SELECT * FROM guild_settings WHERE guild_id = ?", [guildId]);
  if (row) {
    return {
      NOTIFICATION_CHANNEL_ID: row.notification_channel_id,
      VERIFIED_ROLE_ID: row.verified_role_id,
      ALT_ROLE_ID: row.alt_role_id,
      log_channel_id: row.log_channel_id
    };
  } else {
    const defaults = {
      NOTIFICATION_CHANNEL_ID: DEFAULT_NOTIFICATION_CHANNEL_ID,
      VERIFIED_ROLE_ID: DEFAULT_VERIFIED_ROLE_ID,
      ALT_ROLE_ID: DEFAULT_ALT_ROLE_ID,
      log_channel_id: null
    };
    await dbRun(
      "INSERT INTO guild_settings (guild_id, notification_channel_id, verified_role_id, alt_role_id, log_channel_id) VALUES (?, ?, ?, ?, ?)",
      [guildId, defaults.NOTIFICATION_CHANNEL_ID, defaults.VERIFIED_ROLE_ID, defaults.ALT_ROLE_ID, defaults.log_channel_id]
    );
    return defaults;
  }
}

// Recherche des comptes alternatifs d'un utilisateur
async function getAlts(userId, guildId) {
  const row = await dbGetOne("SELECT stable_hash FROM user_data WHERE user_id = ? AND guild_id = ?", [userId, guildId]);
  if (!row) return [];
  let myHashes;
  try { myHashes = JSON.parse(row.stable_hash); } catch { myHashes = [row.stable_hash]; }
  const rows = await dbAll("SELECT user_id, stable_hash FROM user_data WHERE guild_id = ?", [guildId]);
  const alts = [];
  for (const r of rows) {
    if (r.user_id !== userId) {
      let otherHashes;
      try { otherHashes = JSON.parse(r.stable_hash); } catch { otherHashes = [r.stable_hash]; }
      if (myHashes.some(h => otherHashes.includes(h))) {
        alts.push(r.user_id);
      }
    }
  }
  return alts;
}

// Fonctions de détection VPN (déjà dans la version précédente)
async function detectVPNviaAPI(ip) {
  const apiKey = "9a038c170f4d4066a865bd351eddc920";
  try {
    const response = await axios.get(`https://vpnapi.io/api/${ip}?key=${apiKey}`);
    if (response.data && response.data.security && response.data.security.vpn === true) {
      console.log(`[VPNAPI.io] L'IP ${ip} est détectée comme VPN.`);
      return true;
    }
  } catch (err) {
    console.error(`[VPNAPI.io] Erreur pour l'IP ${ip}:`, err.response ? err.response.data : err.message);
  }
  return false;
}

async function detectVPNviaDNS(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    console.log(`[VPN DNS] Reverse DNS pour l'IP ${ip}:`, hostnames);
    const keywords = ["vpn", "proxy", "virtual", "datacenter"];
    for (const hostname of hostnames) {
      for (const keyword of keywords) {
        if (hostname.toLowerCase().includes(keyword)) {
          console.log(`[VPN DNS] L'IP ${ip} (hostname: ${hostname}) contient "${keyword}".`);
          return true;
        }
      }
    }
  } catch (err) {
    console.error(`[VPN DNS] Erreur pour l'IP ${ip}:`, err.message);
  }
  return false;
}

async function detectVPN(ip) {
  return (await detectVPNviaAPI(ip)) || (await detectVPNviaDNS(ip));
}

// ---------------------- Traitement des submissions ----------------------

// Utilisation d'un Set pour éviter le double traitement
const processedSubmissions = new Set();

async function processSubmission(submission) {
  console.log("PROCESSING SUBMISSION:", submission);
  let userId, guildId;
  try {
    userId = Buffer.from(submission.userId, "base64").toString("utf8");
    guildId = submission.guildId ? Buffer.from(submission.guildId, "base64").toString("utf8") : "";
  } catch (err) {
    console.error("[ProcessSubmission] Erreur de décodage:", err.message);
    return;
  }
  const submissionKey = `${userId}-${submission.ip}-${submission.mode}`;
  if (processedSubmissions.has(submissionKey)) {
    console.log(`[ProcessSubmission] Déjà traité pour ${userId}, IP=${submission.ip}`);
    return;
  }
  processedSubmissions.add(submissionKey);
  console.log(`[ProcessSubmission] Traitement pour ${userId}, IP=${submission.ip}`);

  // Ignorer certaines IP (ex: celles des agents Discord)
  const ignoredIPs = ["35.237.4.214", "35.196.132.85", "35.227.62.178"];
  if (ignoredIPs.includes(submission.ip)) {
    console.log(`[ProcessSubmission] Ignoré IP ${submission.ip}`);
    return;
  }

  if (await detectVPN(submission.ip)) {
    console.log(`[ProcessSubmission] VPN détecté pour ${userId}. Vérification bloquée.`);
    await envoyerNotificationVPN({ type: "vpn", userId, guildId, ip: submission.ip, mode: submission.mode });
    return;
  }

  // Calcul du hash de l'IP
  const newHash = crypto.createHmac("sha256", HASH_SALT).update(submission.ip).digest("hex");

  // Vérifier si l'utilisateur existe déjà dans la DB
  let row = await dbGetOne("SELECT * FROM user_data WHERE user_id = ? AND guild_id = ?", [userId, guildId]);
  if (row) {
    if (row.email !== null) {
      console.log(`[ProcessSubmission] ${userId} déjà vérifié en mode haute.`);
      return;
    } else {
      if (submission.mode === "basic") {
        console.log(`[ProcessSubmission] ${userId} a déjà une vérification basique – refus de nouvelle baseline.`);
        return;
      } else if (submission.mode === "high") {
        // Conversion de basique vers haute : fusion des infos
        let oldHashes;
        try {
          oldHashes = JSON.parse(row.stable_hash);
          if (!Array.isArray(oldHashes)) oldHashes = [oldHashes];
        } catch (ex) { oldHashes = [row.stable_hash]; }
        if (!oldHashes.includes(newHash)) oldHashes.push(newHash);

        let oldIPs;
        try {
          oldIPs = JSON.parse(row.ip);
          if (!Array.isArray(oldIPs)) oldIPs = [oldIPs];
        } catch (ex) { oldIPs = [row.ip]; }
        if (!oldIPs.includes(submission.ip)) oldIPs.push(submission.ip);

        await dbRun("UPDATE user_data SET stable_hash = ?, email = ?, ip = ? WHERE user_id = ? AND guild_id = ?",
          [JSON.stringify(oldHashes), submission.email, JSON.stringify(oldIPs), userId, guildId]);
        console.log(`[ProcessSubmission] Conversion basique -> haute pour ${userId}.`);
        await envoyerNotificationVerifiee({ userId, guildId, ip: submission.ip, mode: submission.mode, guilds: submission.guilds });
        return;
      }
    }
  } else {
    // Insertion initiale
    const stableValue = JSON.stringify([newHash]);
    const ipValue = JSON.stringify([submission.ip]);
    const insertEmail = submission.mode === "high" ? submission.email : null;
    await dbRun("INSERT INTO user_data (stable_hash, user_id, guild_id, fingerprint, email, ip) VALUES (?, ?, ?, ?, ?, ?)",
      [stableValue, userId, guildId, submission.fp, insertEmail, ipValue]);
    console.log(`[ProcessSubmission] Insertion effectuée pour ${userId}.`);
    await envoyerNotificationVerifiee({ userId, guildId, ip: submission.ip, mode: submission.mode, guilds: submission.guilds });
  }
}

// ---------------------- Notifications ----------------------

// Envoi de notification de vérification réussie (sans afficher l'IP)
async function envoyerNotificationVerifiee(notif) {
  console.log(`[Notify] Envoi de 'vérifié' pour ${notif.userId}`);
  try {
    const settings = await getGuildSettings(notif.guildId);
    const notifChannel = client.channels.cache.get(settings.NOTIFICATION_CHANNEL_ID);
    if (!notifChannel) {
      console.error("[Notify] Salon de notification non trouvé.");
      return;
    }
    const alts = await getAlts(notif.userId, notif.guildId);
    let altInfo = "";
    if (alts.length > 0) {
      altInfo = `\nCe compte est un alt de ${alts.map(id => `<@${id}>`).join(", ")}`;
    }
    const typeVerification = notif.mode === "high" ? "Haute" : "Basique";
    const description = `<@${notif.userId}> a été vérifié par VerifyBot (${typeVerification} vérification).${altInfo}`;
    const embed = new EmbedBuilder()
      .setTitle("Vérification réussie")
      .setDescription(description)
      .setColor(0x00ff00)
      .setTimestamp();
    await notifChannel.send({ embeds: [embed] });
    console.log("[Notify] Notification 'vérifié' envoyée.");

    // Attribution du rôle vérifié
    const guild = notifChannel.guild;
    const member = await guild.members.fetch(notif.userId);
    if (member && !member.roles.cache.has(settings.VERIFIED_ROLE_ID)) {
      await member.roles.add(settings.VERIFIED_ROLE_ID);
      console.log(`[Notify] Rôle 'vérifié' attribué à ${member.user.tag}.`);
    }
  } catch (err) {
    console.error("[Notify] Erreur lors de l'envoi de la notification 'vérifié':", err.message);
  }
}

async function envoyerNotificationDouble(notif) {
  console.log(`[Notify] Envoi de notification 'double' pour ${notif.userId}`);
  try {
    const settings = await getGuildSettings(notif.guildId);
    const notifChannel = client.channels.cache.get(settings.NOTIFICATION_CHANNEL_ID);
    if (!notifChannel) {
      console.error("[Notify] Salon de notification non trouvé.");
      return;
    }
    let description = notif.notification || `<@${notif.userId}> est détecté comme double compte.`;
    if (notif.mode === "high") {
      const guildNote = analyzeGuilds(notif.guilds);
      if (guildNote) description += guildNote;
    }
    const embed = new EmbedBuilder()
      .setTitle("Doublon détecté")
      .setDescription(description)
      .setColor(0xff0000)
      .setTimestamp();
    await notifChannel.send({ embeds: [embed] });
    console.log("[Notify] Notification 'double' envoyée.");

    const guild = notifChannel.guild;
    const member = await guild.members.fetch(notif.userId);
    if (member && !member.roles.cache.has(settings.ALT_ROLE_ID)) {
      await member.roles.add(settings.ALT_ROLE_ID);
      console.log(`[Notify] Rôle 'alt' attribué à ${member.user.tag}.`);
    }
  } catch (err) {
    console.error("[Notify] Erreur lors de l'envoi de la notification 'double':", err.message);
  }
}

// ---------------------- EXPRESS ENDPOINTS ----------------------

// Route racine
app.get("/", (req, res) => {
  res.send("Bienvenue sur l'application VerifyBot.");
});

// GET /login : redirige vers l'URL OAuth2 de Discord (mode haute uniquement)
app.get("/login", (req, res) => {
  const mode = req.query.mode === "high" ? "high" : "basic";
  if (mode !== "high") {
    return res.status(400).send("La vérification basique ne nécessite pas OAuth2.");
  }
  const redirectUri = encodeURIComponent(`${SERVER_URL}/callback?mode=high`);
  const scope = encodeURIComponent("identify email guilds");
  const oauthUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}`;
  console.log(`[OAuth] URL générée: ${oauthUrl}`);
  res.redirect(oauthUrl);
});

// GET /callback : échange le code OAuth2 pour obtenir un token, récupère l'email et la liste des guildes,
// stocke temporairement ces infos dans /tmp, puis redirige vers /collect.
app.get("/callback", async (req, res) => {
  const mode = req.query.mode === "high" ? "high" : "basic";
  const code = req.query.code;
  if (!code) {
    console.log("[Callback] Aucun code reçu.");
    return res.status(400).send("Code d'autorisation manquant.");
  }
  const baseUrl = SERVER_URL.replace(/\/$/, "");
  const data = new URLSearchParams();
  data.append("client_id", CLIENT_ID);
  data.append("client_secret", CLIENT_SECRET);
  data.append("grant_type", "authorization_code");
  data.append("code", code);
  data.append("redirect_uri", `${baseUrl}/callback?mode=high`);
  try {
    const tokenResponse = await axios.post("https://discord.com/api/oauth2/token", data.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });
    const accessToken = tokenResponse.data.access_token;
    console.log("[Callback] Token obtenu:", accessToken);
    
    // Récupérer les détails de l'utilisateur
    const userResponse = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userData = userResponse.data;
    console.log("[Callback] Données utilisateur:", userData);
    const encodedUserId = Buffer.from(userData.id, "utf8").toString("base64");
    
    let redirectUrl = "";
    if (mode === "high") {
      // Chiffrer l'email avec AES-192-CBC (clé statique)
      const encryptionKey = Buffer.from("VerifyBotOfficialsqj554d", "utf8");
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-192-cbc", encryptionKey, iv);
      let encryptedEmail = cipher.update(userData.email, "utf8", "hex");
      encryptedEmail += cipher.final("hex");
      const finalEncryptedEmail = iv.toString("hex") + ":" + encryptedEmail;
      
      // Récupérer la liste des guildes de l'utilisateur
      const guildsResponse = await axios.get("https://discord.com/api/users/@me/guilds", {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const guildList = guildsResponse.data;
      console.log("[Callback] Liste des guildes:", guildList);
      
      // Générer un token temporaire et stocker les infos dans /tmp
      const tempToken = crypto.randomBytes(16).toString("hex");
      const tmpData = { email: finalEncryptedEmail, guilds: guildList, timestamp: Date.now() };
      fs.writeFileSync(`/tmp/${tempToken}.json`, JSON.stringify(tmpData));
      
      redirectUrl = `${baseUrl}/collect?userId=${encodedUserId}&token=${tempToken}&mode=high`;
      console.log("[Callback] Mode high: données stockées dans /tmp, token généré.");
    }
    res.send(`
      <html>
        <head>
          <meta http-equiv="refresh" content="5;url=${redirectUrl || '#'}" />
        </head>
        <body>
          <p>Première étape réussie. Redirection en cours...</p>
          <p>Si la redirection ne se fait pas automatiquement, <a href="${redirectUrl || '#'}">cliquez ici</a>.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("[Callback] Erreur durant OAuth2:", err.message);
    res.status(500).send("Erreur durant l'authentification.");
  }
});

// GET /collect : Récupère, pour le mode high, les infos stockées en /tmp,
// et construit la submission pour traitement.
app.get("/collect", async (req, res) => {
  const encodedUserId = req.query.userId;
  const guildId = req.query.guildId || "";
  if (!encodedUserId) {
    console.log("[Collect] userId manquant.");
    return res.status(400).send("Lien invalide.");
  }
  const mode = req.query.mode || "basic";
  let email = null, guilds = null;
  if (mode === "high") {
    const token = req.query.token;
    if (token) {
      try {
        const fileData = fs.readFileSync(`/tmp/${token}.json`, "utf8");
        const parsed = JSON.parse(fileData);
        email = parsed.email;
        guilds = JSON.stringify(parsed.guilds);
        fs.unlinkSync(`/tmp/${token}.json`);
      } catch (e) {
        console.error("Erreur lors de la lecture du fichier temporaire:", e.message);
      }
    }
  }
  // Récupérer l'IP de la requête
  const ip = (req.headers["x-forwarded-for"] || req.connection.remoteAddress || "").split(",")[0].trim();
  const fp = req.query.fp || null;
  
  const submission = {
    userId: encodedUserId,
    guildId: guildId,
    ip: ip,
    fp: fp,
    email: email,
    guilds: guilds,
    operator: null,
    mode: mode
  };

  // Traiter directement la submission
  await processSubmission(submission);
  res.send("Votre vérification a été reçue. Vous recevrez bientôt une notification sur Discord.");
});

// ---------------------- Gestion des commandes Slash ----------------------
// Assurez-vous d'avoir déployé ces commandes auprès de Discord via vos outils habituels.
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  
  if (interaction.commandName === "recherche") {
    const targetUser = interaction.options.getUser("utilisateur");
    if (!targetUser) {
      return interaction.reply({ content: "Veuillez spécifier un utilisateur.", ephemeral: true });
    }
    const alts = await getAlts(targetUser.id, interaction.guild.id);
    if (alts.length === 0) {
      return interaction.reply({ content: `Aucun alt trouvé pour <@${targetUser.id}>.`, ephemeral: true });
    }
    const altMentions = alts.map(id => `<@${id}>`).join(", ");
    return interaction.reply({ content: `Les alts de <@${targetUser.id}> sont : ${altMentions}`, ephemeral: true });
  }
  else if (interaction.commandName === "settings") {
    if (interaction.options.getSubcommand() === "view") {
      try {
        const settings = await getGuildSettings(interaction.guild.id);
        const embed = new EmbedBuilder()
          .setTitle("Settings du serveur")
          .setDescription(`Notification Channel: ${settings.NOTIFICATION_CHANNEL_ID}
Verified Role: ${settings.VERIFIED_ROLE_ID}
Alt Role: ${settings.ALT_ROLE_ID}
Log Channel: ${settings.log_channel_id || "Non défini"}`)
          .setColor(0x00ff00)
          .setTimestamp();
        return interaction.reply({ embeds: [embed], ephemeral: true });
      } catch (err) {
        console.error(err);
        return interaction.reply({ content: "Erreur lors de la récupération des settings.", ephemeral: true });
      }
    } else if (interaction.options.getSubcommand() === "set") {
      if (!interaction.memberPermissions.has(PermissionsBitField.Flags.Administrator)) {
        return interaction.reply({ content: "Seuls les administrateurs peuvent modifier les settings.", ephemeral: true });
      }
      const notifChannel = interaction.options.getChannel("notification_channel");
      const verifiedRole = interaction.options.getRole("verified_role");
      const altRole = interaction.options.getRole("alt_role");
      const logChannel = interaction.options.getChannel("log_channel");
      const guildId = interaction.guild.id;
      try {
        await dbRun(
          "UPDATE guild_settings SET notification_channel_id = ?, verified_role_id = ?, alt_role_id = ?, log_channel_id = ? WHERE guild_id = ?",
          [notifChannel.id, verifiedRole.id, altRole.id, logChannel ? logChannel.id : null, guildId]
        );
        return interaction.reply({ content: "Settings mis à jour avec succès.", ephemeral: true });
      } catch (err) {
        console.error(err.message);
        return interaction.reply({ content: "Erreur lors de la mise à jour des settings.", ephemeral: true });
      }
    }
  }
});

// ---------------------- Commandes textuelles classiques ----------------------
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;
  
  if (message.content.startsWith("!verify")) {
    console.log(`[!verify] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const userId = message.author.id;
    const guildId = message.guild.id;
    const existing = await dbGetOne("SELECT * FROM user_data WHERE user_id = ? AND guild_id = ?", [userId, guildId]);
    if (existing) return message.reply("Vous êtes déjà vérifié !");
    
    const embed = new EmbedBuilder()
      .setTitle("Vérification de compte")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre adresse e-mail et la liste des guildes auxquelles vous appartenez.
      
Remarque : La vérification haute ouvrira directement le lien vers Discord.`)
      .setColor(0xffaa00)
      .setTimestamp();
    const rowButtons = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("verify_basic")
        .setLabel("Vérification basique")
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setLabel("Vérification haute")
        .setStyle(ButtonStyle.Link)
        .setURL("https://discord.com/api/oauth2/authorize?client_id=" + CLIENT_ID + "&response_type=code&redirect_uri=" + encodeURIComponent(SERVER_URL + "/callback?mode=high") + "&scope=identify+email+guilds")
    );
    try {
      await message.author.send({ embeds: [embed], components: [rowButtons] });
      message.reply("Le panneau de vérification vous a été envoyé en MP.");
    } catch (err) {
      console.error("[!verify] Erreur d'envoi du MP:", err.message);
      message.reply("Impossible d'envoyer le panneau de vérification en MP.");
    }
  }
  else if (message.content.startsWith("!button")) {
    console.log(`[!button] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const embed = new EmbedBuilder()
      .setTitle("Panneau de vérification")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre adresse e-mail et la liste des guildes.
      
La vérification haute ouvrira directement le lien vers Discord.`)
      .setColor(0xffaa00)
      .setTimestamp();
    const rowButtons = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("verify_basic")
        .setLabel("Vérification basique")
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setLabel("Vérification haute")
        .setStyle(ButtonStyle.Link)
        .setURL("https://discord.com/api/oauth2/authorize?client_id=" + CLIENT_ID + "&response_type=code&redirect_uri=" + encodeURIComponent(SERVER_URL + "/callback?mode=high") + "&scope=identify+email+guilds")
    );
    message.channel.send({ embeds: [embed], components: [rowButtons] });
  }
});

// Gestion de l'interaction pour le bouton de vérification basique via interaction
client.on("interactionCreate", async (interaction) => {
  if (!interaction.isButton()) return;
  if (interaction.customId === "verify_basic") {
    const encodedUserId = Buffer.from(interaction.user.id).toString("base64");
    const guildId = interaction.guild ? interaction.guild.id : "";
    const redirectLink = `${SERVER_URL}/collect?userId=${encodedUserId}&guildId=${guildId}&mode=basic`;
    console.log(`[Bouton] Lien de vérification basique: ${redirectLink}`);
    return interaction.reply({ content: `Cliquez sur ce lien pour continuer la vérification basique:\n${redirectLink}`, ephemeral: true });
  } else {
    return interaction.reply({ content: "Interaction non reconnue.", ephemeral: true });
  }
});

// ---------------------- Démarrage du serveur Express et du bot Discord ----------------------

// Démarrage d'Express : si la variable PORT est vide, utiliser le port 80
const port = ENV_PORT && ENV_PORT.trim() !== "" ? ENV_PORT : 80;
app.listen(port, () => {
  console.log(`Serveur Express démarré sur le port ${port}`);
});

// Démarrage du client Discord
client.login(BOT_TOKEN)
  .then(() => console.log("[Login] Client Discord connecté avec succès."))
  .catch(err => console.error("[Login] Erreur lors du login:", err.message));
console.log(process.env.SERVER_URL)
