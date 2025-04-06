/******************************************************************
 * INDEX.JS : Bot Discord + Serveur Express + Base PostgreSQL
 *
 * Ce script intègre :
 * - Un serveur Express pour gérer OAuth2 (5 endpoints callback, /collect, /result)
 * - Un bot Discord (commandes textuelles et slash)
 * - Une connexion à une base de données PostgreSQL via "postgres"
 *
 * Fonctionnalités :
 *  • La vérification haute n’enregistre plus l’e‑mail en base (il sert uniquement à envoyer un e‑mail de confirmation via nodemailer).
 *  • Lorsque l'utilisateur déclenche une vérification haute (via !verify ou !button), le bot renvoie directement le lien OAuth2
 *    correspondant à sa guilde (selon une table statique de 5 liens). Ce lien doit être enregistré exactement dans Discord.
 *  • Les notifications de vérification sont envoyées dans le salon configuré pour la guilde concernée.
 *  • Les commandes slash `/settings` (view et set) et `/recherche` fonctionnent dans chaque serveur.
 *  • Les commandes textuelles !del et !resetdb sont réservées à l’ID "1222548578539536405".
 *  • Toutes les références à "VerifyBot" sont remplacées par "AutentiBot".
 *
 * Pour l'envoi d'e‑mail de confirmation :
 *    Adresse : autentibotofficial@gmail.com
 *    Mot de passe : AutentiBot15
 ******************************************************************/

// ================== Chargement des dépendances ==================
import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import postgres from 'postgres';
import crypto from 'crypto';
import dns from 'dns/promises';
import nodemailer from 'nodemailer';
import {
  Client,
  GatewayIntentBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  PermissionsBitField
} from 'discord.js';

// ================== Variables Globales ==================
const processedSubmissions = new Set();
const tempDataStore = new Map();

// ================== Configuration de Nodemailer ==================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'autentibotofficial@gmail.com',
    pass: 'AutentiBot15'
  }
});

// Fonction d'envoi d'e‑mail de confirmation
async function sendConfirmationEmail(email) {
  const mailOptions = {
    from: 'autentibotofficial@gmail.com',
    to: email,
    subject: 'Confirmation de vérification - AutentiBot',
    text: "Bonjour,\n\nVotre vérification a été effectuée avec succès par AutentiBot.\n\nCordialement,\nL'équipe AutentiBot"
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("E‑mail de confirmation envoyé :", info.response);
  } catch (error) {
    console.error("Erreur lors de l'envoi de l'e‑mail de confirmation :", error);
  }
}

// ================== Variables d'environnement ==================
const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_URL = process.env.SERVER_URL;     // Ex : "https://welcome-eleen-know-e88aa2cb.koyeb.app" (sans slash final)
const ENV_PORT = process.env.PORT;
const PORT = ENV_PORT || 80;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const NOTIFICATION_CHANNEL_ID = process.env.NOTIFICATION_CHANNEL_ID;
const VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
const ALT_ROLE_ID = process.env.ALT_ROLE_ID;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const HASH_SALT = process.env.HASH_SALT;

// ================== Table statique des liens OAuth2 par guilde ==================
const guildOAuthLinks = {
  // Assurez-vous que ces IDs et URIs correspondent à vos enregistrements dans Discord Developer Portal.
  "1287382398287216650": `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(SERVER_URL + "/callback1")}&scope=identify+email+guilds`,
  "1111111111111111111": `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(SERVER_URL + "/callback2")}&scope=identify+email+guilds`,
  "2222222222222222222": `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(SERVER_URL + "/callback3")}&scope=identify+email+guilds`,
  "3333333333333333333": `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(SERVER_URL + "/callback4")}&scope=identify+email+guilds`,
  "4444444444444444444": `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(SERVER_URL + "/callback5")}&scope=identify+email+guilds`
};

// ================== Valeurs par défaut pour la configuration d'un serveur ==================
const DEFAULT_NOTIFICATION_CHANNEL_ID = NOTIFICATION_CHANNEL_ID;
const DEFAULT_VERIFIED_ROLE_ID = VERIFIED_ROLE_ID;
const DEFAULT_ALT_ROLE_ID = ALT_ROLE_ID;

// ================== Connexion à PostgreSQL ==================
const sql = postgres({
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  username: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  ssl: 'require'
});

// ================== Initialisation de la Base de Données ==================
async function initDB() {
  await sql`
    CREATE TABLE IF NOT EXISTS guild_settings (
      guild_id TEXT PRIMARY KEY,
      notification_channel_id TEXT,
      verified_role_id TEXT,
      alt_role_id TEXT,
      log_channel_id TEXT
    );
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id TEXT,
      guild_id TEXT,
      stable_hash TEXT,
      fingerprint TEXT,
      email TEXT,
      ip TEXT,
      PRIMARY KEY (user_id, guild_id)
    );
  `;
  console.log("Database initialized.");
}

// Commande pour réinitialiser la base (accessible via !resetdb)
async function resetDB() {
  await sql`DROP TABLE IF EXISTS user_data;`;
  await sql`DROP TABLE IF EXISTS guild_settings;`;
  await initDB();
}

// ================== Initialisation du client Discord ==================
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers
  ]
});

// ================== Initialisation d'Express ==================
const app = express();
app.use(express.json());

// ================== Fonctions Utilitaires ==================

// Détection VPN via API externe
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

// Détection VPN via reverse DNS
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

// Récupération (ou création) de la configuration d'un serveur (guild)
async function getGuildSettings(guildId) {
  const rows = await sql`SELECT * FROM guild_settings WHERE guild_id = ${guildId}`;
  if (rows.length > 0) {
    const row = rows[0];
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
    await sql`
      INSERT INTO guild_settings (guild_id, notification_channel_id, verified_role_id, alt_role_id, log_channel_id)
      VALUES (${guildId}, ${defaults.NOTIFICATION_CHANNEL_ID}, ${defaults.VERIFIED_ROLE_ID}, ${defaults.ALT_ROLE_ID}, ${defaults.log_channel_id})
    `;
    return defaults;
  }
}

// Recherche d'alts
async function getAlts(userId, guildId) {
  const rows = await sql`SELECT stable_hash FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
  if (rows.length === 0) return [];
  let myHashes;
  try {
    myHashes = JSON.parse(rows[0].stable_hash);
    if (!Array.isArray(myHashes)) myHashes = [myHashes];
  } catch (e) {
    myHashes = [rows[0].stable_hash];
  }
  const allRows = await sql`SELECT user_id, stable_hash FROM user_data WHERE guild_id = ${guildId}`;
  const alts = [];
  for (const r of allRows) {
    if (r.user_id !== userId) {
      let otherHashes;
      try {
        otherHashes = JSON.parse(r.stable_hash);
        if (!Array.isArray(otherHashes)) otherHashes = [otherHashes];
      } catch (e) {
        otherHashes = [r.stable_hash];
      }
      if (myHashes.some(h => otherHashes.includes(h))) {
        alts.push(r.user_id);
      }
    }
  }
  return alts;
}

// ================== Traitement des Soumissions ==================
// L’e‑mail n’est pas stocké en base ; il est uniquement utilisé pour envoyer la confirmation.
async function processSubmission(submission) {
  console.log("PROCESSING SUBMISSION:", submission);
  let userId, guildId;
  try {
    userId = Buffer.from(submission.userId, "base64").toString("utf8");
    guildId = submission.guildId ? Buffer.from(submission.guildId, "utf8").toString("utf8") : "";
  } catch (err) {
    console.error("[ProcessSubmission] Erreur de décodage:", err.message);
    return "Erreur lors du décodage des informations.";
  }
  
  const submissionKey = `${userId}-${submission.ip}-${submission.mode}`;
  if (processedSubmissions.has(submissionKey)) {
    console.log(`[ProcessSubmission] Déjà traité pour ${userId}, IP=${submission.ip}`);
    return "Cette soumission a déjà été traitée.";
  }
  processedSubmissions.add(submissionKey);
  console.log(`[ProcessSubmission] Traitement pour ${userId}, IP=${submission.ip}`);
  
  const ignoredIPs = ["35.237.4.214", "35.196.132.85", "35.227.62.178"];
  if (ignoredIPs.includes(submission.ip)) {
    console.log(`[ProcessSubmission] Ignoré IP ${submission.ip}`);
    return "Cette IP est ignorée pour des raisons internes.";
  }
  
  if (await detectVPN(submission.ip)) {
    console.log(`[ProcessSubmission] VPN détecté pour ${userId}.`);
    await envoyerNotificationDouble({ type: "vpn", userId, guildId, ip: submission.ip, mode: submission.mode });
    return "VPN détecté. Votre vérification a été annulée.";
  }
  
  const newHash = crypto.createHmac("sha256", HASH_SALT)
    .update(submission.ip)
    .digest("hex");
  
  const rowsExist = await sql`SELECT * FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
  if (rowsExist.length > 0) {
    const row = rowsExist[0];
    if (row.email !== null) {
      console.log(`[ProcessSubmission] ${userId} déjà vérifié en mode haute.`);
      return "Vous êtes déjà vérifié.";
    } else {
      if (submission.mode === "basic") {
        console.log(`[ProcessSubmission] ${userId} a déjà effectué une vérification basique – refus.`);
        return "Vous avez déjà effectué une vérification basique.";
      } else if (submission.mode === "high") {
        let oldHashes;
        try {
          oldHashes = JSON.parse(row.stable_hash);
          if (!Array.isArray(oldHashes)) oldHashes = [oldHashes];
        } catch (e) {
          oldHashes = [row.stable_hash];
        }
        if (!oldHashes.includes(newHash)) oldHashes.push(newHash);
        
        let oldIPs;
        try {
          oldIPs = JSON.parse(row.ip);
          if (!Array.isArray(oldIPs)) oldIPs = [oldIPs];
        } catch (e) {
          oldIPs = [row.ip];
        }
        if (!oldIPs.includes(submission.ip)) oldIPs.push(submission.ip);
        
        await sql`
          UPDATE user_data
          SET stable_hash = ${JSON.stringify(oldHashes)},
              email = null,
              ip = ${JSON.stringify(oldIPs)}
          WHERE user_id = ${userId} AND guild_id = ${guildId}
        `;
        console.log(`[ProcessSubmission] Conversion basique -> haute pour ${userId}.`);
        await envoyerNotificationVerifiee({
          userId,
          guildId,
          ip: submission.ip,
          mode: submission.mode,
          guilds: submission.guilds
        });
        if (submission.email) {
          await sendConfirmationEmail(submission.email);
        }
        return "Conversion de vérification basique vers haute effectuée avec succès.";
      }
    }
  } else {
    const stableValue = JSON.stringify([newHash]);
    const ipValue = JSON.stringify([submission.ip]);
    await sql`
      INSERT INTO user_data (stable_hash, user_id, guild_id, fingerprint, email, ip)
      VALUES (${stableValue}, ${userId}, ${guildId}, ${submission.fp}, null, ${ipValue})
    `;
    console.log(`[ProcessSubmission] Insertion effectuée pour ${userId}.`);
    await envoyerNotificationVerifiee({
      userId,
      guildId,
      ip: submission.ip,
      mode: submission.mode,
      guilds: submission.guilds
    });
    if (submission.email) {
      await sendConfirmationEmail(submission.email);
    }
    return "Votre vérification a été effectuée avec succès.";
  }
}

// ================== Notifications Discord ==================
// La notification est envoyée dans le salon configuré pour le serveur.
async function envoyerNotificationVerifiee(notif) {
  console.log(`[Notify] Envoi de notification pour ${notif.userId}`);
  try {
    const settings = await getGuildSettings(notif.guildId);
    let guild = client.guilds.cache.get(notif.guildId);
    if (!guild) {
      try {
        guild = await client.guilds.fetch(notif.guildId);
      } catch (error) {
        console.error("Impossible de récupérer la guilde :", error);
        return;
      }
    }
    const notifChannel = guild.channels.cache.get(settings.NOTIFICATION_CHANNEL_ID);
    if (!notifChannel) {
      console.error("[Notify] Salon de notification introuvable dans cette guilde.");
      return;
    }
    const alts = await getAlts(notif.userId, notif.guildId);
    let altInfo = "";
    if (alts.length > 0) {
      altInfo = `\nCe compte est détecté comme alt de ${alts.map(id => `<@${id}>`).join(", ")}`;
    }
    let extraInfo = "";
    if (notif.mode === "high" && notif.guilds) {
      try {
        const guilds = JSON.parse(notif.guilds);
        const totalGuilds = guilds.length;
        const ownerGuilds = guilds.filter(g => g.owner === true).length;
        extraInfo = `\nNote: Présence sur ${totalGuilds} serveurs, dont ${ownerGuilds} en tant qu’owner/admin.`;
      } catch (e) {}
    }
    const typeVerification = notif.mode === "high" ? "Haute" : "Basique";
    const description = `<@${notif.userId}> a été vérifié par AutentiBot (${typeVerification}).${altInfo}${extraInfo}`;
    
    const embed = new EmbedBuilder();
    if (alts.length > 0) {
      embed.setTitle("Alt détecté").setColor(0xff0000);
    } else {
      embed.setTitle("Vérification réussie").setColor(0x00ff00);
    }
    embed.setDescription(description).setTimestamp();
    
    await notifChannel.send({ embeds: [embed] });
    console.log("[Notify] Notification envoyée.");
    
    const member = await guild.members.fetch(notif.userId);
    if (member && !member.roles.cache.has(settings.VERIFIED_ROLE_ID)) {
      await member.roles.add(settings.VERIFIED_ROLE_ID);
      console.log(`[Notify] Rôle "vérifié" attribué à ${member.user.tag}.`);
    }
  } catch (err) {
    console.error("[Notify] Erreur lors de l'envoi de la notification :", err.message);
  }
}

// Notification en cas de doublon/VPN détecté
async function envoyerNotificationDouble(notif) {
  console.log(`[Notify] Envoi de notification "double" pour ${notif.userId}`);
  try {
    const settings = await getGuildSettings(notif.guildId);
    let guild = client.guilds.cache.get(notif.guildId);
    if (!guild) {
      try {
        guild = await client.guilds.fetch(notif.guildId);
      } catch (error) {
        console.error("Impossible de récupérer la guilde :", error);
        return;
      }
    }
    const notifChannel = guild.channels.cache.get(settings.NOTIFICATION_CHANNEL_ID);
    if (!notifChannel) {
      console.error("[Notify] Salon de notification introuvable dans cette guilde.");
      return;
    }
    let description = notif.notification || `<@${notif.userId}> est détecté comme double compte.`;
    const embed = new EmbedBuilder()
      .setTitle("Doublon détecté")
      .setDescription(description)
      .setColor(0xff0000)
      .setTimestamp();
    await notifChannel.send({ embeds: [embed] });
    console.log("[Notify] Notification 'double' envoyée.");
    const member = await guild.members.fetch(notif.userId);
    if (member && !member.roles.cache.has(settings.ALT_ROLE_ID)) {
      await member.roles.add(settings.ALT_ROLE_ID);
      console.log(`[Notify] Rôle "alt" attribué à ${member.user.tag}.`);
    }
  } catch (err) {
    console.error("[Notify] Erreur lors de l'envoi de la notification 'double':", err.message);
  }
}

// ================== Endpoints Express ==================

// Route racine
app.get("/", (req, res) => {
  res.send("Bienvenue sur l'application AutentiBot.");
});

// --- Endpoints OAuth2 Callback ---
// Ces endpoints doivent être enregistrés dans le Developer Portal EXACTEMENT :
app.get("/callback1", async (req, res) => {
  // Pour la guilde "1287382398287216650"
  const guildId = "1287382398287216650";
  await handleCallback(req, res, guildId);
});
app.get("/callback2", async (req, res) => {
  const guildId = "1111111111111111111";
  await handleCallback(req, res, guildId);
});
app.get("/callback3", async (req, res) => {
  const guildId = "2222222222222222222";
  await handleCallback(req, res, guildId);
});
app.get("/callback4", async (req, res) => {
  const guildId = "3333333333333333333";
  await handleCallback(req, res, guildId);
});
app.get("/callback5", async (req, res) => {
  const guildId = "4444444444444444444";
  await handleCallback(req, res, guildId);
});

// Fonction utilitaire pour les callbacks OAuth2
async function handleCallback(req, res, guildId) {
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
  // L'URI de redirection doit être exactement identique à l'enregistrement dans Discord Developer Portal :
  // Pour callback1, l'URI est SERVER_URL/callback1, etc.
  let callbackSuffix = "";
  if (guildId === "1287382398287216650") callbackSuffix = "1";
  else if (guildId === "1111111111111111111") callbackSuffix = "2";
  else if (guildId === "2222222222222222222") callbackSuffix = "3";
  else if (guildId === "3333333333333333333") callbackSuffix = "4";
  else callbackSuffix = "5";
  data.append("redirect_uri", `${baseUrl}/callback${callbackSuffix}`);
  
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
    
    let redirectUrl = `${baseUrl}/collect?userId=${encodedUserId}&guildId=${Buffer.from(guildId, "utf8").toString("base64")}&mode=high`;
    
    const guildsResponse = await axios.get("https://discord.com/api/users/@me/guilds", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const guildList = guildsResponse.data;
    console.log("[Callback] Liste des guildes:", guildList);
    
    const tempToken = crypto.randomBytes(16).toString("hex");
    const tmpData = { email: userData.email, guilds: guildList, timestamp: Date.now() };
    tempDataStore.set(tempToken, tmpData);
    
    redirectUrl += `&token=${tempToken}`;
    console.log("[Callback] Mode high: données stockées temporairement, token généré.");
    
    res.send(`
      <html>
        <head>
          <meta http-equiv="refresh" content="5;url=${redirectUrl}" />
        </head>
        <body>
          <p>Première étape réussie. Redirection en cours...</p>
          <p>Si la redirection ne fonctionne pas, <a href="${redirectUrl}">cliquez ici</a>.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("[Callback] Erreur durant OAuth2:", err.message);
    res.status(500).send("Erreur durant l'authentification.");
  }
}

// --- Endpoint /collect ---
// Cet endpoint collecte la soumission de vérification.
app.get("/collect", async (req, res) => {
  const encodedUserId = req.query.userId;
  const encodedGuildId = req.query.guildId || "";
  if (!encodedUserId) {
    console.log("[Collect] userId manquant.");
    return res.status(400).send("Lien invalide.");
  }
  const mode = req.query.mode || "basic";
  let email = null, guilds = null;
  if (mode === "high") {
    const token = req.query.token;
    if (token && tempDataStore.has(token)) {
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
    ip: ip,
    fp: fp,
    email: email,
    guilds: guilds,
    operator: null,
    mode: mode
  };
  
  const resultMsg = await processSubmission(submission);
  res.redirect(`${SERVER_URL}/result?msg=${encodeURIComponent(resultMsg)}`);
});

// --- Endpoint /result ---
// Affiche le résultat de la vérification.
app.get("/result", (req, res) => {
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

// ================== Commandes Discord ==================

// Commandes slash: /recherche et /settings
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
  } else if (interaction.commandName === "settings") {
    if (interaction.options.getSubcommand() === "view") {
      try {
        const settings = await getGuildSettings(interaction.guild.id);
        const embed = new EmbedBuilder()
          .setTitle("Settings du serveur")
          .setDescription(`Salon de notification: ${settings.NOTIFICATION_CHANNEL_ID}\nRôle vérifié: ${settings.VERIFIED_ROLE_ID}\nRôle alt: ${settings.ALT_ROLE_ID}`)
          .setColor(0x00ff00)
          .setTimestamp();
        return interaction.reply({ embeds: [embed], ephemeral: true });
      } catch (err) {
        console.error(err);
        return interaction.reply({ content: "Erreur lors de la récupération des settings.", ephemeral: true });
      }
    } else if (interaction.options.getSubcommand() === "set") {
      if (!interaction.memberPermissions.has(PermissionsBitField.Flags.Administrator)) {
        return interaction.reply({ content: "Seuls les administrateurs peuvent modifier ces paramètres.", ephemeral: true });
      }
      const notifChannel = interaction.options.getChannel("notification_channel");
      const verifiedRole = interaction.options.getRole("verified_role");
      const altRole = interaction.options.getRole("alt_role");
      try {
        await sql`
          UPDATE guild_settings
          SET notification_channel_id = ${notifChannel.id},
              verified_role_id = ${verifiedRole.id},
              alt_role_id = ${altRole.id}
          WHERE guild_id = ${interaction.guild.id}
        `;
        return interaction.reply({ content: "Settings mis à jour avec succès.", ephemeral: true });
      } catch (err) {
        console.error(err.message);
        return interaction.reply({ content: "Erreur lors de la mise à jour des settings.", ephemeral: true });
      }
    }
  }
});

// Commande textuelle !verify et !button pour la vérification haute
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;
  
  if (message.content.startsWith("!verify")) {
    console.log(`[!verify] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const userId = message.author.id;
    const guildId = message.guild.id;
    const existing = await sql`SELECT * FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
    if (existing.length > 0) return message.reply("Vous êtes déjà vérifié !");
    
    // Récupération directe du lien OAuth2 à partir de la table
    const oauthUrl = guildOAuthLinks[guildId] || "Lien OAuth2 par défaut non configuré.";
    const embed = new EmbedBuilder()
      .setTitle("Vérification de compte")
      .setDescription(`Cliquez sur le lien ci-dessous pour réaliser une vérification haute.\n\n${oauthUrl}`)
      .setColor(0xffaa00)
      .setTimestamp();
    try {
      await message.author.send({ embeds: [embed] });
      message.reply("Le lien de vérification haute vous a été envoyé en MP.");
    } catch (err) {
      console.error("[!verify] Erreur d'envoi du MP:", err.message);
      message.reply("Impossible d'envoyer le panneau de vérification en MP.");
    }
  } else if (message.content.startsWith("!button")) {
    console.log(`[!button] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const oauthUrl = guildOAuthLinks[message.guild.id] || "Lien OAuth2 par défaut non configuré.";
    const embed = new EmbedBuilder()
      .setTitle("Panneau de vérification")
      .setDescription(`Cliquez sur le lien ci-dessous pour réaliser une vérification haute :\n\n${oauthUrl}`)
      .setColor(0xffaa00)
      .setTimestamp();
    message.channel.send({ embeds: [embed] });
  }
});

client.on("interactionCreate", async (interaction) => {
  if (!interaction.isButton()) return;
  if (interaction.customId === "verify_basic") {
    const encodedUserId = Buffer.from(interaction.user.id).toString("base64");
    const redirectLink = `${SERVER_URL}/collect?userId=${encodedUserId}&mode=basic`;
    console.log(`[Bouton] Lien de vérification basique: ${redirectLink}`);
    return interaction.reply({ content: `Cliquez sur ce lien pour continuer la vérification basique:\n${redirectLink}`, ephemeral: true });
  } else {
    return interaction.reply({ content: "Interaction non reconnue.", ephemeral: true });
  }
});

// ================== Démarrage de l'Application ==================
app.listen(PORT, async () => {
  console.log(`Serveur Express démarré sur le port ${PORT}`);
  await initDB();
});

client.login(BOT_TOKEN)
  .then(() => console.log("[Login] Client Discord connecté avec succès."))
  .catch(err => console.error("[Login] Erreur lors du login:", err.message));
