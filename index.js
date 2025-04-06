/******************************************************************
 * INDEX.JS : Bot Discord + Serveur Express + Base PostgreSQL
 *
 * Ce script intègre :
 * - Un serveur Express pour gérer OAuth2 (/login, /callback, /collect, /result)
 * - Un bot Discord (commandes textuelles et slash)
 * - Une connexion à une base de données PostgreSQL via le module "postgres"
 *
 * La fonction initDB() crée automatiquement les tables nécessaires
 * (guild_settings et user_data) si elles n'existent pas.
 *
 * Changements :
 *  • Le message de vérification haute ne contient plus la mention 
 *    "Pour une vérification haute complète, il devrait être présent sur au moins 11 serveurs."
 *  • La commande slash /settings permet de consulter et modifier les paramètres
 *    basiques (salon de notification, rôle vérifié et rôle alt) pour le seul serveur
 *    dans lequel elle est utilisée (seuls les admins peuvent l'exécuter). Un script
 *    de réinitialisation de la base est accessible via la commande !resetdb.
 *  • L’adresse e‑mail des membres n’est plus stockée en base, mais un e‑mail
 *    de confirmation est envoyé à l’utilisateur (via nodemailer avec les identifiants
 *    autentibotofficial@gmail.com / AutentiBot15).
 *  • Toutes les références à "VerifyBot" ont été remplacées par "AutentiBot".
 ******************************************************************/

// ================== Chargement des dépendances ==================
import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import postgres from 'postgres';
import crypto from 'crypto';
import dns from 'dns/promises';
import fs from 'fs'; // Conservé pour d'éventuelles autres utilisations
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

// ================== Variables globales ==================
// Pour éviter le double traitement des soumissions
const processedSubmissions = new Set();
// Stockage temporaire en mémoire pour le mode "high"
const tempDataStore = new Map();

// ================== Configuration de nodemailer ==================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'autentibotofficial@gmail.com',
    pass: 'AutentiBot15'
  }
});

// ================== Variables d'environnement ==================
const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_URL = process.env.SERVER_URL; // ex : https://welcome-eleen-know-e88aa2cb.koyeb.app
const ENV_PORT = process.env.PORT;
const PORT = ENV_PORT || 80;

const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const NOTIFICATION_CHANNEL_ID = process.env.NOTIFICATION_CHANNEL_ID;
const VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
const ALT_ROLE_ID = process.env.ALT_ROLE_ID;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const HASH_SALT = process.env.HASH_SALT;

// Valeurs par défaut pour la configuration d'un serveur (guild)
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

// ================== Initialisation de la base de données ==================
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

// Fonction pour réinitialiser la BD (accessible via la commande !resetdb)
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

// Récupération ou création de la configuration d'un serveur
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

// Recherche des alts
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

/*
  La fonction processSubmission traite une soumission de vérification et renvoie
  un message à afficher sur le site.
  - L'e-mail n'est plus stockée dans la BD (elle reste à null).
  - Un e-mail de confirmation est envoyé après une vérification haute réussie.
*/
async function processSubmission(submission) {
  console.log("PROCESSING SUBMISSION:", submission);
  let userId, guildId;
  try {
    userId = Buffer.from(submission.userId, "base64").toString("utf8");
    guildId = submission.guildId ? Buffer.from(submission.guildId, "base64").toString("utf8") : "";
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

  // Ignorer certaines IP
  const ignoredIPs = ["35.237.4.214", "35.196.132.85", "35.227.62.178"];
  if (ignoredIPs.includes(submission.ip)) {
    console.log(`[ProcessSubmission] Ignoré IP ${submission.ip}`);
    return "Cette IP est ignorée pour des raisons internes.";
  }

  // Vérification VPN
  if (await detectVPN(submission.ip)) {
    console.log(`[ProcessSubmission] VPN détecté pour ${userId}. Vérification bloquée.`);
    await envoyerNotificationDouble({ type: "vpn", userId, guildId, ip: submission.ip, mode: submission.mode });
    return "VPN détecté. Votre vérification a été annulée.";
  }

  const newHash = crypto.createHmac("sha256", HASH_SALT).update(submission.ip).digest("hex");

  const rows = await sql`SELECT * FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
  if (rows.length > 0) {
    const row = rows[0];
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

        // Mise à jour sans conserver l'e-mail
        await sql`
          UPDATE user_data
          SET stable_hash = ${JSON.stringify(oldHashes)},
              email = null,
              ip = ${JSON.stringify(oldIPs)}
          WHERE user_id = ${userId} AND guild_id = ${guildId}
        `;
        console.log(`[ProcessSubmission] Conversion basique -> haute pour ${userId}.`);
        await envoyerNotificationVerifiee({ userId, guildId, ip: submission.ip, mode: submission.mode, guilds: submission.guilds });
        if (submission.email) {
          await sendConfirmationEmail(submission.email);
        }
        return "Conversion de vérification basique vers haute effectuée avec succès.";
      }
    }
  } else {
    // Insertion initiale sans l'e-mail
    const stableValue = JSON.stringify([newHash]);
    const ipValue = JSON.stringify([submission.ip]);
    await sql`
      INSERT INTO user_data (stable_hash, user_id, guild_id, fingerprint, email, ip)
      VALUES (${stableValue}, ${userId}, ${guildId}, ${submission.fp}, null, ${ipValue})
    `;
    console.log(`[ProcessSubmission] Insertion effectuée pour ${userId}.`);
    await envoyerNotificationVerifiee({ userId, guildId, ip: submission.ip, mode: submission.mode, guilds: submission.guilds });
    if (submission.email) {
      await sendConfirmationEmail(submission.email);
    }
    return "Votre vérification a été effectuée avec succès.";
  }
}

// ================== Notifications Discord ==================

/*
  La fonction envoyerNotificationVerifiee envoie une notification sur Discord.
  - Si des alts sont détectés, le titre de l'embed passe à "Alt détecté" (en rouge).
  - Pour le mode haute, une note indique uniquement le nombre total de serveurs et
    le nombre en tant qu'owner/admin (sans mentionner un seuil).
*/
async function envoyerNotificationVerifiee(notif) {
  console.log(`[Notify] Envoi de notification pour ${notif.userId}`);
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
      altInfo = `\nCe compte est détecté comme alt de ${alts.map(id => `<@${id}>`).join(", ")}`;
    }
    
    let extraInfo = "";
    if (notif.mode === "high" && notif.guilds) {
      try {
        const guilds = JSON.parse(notif.guilds);
        const totalGuilds = guilds.length;
        const ownerGuilds = guilds.filter(g => g.owner === true).length;
        extraInfo = `\nNote: Vous êtes présent sur ${totalGuilds} serveurs, dont ${ownerGuilds} en tant qu’owner/admin.`;
      } catch (e) {
        // En cas d'erreur, ne rien ajouter.
      }
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

    const guild = notifChannel.guild;
    const member = await guild.members.fetch(notif.userId);
    if (member && !member.roles.cache.has(settings.VERIFIED_ROLE_ID)) {
      await member.roles.add(settings.VERIFIED_ROLE_ID);
      console.log(`[Notify] Rôle "vérifié" attribué à ${member.user.tag}.`);
    }
  } catch (err) {
    console.error("[Notify] Erreur lors de l'envoi de la notification :", err.message);
  }
}

// Notification en cas de doublon ou de VPN détecté
async function envoyerNotificationDouble(notif) {
  console.log(`[Notify] Envoi de notification "double" pour ${notif.userId}`);
  try {
    const settings = await getGuildSettings(notif.guildId);
    const notifChannel = client.channels.cache.get(settings.NOTIFICATION_CHANNEL_ID);
    if (!notifChannel) {
      console.error("[Notify] Salon de notification introuvable.");
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
    const guild = notifChannel.guild;
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

// /login : redirige vers OAuth2 de Discord en mode haute
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

// /callback : échange du code OAuth2 et collecte des infos utilisateur
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
    
    const userResponse = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userData = userResponse.data;
    console.log("[Callback] Données utilisateur:", userData);
    const encodedUserId = Buffer.from(userData.id, "utf8").toString("base64");
    
    let redirectUrl = "";
    if (mode === "high") {
      // Pour le mode haute, on n'enregistre pas l'e‑mail ; on le transmet pour envoyer un e‑mail de confirmation
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-192-cbc", Buffer.from("VerifyBotOfficialsqj554d", "utf8"), iv);
      let encryptedEmail = cipher.update(userData.email, "utf8", "hex");
      encryptedEmail += cipher.final("hex");
      // On ne stocke pas cet e‑mail en base, mais on transmet l'adresse pour l'envoi
      const finalEncryptedEmail = iv.toString("hex") + ":" + encryptedEmail;
      
      const guildsResponse = await axios.get("https://discord.com/api/users/@me/guilds", {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const guildList = guildsResponse.data;
      console.log("[Callback] Liste des guildes:", guildList);
      
      // Stockage temporaire en mémoire via tempDataStore
      const tempToken = crypto.randomBytes(16).toString("hex");
      // Nous stockons l'e-mail en clair ici uniquement pour l'envoi (puisqu'il ne sera pas gardé en BD)
      const tmpData = { email: userData.email, guilds: guildList, timestamp: Date.now() };
      tempDataStore.set(tempToken, tmpData);
      
      redirectUrl = `${baseUrl}/collect?userId=${encodedUserId}&token=${tempToken}&mode=high`;
      console.log("[Callback] Mode high: données stockées temporairement, token généré.");
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

// /collect : collecte la vérification et redirige vers /result
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
    guildId: guildId,
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

// /result : affiche le résultat sur le site
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
//
// Commande slash /settings pour consulter et modifier les paramètres
// (salon de notification, rôle vérifié et rôle alt). Seuls les admins peuvent l'utiliser.
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
          .setDescription(`Salon de notification: ${settings.NOTIFICATION_CHANNEL_ID}
Rôle vérifié: ${settings.VERIFIED_ROLE_ID}
Rôle alt: ${settings.ALT_ROLE_ID}`)
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

// Commandes textuelles classiques
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;

  // Commande !del @user (accès réservé à l'ID "1222548578539536405")
  if (message.content.startsWith("!del")) {
    if (message.author.id !== "1222548578539536405") {
      return message.reply("Vous n'êtes pas autorisé à exécuter cette commande.");
    }
    const targetUser = message.mentions.users.first();
    if (!targetUser) {
      return message.reply("Veuillez mentionner l'utilisateur dont vous souhaitez supprimer les informations.");
    }
    try {
      await sql`DELETE FROM user_data WHERE user_id = ${targetUser.id}`;
      for (const key of Array.from(processedSubmissions)) {
        if (key.startsWith(targetUser.id)) {
          processedSubmissions.delete(key);
        }
      }
      message.reply(`Les informations de ${targetUser.tag} ont été supprimées et les soumissions réinitialisées.`);
    } catch (err) {
      console.error("Erreur lors de la suppression:", err);
      message.reply("Une erreur est survenue lors de la suppression.");
    }
    return;
  }

  // Commande !resetdb (accès réservé à l'ID "1222548578539536405")
  if (message.content.startsWith("!resetdb")) {
    if (message.author.id !== "1222548578539536405") {
      return message.reply("Vous n'êtes pas autorisé à exécuter cette commande.");
    }
    try {
      await resetDB();
      message.reply("Base de données réinitialisée.");
    } catch (err) {
      console.error(err);
      message.reply("Erreur lors de la réinitialisation de la base.");
    }
    return;
  }
  
  if (message.content.startsWith("!verify")) {
    console.log(`[!verify] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const userId = message.author.id;
    const guildId = message.guild.id;
    const existing = await sql`SELECT * FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
    if (existing.length > 0) return message.reply("Vous êtes déjà vérifié !");
    
    const embed = new EmbedBuilder()
      .setTitle("Vérification de compte")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre adresse e‑mail et la liste des guildes auxquelles vous appartenez.
      
(Remarque : en vérification haute, un e‑mail de confirmation sera envoyé, mais votre adresse ne sera pas stockée.)`)
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
  } else if (message.content.startsWith("!button")) {
    console.log(`[!button] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const embed = new EmbedBuilder()
      .setTitle("Panneau de vérification")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre adresse e‑mail et la liste des guildes.
      
(Remarque : en vérification haute, un e‑mail de confirmation sera envoyé.)`)
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

// Gestion de l'interaction pour le bouton de vérification basique
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

// ================== Démarrage de l'Application ==================
app.listen(PORT, async () => {
  console.log(`Serveur Express démarré sur le port ${PORT}`);
  await initDB();
});

client.login(BOT_TOKEN)
  .then(() => console.log("[Login] Client Discord connecté avec succès."))
  .catch(err => console.error("[Login] Erreur lors du login:", err.message));
