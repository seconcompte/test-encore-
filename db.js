// db.js
import postgres from 'postgres';
import { DATABASE_CONFIG, DEFAULT_NOTIFICATION_CHANNEL_ID, DEFAULT_VERIFIED_ROLE_ID, DEFAULT_ALT_ROLE_ID, HASH_SALT } from './config.js';
import { isValidBase64, isValidUserId, isValidGuildId, detectVPN } from './utils.js';
import crypto from 'crypto';
import { sendConfirmationEmail } from './email.js';

export const sql = postgres(DATABASE_CONFIG);

export async function initDB() {
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

export async function resetDB() {
  await sql`DROP TABLE IF EXISTS user_data;`;
  await sql`DROP TABLE IF EXISTS guild_settings;`;
  await initDB();
}

export async function getGuildSettings(guildId) {
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

export async function getAlts(userId, guildId) {
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

// Ensemble des soumissions déjà traitées (pour éviter les doublons)
const processedSubmissions = new Set();

export async function processSubmission(submission) {
  console.log("PROCESSING SUBMISSION:", submission);
  let userId, guildId;
  try {
    if (!submission.userId || !isValidBase64(submission.userId))
      throw new Error("UserId encodé invalide.");
    userId = Buffer.from(submission.userId, "base64").toString("utf8");
    if (!isValidUserId(userId))
      throw new Error("UserId décodé invalide.");
    if (submission.guildId) {
      if (!isValidBase64(submission.guildId))
        throw new Error("GuildId encodé invalide.");
      guildId = Buffer.from(submission.guildId, "base64").toString("utf8");
      if (!isValidGuildId(guildId))
        throw new Error("GuildId décodé invalide.");
    } else {
      guildId = "";
    }
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

  // Vérification VPN
  if (await detectVPN(submission.ip)) {
    console.log(`[ProcessSubmission] VPN détecté pour ${userId}. Vérification bloquée.`);
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

        await sql`
          UPDATE user_data
          SET stable_hash = ${JSON.stringify(oldHashes)},
              email = null,
              ip = ${JSON.stringify(oldIPs)}
          WHERE user_id = ${userId} AND guild_id = ${guildId}
        `;
        console.log(`[ProcessSubmission] Conversion basique -> haute pour ${userId}.`);
        if (submission.email) await sendConfirmationEmail(submission.email);
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
    if (submission.email) await sendConfirmationEmail(submission.email);
    return "Votre vérification a été effectuée avec succès.";
  }
}
