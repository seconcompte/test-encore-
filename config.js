// config.js
import 'dotenv/config';

export const BOT_TOKEN = process.env.BOT_TOKEN;
export const SERVER_URL = process.env.SERVER_URL; // ex: https://votreapp.exemple.com
export const PORT = process.env.PORT || 80;

export const CLIENT_SECRET = process.env.CLIENT_SECRET;
export const CLIENT_ID = process.env.CLIENT_ID;
export const NOTIFICATION_CHANNEL_ID = process.env.NOTIFICATION_CHANNEL_ID;
export const VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
export const ALT_ROLE_ID = process.env.ALT_ROLE_ID;
export const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
export const HASH_SALT = process.env.HASH_SALT;

export const DEFAULT_NOTIFICATION_CHANNEL_ID = NOTIFICATION_CHANNEL_ID;
export const DEFAULT_VERIFIED_ROLE_ID = VERIFIED_ROLE_ID;
export const DEFAULT_ALT_ROLE_ID = ALT_ROLE_ID;

export const DATABASE_CONFIG = {
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  username: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  ssl: 'require'
};

export const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD; // pour Nodemailer

export const API_KEY_VPN = "9a038c170f4d4066a865bd351eddc920"; // clé de l'API VPN
