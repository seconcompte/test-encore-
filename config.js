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

export const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD; // Pour Nodemailer
export const API_KEY_VPN = "9a038c170f4d4066a865bd351eddc920";

// Mapping entre l’ID de guilde et le suffixe de route
export const ROUTE_SUFFIX_MAP = {
  "1287382398287216650": "-test",
  "1273271104621903892": "-test2",
  "1239302430986866769": "-WAFR",
  "1097110036192448656": "-BLZ"
};

/**
 * Renvoie le suffixe associé à l’ID de guilde, ou une chaîne vide si non défini.
 */
export function getRouteSuffix(guildId) {
  return ROUTE_SUFFIX_MAP[guildId] || "";
}

/**
 * Construit l’URL complète pour une route donnée en ajoutant le suffixe associé
 * @param {string} guildId L’ID de la guilde d’où provient la commande.
 * @param {string} routeName Le nom de la route (ex: "collect", "login", etc.)
 * @returns {string} L’URL complète, par exemple "https://votreapp/collect-test"
 */
export function getDynamicRoute(guildId, routeName) {
  const suffix = getRouteSuffix(guildId);
  return `${SERVER_URL}/${routeName}${suffix}`;
}
