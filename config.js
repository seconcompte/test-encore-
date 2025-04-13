require('dotenv/config');

const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_URL = process.env.SERVER_URL; // ex: https://votreapp.exemple.com
const PORT = process.env.PORT || 80;

const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const NOTIFICATION_CHANNEL_ID = process.env.NOTIFICATION_CHANNEL_ID;
const VERIFIED_ROLE_ID = process.env.VERIFIED_ROLE_ID;
const ALT_ROLE_ID = process.env.ALT_ROLE_ID;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const HASH_SALT = process.env.HASH_SALT;

const DEFAULT_NOTIFICATION_CHANNEL_ID = NOTIFICATION_CHANNEL_ID;
const DEFAULT_VERIFIED_ROLE_ID = VERIFIED_ROLE_ID;
const DEFAULT_ALT_ROLE_ID = ALT_ROLE_ID;

const DATABASE_CONFIG = {
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  username: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  ssl: 'require'
};

const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD; // Pour Nodemailer
const API_KEY_VPN = "9a038c170f4d4066a865bd351eddc920";

// Mapping entre l’ID de guilde et le suffixe de route
const ROUTE_SUFFIX_MAP = {
  "1287382398287216650": "-test",
  "1273271104621903892": "-test2",
  "1239302430986866769": "-WAFR",
  "1097110036192448656": "-BLZ"
};

/**
 * Renvoie le suffixe associé à l’ID de guilde, ou une chaîne vide si non défini.
 */
function getRouteSuffix(guildId) {
  return ROUTE_SUFFIX_MAP[guildId] || "";
}

/**
 * Construit l’URL complète pour une route donnée en ajoutant le suffixe associé.
 * @param {string} guildId L’ID de la guilde d’où provient la commande.
 * @param {string} routeName Le nom de la route (ex: "collect", "login", etc.)
 * @returns {string} L’URL complète, par exemple "https://votreapp/collect-test"
 */
function getDynamicRoute(guildId, routeName) {
  const suffix = getRouteSuffix(guildId);
  return `${SERVER_URL}/${routeName}${suffix}`;
}

module.exports = {
  BOT_TOKEN,
  SERVER_URL,
  PORT,
  CLIENT_SECRET,
  CLIENT_ID,
  NOTIFICATION_CHANNEL_ID,
  VERIFIED_ROLE_ID,
  ALT_ROLE_ID,
  LOG_CHANNEL_ID,
  HASH_SALT,
  DEFAULT_NOTIFICATION_CHANNEL_ID,
  DEFAULT_VERIFIED_ROLE_ID,
  DEFAULT_ALT_ROLE_ID,
  DATABASE_CONFIG,
  EMAIL_PASSWORD,
  API_KEY_VPN,
  ROUTE_SUFFIX_MAP,
  getRouteSuffix,
  getDynamicRoute,
};
