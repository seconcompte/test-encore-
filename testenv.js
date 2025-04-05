// testenv.js
// Ce script charge toutes les variables d'environnement du fichier .env et les affiche,
// afin de vérifier qu'elles sont correctement chargées.

require("dotenv").config();

console.log("------ Variables d'environnement ------");
console.log("BOT_TOKEN =", process.env.BOT_TOKEN);
console.log("SERVER_URL =", process.env.SERVER_URL);
console.log("PORT =", process.env.PORT);
console.log("CLIENT_ID =", process.env.CLIENT_ID);
console.log("CLIENT_SECRET =", process.env.CLIENT_SECRET);
console.log("NOTIFICATION_CHANNEL_ID =", process.env.NOTIFICATION_CHANNEL_ID);
console.log("VERIFIED_ROLE_ID =", process.env.VERIFIED_ROLE_ID);
console.log("ALT_ROLE_ID =", process.env.ALT_ROLE_ID);
console.log("LOG_CHANNEL_ID =", process.env.LOG_CHANNEL_ID);
console.log("HASH_SALT =", process.env.HASH_SALT);
console.log("MYSQL_HOST =", process.env.MYSQL_HOST);
console.log("MYSQL_PORT =", process.env.MYSQL_PORT);
console.log("MYSQL_USER =", process.env.MYSQL_USER);
console.log("MYSQL_PASSWORD =", process.env.MYSQL_PASSWORD);
console.log("MYSQL_DATABASE =", process.env.MYSQL_DATABASE);
console.log("------ Fin des variables ------");
