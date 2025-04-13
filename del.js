const { Client, GatewayIntentBits } = require('discord.js');
const { Pool } = require('pg');
require('dotenv').config();

// Création du client dédié pour ce module
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ]
});

// Configuration de la connexion à la base de données
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Fonction pour supprimer les données d'un utilisateur
async function deleteUserData(discordId) {
  // Exemple de requête SQL. Adaptez-la selon votre schéma.
  await pool.query('DELETE FROM users WHERE discord_id = $1', [discordId]);
}

// Fonction pour réinitialiser la base de données
async function resetDatabase() {
  // Dans cet exemple, on tronque la table "users" et on réinitialise l'ID.
  // Adaptez cette commande à votre schéma si besoin.
  await pool.query('TRUNCATE TABLE users RESTART IDENTITY');
}

// Écoute de l'événement messageCreate pour traiter les commandes textuelles
client.on('messageCreate', async (message) => {
  // Ignorer les messages des bots
  if (message.author.bot) return;

  // --- Commande !del ---
  if (message.content.startsWith('!del')) {
    // Seul l'utilisateur avec l'ID "1222548578539536405" peut exécuter cette commande
    if (message.author.id !== '1222548578539536405') {
      return message.reply("Tu n'as pas la permission d'exécuter cette commande.");
    }

    // Récupérer l'utilisateur mentionné
    const mentionedUser = message.mentions.users.first();
    if (!mentionedUser) {
      return message.reply("Veuillez mentionner l'utilisateur dont vous souhaitez supprimer les données.");
    }

    try {
      // Supprimer les données de l'utilisateur mentionné
      await deleteUserData(mentionedUser.id);
      message.channel.send(`Les données de ${mentionedUser.tag} ont été supprimées de la base de données.`);
    } catch (error) {
      console.error("Erreur lors de la suppression des données:", error);
      message.channel.send("Une erreur est survenue lors de la suppression des données.");
    }
  }

  // --- Commande !resetdb ---
  if (message.content.startsWith('!resetdb')) {
    // Seul l'utilisateur avec l'ID "1222548578539536405" peut exécuter cette commande
    if (message.author.id !== '1222548578539536405') {
      return message.reply("Tu n'as pas la permission d'exécuter cette commande.");
    }

    try {
      // Réinitialiser la base de données
      await resetDatabase();
      message.channel.send("La base de données a été réinitialisée.");
    } catch (error) {
      console.error("Erreur lors de la réinitialisation de la base:", error);
      message.channel.send("Une erreur est survenue lors de la réinitialisation de la base.");
    }
  }
});

// Connexion du client avec le token provenant de l'environnement
client.login(process.env.BOT_TOKEN);
