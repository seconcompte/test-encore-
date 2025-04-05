const { Client, GatewayIntentBits } = require('discord.js');
const { Pool } = require('pg');

// Configurez votre client Discord
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ]
});

// Configuration de la connexion à la base de données
// Assurez-vous que votre chaîne de connexion est bien définie via la variable d'environnement DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Fonction pour supprimer les données d'un utilisateur dans la base
async function deleteUserData(discordId) {
  // Exemple de requête SQL, à adapter selon votre schéma de base.
  await pool.query('DELETE FROM users WHERE discord_id = $1', [discordId]);
}

// Événement qui se déclenche à la réception d'un message
client.on('messageCreate', async (message) => {
  // Ignorer les messages des bots
  if (message.author.bot) return;

  // Vérifier si la commande commence par !del
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
      // Supprimer les données de l'utilisateur mentionné de la base
      await deleteUserData(mentionedUser.id);
      message.channel.send(`Les données de ${mentionedUser.tag} ont été supprimées de la base de données.`);
    } catch (error) {
      console.error("Erreur lors de la suppression des données:", error);
      message.channel.send("Une erreur est survenue lors de la suppression des données.");
    }
  }
});

// Connectez votre bot en utilisant votre token (souvent stocké dans une variable d'environnement)
client.login(process.env.BOT_TOKEN);
