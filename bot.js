// Importation de Client et des bits d'intention depuis discord.js (version 14)
const { Client, GatewayIntentBits } = require('discord.js');

// Création d'une instance du client avec les intentions nécessaires
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,          // Pour récupérer les serveurs du bot
    GatewayIntentBits.GuildMessages,   // Pour recevoir les messages des salons
    GatewayIntentBits.MessageContent   // Pour lire le contenu des messages
  ]
});

// Quand le bot est connecté et prêt
client.once('ready', () => {
  console.log(`Connecté en tant que ${client.user.tag} !`);
});

// Réagir aux messages reçus
client.on('messageCreate', message => {
  // Ignore les messages envoyés par le bot lui-même pour éviter les boucles
  if (message.author.bot) return;
  
  // Si le message est exactement "!test", le bot répond
  if (message.content === '!test') {
    message.channel.send('Test réussi !');
  }
});

// Connexion du bot en utilisant ton token
client.login(process.env.BOT_TOKEN);