// Partie serveur web minimal avec Express
const express = require('express');
const app = express();
const port = process.env.PORT || 8000;

app.get('/', (req, res) => {
  res.send('OK');
});

app.listen(port, () => {
  console.log(`Serveur en écoute sur le port ${port}`);
});

// Partie bot Discord
const { Client, GatewayIntentBits } = require('discord.js');
const discordClient = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ]
});

discordClient.once('ready', () => {
  console.log(`Connecté en tant que ${discordClient.user.tag} !`);
});

discordClient.on('messageCreate', message => {
  if (message.author.bot) return;
  if (message.content === '!test') {
    message.channel.send('Test réussi !');
  }
});

discordClient.login(process.env.BOT_TOKEN); // Remplace TON_TOKEN_ICI par ton vrai token
