// deploy-commands.js
import { REST, Routes, ApplicationCommandOptionType } from 'discord.js';
import 'dotenv/config';

const commands = [
  {
    name: 'recherche',
    description: 'Recherche les alts d’un utilisateur',
    options: [
      {
        type: ApplicationCommandOptionType.User,
        name: 'utilisateur',
        description: 'L’utilisateur à rechercher',
        required: true
      }
    ]
  },
  {
    name: 'settings',
    description: 'Configurer ou afficher les réglages du serveur',
    options: [
      {
        type: ApplicationCommandOptionType.Subcommand,
        name: 'view',
        description: 'Afficher les réglages actuels'
      },
      {
        type: ApplicationCommandOptionType.Subcommand,
        name: 'set',
        description: 'Mettre à jour les réglages du serveur',
        options: [
          {
            type: ApplicationCommandOptionType.Channel,
            name: 'notification_channel',
            description: 'Le salon de notifications',
            required: true
          },
          {
            type: ApplicationCommandOptionType.Role,
            name: 'verified_role',
            description: 'Le rôle vérifié',
            required: true
          },
          {
            type: ApplicationCommandOptionType.Role,
            name: 'alt_role',
            description: 'Le rôle alt',
            required: true
          }
        ]
      }
    ]
  }
];

const rest = new REST({ version: '10' }).setToken(process.env.BOT_TOKEN);

(async () => {
  try {
    // Déploiement sur le serveur de test d'abord
    const testGuildId = "1287382398287216650";
    console.log(`Déploiement des commandes sur le serveur ${testGuildId} en cours...`);
    await rest.put(
      Routes.applicationGuildCommands(process.env.CLIENT_ID, testGuildId),
      { body: commands }
    );
    console.log(`Commandes déployées avec succès sur le serveur ${testGuildId}.`);

    // Ensuite, déploiement global
    console.log('Déploiement global des commandes en cours...');
    await rest.put(
      Routes.applicationCommands(process.env.CLIENT_ID),
      { body: commands }
    );
    console.log('Les commandes slash globales ont été déployées avec succès.');
  } catch (error) {
    console.error('Erreur lors du déploiement des commandes slash:', error);
  }
})();
