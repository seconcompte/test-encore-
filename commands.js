// deploy-commands.js
import { REST, Routes, ApplicationCommandOptionType, ApplicationCommandType } from 'discord.js';
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
    console.log('Déploiement global des commandes slash en cours...');
    await rest.put(
      Routes.applicationCommands(process.env.CLIENT_ID),
      { body: commands }
    );
    console.log('Les commandes slash globales ont été déployées avec succès.');
  } catch (error) {
    console.error(error);
  }
})();
