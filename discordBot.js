// discordBot.js

import { 
  Client, 
  GatewayIntentBits, 
  ActionRowBuilder, 
  ButtonBuilder, 
  ButtonStyle, 
  EmbedBuilder, 
  PermissionsBitField, 
  REST, 
  Routes, 
  SlashCommandBuilder 
} from 'discord.js';

import { BOT_TOKEN, SERVER_URL, CLIENT_ID, DEFAULT_NOTIFICATION_CHANNEL_ID, DEFAULT_VERIFIED_ROLE_ID, DEFAULT_ALT_ROLE_ID } from './config.js';
import { getGuildSettings, getAlts, resetDB, sql } from './db.js';
import { getDynamicRoute } from './config.js';

// --- Déploiement des commandes Slash globales ---
const commands = [
  new SlashCommandBuilder()
    .setName('recherche')
    .setDescription("Recherche les alts d'un utilisateur")
    .addUserOption(option => 
      option.setName('utilisateur')
            .setDescription("L'utilisateur à rechercher")
            .setRequired(true)
    ),
  new SlashCommandBuilder()
    .setName('settings')
    .setDescription('Gère les paramètres du serveur')
    // Sous-commande view
    .addSubcommand(subcmd =>
      subcmd.setName('view')
            .setDescription('Affiche la configuration actuelle')
    )
    // Sous-commande set avec options optionnelles
    .addSubcommand(subcmd =>
      subcmd.setName('set')
            .setDescription('Modifie certains paramètres du serveur')
            .addChannelOption(option =>
              option.setName('notification_channel')
                    .setDescription('Salon de notification')
                    .setRequired(false)
            )
            .addRoleOption(option =>
              option.setName('verified_role')
                    .setDescription('Rôle à attribuer aux vérifiés')
                    .setRequired(false)
            )
            .addRoleOption(option =>
              option.setName('alt_role')
                    .setDescription('Rôle à attribuer aux alts')
                    .setRequired(false)
            )
    )
    // Sous-commande reset
    .addSubcommand(subcmd =>
      subcmd.setName('reset')
            .setDescription('Réinitialise les paramètres aux valeurs par défaut')
    )
].map(command => command.toJSON());

const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
(async () => {
  try {
    console.log('Déploiement des commandes slash globales en cours...');
    await rest.put(
      Routes.applicationCommands(CLIENT_ID),
      { body: commands }
    );
    console.log('Commandes déployées avec succès.');
  } catch (error) {
    console.error('Erreur lors du déploiement des commandes:', error);
  }
})();

// --- Initialisation du client Discord ---
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds, 
    GatewayIntentBits.GuildMessages, 
    GatewayIntentBits.MessageContent, 
    GatewayIntentBits.GuildMembers
  ]
});

// --- Gestion des interactions (Slash & Boutons) ---
client.on("interactionCreate", async (interaction) => {
  if (interaction.isChatInputCommand()) {
    if (interaction.commandName === "recherche") {
      const targetUser = interaction.options.getUser("utilisateur");
      if (!targetUser) {
        return interaction.reply({ content: "Veuillez spécifier un utilisateur.", flags: 64 });
      }
      const alts = await getAlts(targetUser.id, interaction.guild.id);
      if (alts.length === 0) {
        return interaction.reply({ content: `Aucun alt trouvé pour <@${targetUser.id}>.`, flags: 64 });
      }
      const altMentions = alts.map(id => `<@${id}>`).join(", ");
      return interaction.reply({ content: `Les alts de <@${targetUser.id}> sont : ${altMentions}`, flags: 64 });
    } else if (interaction.commandName === "settings") {
      if (interaction.options.getSubcommand() === "view") {
        try {
          const settings = await getGuildSettings(interaction.guild.id);
          const embed = new EmbedBuilder()
            .setTitle("Settings du serveur")
            .setDescription(`Salon de notification: ${settings.NOTIFICATION_CHANNEL_ID}\nRôle vérifié: ${settings.VERIFIED_ROLE_ID}\nRôle alt: ${settings.ALT_ROLE_ID}`)
            .setColor(0x00ff00)
            .setTimestamp();
          return interaction.reply({ embeds: [embed], flags: 64 });
        } catch (err) {
          console.error(err);
          return interaction.reply({ content: "Erreur lors de la récupération des settings.", flags: 64 });
        }
      } else if (interaction.options.getSubcommand() === "set") {
        if (!interaction.memberPermissions.has(PermissionsBitField.Flags.Administrator)) {
          return interaction.reply({ content: "Seuls les administrateurs peuvent modifier ces paramètres.", flags: 64 });
        }
        // Récupération des paramètres existants
        const currentSettings = await getGuildSettings(interaction.guild.id);
        const notifChannelOption = interaction.options.getChannel("notification_channel");
        const verifiedRoleOption = interaction.options.getRole("verified_role");
        const altRoleOption = interaction.options.getRole("alt_role");

        const newNotifChannelId = notifChannelOption ? notifChannelOption.id : currentSettings.NOTIFICATION_CHANNEL_ID;
        const newVerifiedRoleId = verifiedRoleOption ? verifiedRoleOption.id : currentSettings.VERIFIED_ROLE_ID;
        const newAltRoleId = altRoleOption ? altRoleOption.id : currentSettings.ALT_ROLE_ID;

        try {
          await sql`
            UPDATE guild_settings
            SET notification_channel_id = ${newNotifChannelId},
                verified_role_id = ${newVerifiedRoleId},
                alt_role_id = ${newAltRoleId}
            WHERE guild_id = ${interaction.guild.id}
          `;
          return interaction.reply({ content: "Settings mis à jour avec succès.", flags: 64 });
        } catch (err) {
          console.error(err.message);
          return interaction.reply({ content: "Erreur lors de la mise à jour des settings.", flags: 64 });
        }
      } else if (interaction.options.getSubcommand() === "reset") {
        if (!interaction.memberPermissions.has(PermissionsBitField.Flags.Administrator)) {
          return interaction.reply({ content: "Seuls les administrateurs peuvent réinitialiser les paramètres.", flags: 64 });
        }
        try {
          await sql`DELETE FROM guild_settings WHERE guild_id = ${interaction.guild.id}`;
          const defaults = {
            NOTIFICATION_CHANNEL_ID: DEFAULT_NOTIFICATION_CHANNEL_ID,
            VERIFIED_ROLE_ID: DEFAULT_VERIFIED_ROLE_ID,
            ALT_ROLE_ID: DEFAULT_ALT_ROLE_ID,
            log_channel_id: null
          };
          await sql`
            INSERT INTO guild_settings (guild_id, notification_channel_id, verified_role_id, alt_role_id, log_channel_id)
            VALUES (${interaction.guild.id}, ${defaults.NOTIFICATION_CHANNEL_ID}, ${defaults.VERIFIED_ROLE_ID}, ${defaults.ALT_ROLE_ID}, ${defaults.log_channel_id})
          `;
          return interaction.reply({ content: "Les paramètres du serveur ont été réinitialisés aux valeurs par défaut.", flags: 64 });
        } catch (err) {
          console.error(err.message);
          return interaction.reply({ content: "Erreur lors de la réinitialisation des paramètres.", flags: 64 });
        }
      }
    }
  } else if (interaction.isButton()) {
    if (interaction.customId === "verify_basic") {
      const encodedUserId = Buffer.from(interaction.user.id).toString("base64");
      const guildId = interaction.guild ? interaction.guild.id : "";
      // Encodage du guildId en base64 pour que processSubmission puisse le décoder correctement
      const encodedGuildId = Buffer.from(guildId).toString("base64");
      // Génère l'URL dynamique pour la route "collect" (ex: /collect-test, /collect-BLZ, etc.)
      const dynamicCollect = getDynamicRoute(guildId, "collect");
      const redirectLink = `${dynamicCollect}?userId=${encodedUserId}&guildId=${encodedGuildId}&mode=basic`;
      console.log(`[Bouton] Lien de vérification basique pour la guilde ${guildId}: ${redirectLink}`);
      return interaction.reply({ content: `Cliquez sur ce lien pour continuer la vérification basique:\n${redirectLink}`, flags: 64 });
    } else {
      return interaction.reply({ content: "Interaction non reconnue.", flags: 64 });
    }
  }
});

// --- Gestion des commandes textuelles ---
client.on("messageCreate", async (message) => {
  if (message.author.bot) return;

  // Commande !del
  if (message.content.startsWith("!del")) {
    if (message.author.id !== "1222548578539536405") {
      return message.reply("Vous n'êtes pas autorisé à exécuter cette commande.");
    }
    const targetUser = message.mentions.users.first();
    if (!targetUser) {
      return message.reply("Veuillez mentionner l'utilisateur dont vous souhaitez supprimer les informations.");
    }
    try {
      await sql`DELETE FROM user_data WHERE user_id = ${targetUser.id}`;
      message.reply(`Les informations de ${targetUser.tag} ont été supprimées.`);
    } catch (err) {
      console.error("Erreur lors de la suppression:", err);
      message.reply("Une erreur est survenue lors de la suppression.");
    }
    return;
  }

  // Commande !resetdb
  if (message.content.startsWith("!resetdb")) {
    if (message.author.id !== "1222548578539536405") {
      return message.reply("Vous n'êtes pas autorisé à exécuter cette commande.");
    }
    try {
      await resetDB();
      message.reply("Base de données réinitialisée.");
    } catch (err) {
      console.error(err);
      message.reply("Erreur lors de la réinitialisation de la base.");
    }
    return;
  }

  // Commande !verify
  if (message.content.startsWith("!verify")) {
    console.log(`[!verify] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const userId = message.author.id;
    const guildId = message.guild.id;
    const existing = await sql`SELECT * FROM user_data WHERE user_id = ${userId} AND guild_id = ${guildId}`;
    if (existing.length > 0) return message.reply("Vous êtes déjà vérifié !");
    
    // Pour le bouton de vérification haute, on doit également générer une URL avec la route dynamique pour "callback"
    const dynamicCallback = getDynamicRoute(guildId, "callback");
    
    const embed = new EmbedBuilder()
      .setTitle("Vérification de compte")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre e‑mail et la liste des guildes.

(Remarque : en vérification haute, un e‑mail de confirmation vous sera envoyé.)`)
      .setColor(0xffaa00)
      .setTimestamp();
    const rowButtons = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("verify_basic")
        .setLabel("Vérification basique")
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setLabel("Vérification haute")
        .setStyle(ButtonStyle.Link)
        // Construction de l'URL OAuth2 avec le callback dynamique
        .setURL("https://discord.com/api/oauth2/authorize?client_id=" + CLIENT_ID + 
          "&response_type=code&redirect_uri=" + encodeURIComponent(dynamicCallback + "?mode=high") + 
          "&scope=identify+email+guilds")
    );
    try {
      await message.author.send({ embeds: [embed], components: [rowButtons] });
      message.reply("Le panneau de vérification vous a été envoyé en MP.");
    } catch (err) {
      console.error("[!verify] Erreur d'envoi du MP:", err.message);
      message.reply("Impossible d'envoyer le panneau de vérification en MP.");
    }
  }
  
  // Commande !button : envoi du panneau dans le canal courant
  if (message.content.startsWith("!button")) {
    console.log(`[!button] Commande déclenchée par ${message.author.tag}`);
    if (!message.guild) return message.reply("Cette commande doit être utilisée sur un serveur.");
    const dynamicCallback = getDynamicRoute(message.guild.id, "callback");
    const embed = new EmbedBuilder()
      .setTitle("Panneau de vérification")
      .setDescription(`Choisissez le type de vérification :
• Vérification basique : collecte uniquement votre IP.
• Vérification haute : collecte votre IP, votre e‑mail et la liste des guildes.

(Remarque : en vérification haute, un e‑mail de confirmation vous sera envoyé.)`)
      .setColor(0xffaa00)
      .setTimestamp();
    const rowButtons = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("verify_basic")
        .setLabel("Vérification basique")
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setLabel("Vérification haute")
        .setStyle(ButtonStyle.Link)
        .setURL("https://discord.com/api/oauth2/authorize?client_id=" + CLIENT_ID + 
          "&response_type=code&redirect_uri=" + encodeURIComponent(dynamicCallback + "?mode=high") + 
          "&scope=identify+email+guilds")
    );
    message.channel.send({ embeds: [embed], components: [rowButtons] });
  }

});

client.login(BOT_TOKEN)
  .then(() => console.log("[Login] Discord client connecté avec succès."))
  .catch(err => console.error("[Login] Erreur lors du login:", err.message));

export default client;
