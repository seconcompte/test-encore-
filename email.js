const nodemailer = require('nodemailer');
const { EMAIL_PASSWORD } = require('./config');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'autentibotofficial@gmail.com',
    pass: EMAIL_PASSWORD // doit respecter l’utilisation d’un mot de passe d’application
  }
});

async function sendConfirmationEmail(email) {
  const mailOptions = {
    from: 'autentibotofficial@gmail.com',
    to: email,
    subject: 'Confirmation de vérification - AutentiBot',
    text: "Bonjour,\n\nVotre vérification a été effectuée avec succès par AutentiBot.\n\nCordialement,\nL'équipe AutentiBot"
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("E-mail de confirmation envoyé :", info.response);
  } catch (error) {
    console.error("Erreur lors de l'envoi de l'e‑mail de confirmation :", error);
  }
}

module.exports = { sendConfirmationEmail };
