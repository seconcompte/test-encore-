const axios = require('axios');
const dns = require('dns').promises;
const { API_KEY_VPN } = require('./config');

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  try {
    Buffer.from(str, 'base64').toString('utf8');
    return true;
  } catch (e) {
    return false;
  }
}

function isValidToken(token) {
  return /^[a-f0-9]{32}$/i.test(token);
}

function isValidUserId(userId) {
  return /^\d+$/.test(userId);
}

function isValidGuildId(guildId) {
  // Généralement un ID de guilde comporte 17 à 19 chiffres.
  return /^\d{17,19}$/.test(guildId);
}

async function detectVPNviaAPI(ip) {
  try {
    const response = await axios.get(`https://vpnapi.io/api/${ip}?key=${API_KEY_VPN}`);
    if (response.data && response.data.security && response.data.security.vpn === true) {
      console.log(`[VPNAPI.io] L'IP ${ip} est détectée comme VPN.`);
      return true;
    }
  } catch (err) {
    console.error(`[VPNAPI.io] Erreur pour l'IP ${ip}:`, err.response ? err.response.data : err.message);
  }
  return false;
}

async function detectVPNviaDNS(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    console.log(`[VPN DNS] Reverse DNS pour l'IP ${ip}:`, hostnames);
    const keywords = ["vpn", "proxy", "virtual", "datacenter"];
    for (const hostname of hostnames) {
      for (const keyword of keywords) {
        if (hostname.toLowerCase().includes(keyword)) {
          console.log(`[VPN DNS] L'IP ${ip} (hostname: ${hostname}) contient "${keyword}".`);
          return true;
        }
      }
    }
  } catch (err) {
    console.error(`[VPN DNS] Erreur pour l'IP ${ip}:`, err.message);
  }
  return false;
}

async function detectVPN(ip) {
  return (await detectVPNviaAPI(ip)) || (await detectVPNviaDNS(ip));
}

module.exports = {
  isValidBase64,
  isValidToken,
  isValidUserId,
  isValidGuildId,
  detectVPNviaAPI,
  detectVPNviaDNS,
  detectVPN,
};
