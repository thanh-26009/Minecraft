/*
 * ============================================================
 *  Minecraft AFK Bot — mineflayer (Microsoft Account)
 *  + Web Dashboard on port 26065
 *
 *  HAI LUỒNG ĐỘC LẬP:
 *    Luồng 1 — Bot Minecraft  : chạy tại file này
 *    Luồng 2 — Proxy Server   : proxy/proxy-server.js
 *
 *  INSTALL:
 *    npm install mineflayer socks
 *
 *  RUN:
 *    node afk-bot.js
 * ============================================================
 */

// ── Khởi động Proxy Server (luồng 2, hoàn toàn độc lập) ───
require('./proxy');

// ══════════════════════════════════════════════════════════
//  LUỒNG 1 — BOT MINECRAFT (giữ nguyên 100% như code cũ)
// ══════════════════════════════════════════════════════════

const mineflayer = require('mineflayer');
const http       = require('http');
const fs         = require('fs');
const path       = require('path');

// ── Configuration ──────────────────────────────────────────
const HOST     = 'donutsmp.net';
const PORT     = 25565;
const WEB_PORT = 25996;
// ──────────────────────────────────────────────────────────

let afkCommandSent = false;
let jumpInterval   = null;
let bot            = null;
let botEnabled     = true;
let reconnectTimer = null;
let startTime      = Date.now();

const state = {
  status:     'Stopped',
  username:   '—',
  uptime:     0,
  logs:       [],
  botEnabled: true,
};

let connectedAt = null;

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function log(msg) {
  const ts   = new Date().toLocaleTimeString();
  const line = `[${ts}] ${msg}`;
  console.log(line);
  state.logs.push(line);
  if (state.logs.length > 200) state.logs.shift();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function startJumping() {
  if (jumpInterval) return;
  log('Started jumping.');
  jumpInterval = setInterval(() => {
    if (!bot) return;
    bot.setControlState('jump', true);
    setTimeout(() => {
      if (bot) bot.setControlState('jump', false);
    }, 100);
  }, 1000);
}

function stopJumping() {
  if (jumpInterval) {
    clearInterval(jumpInterval);
    jumpInterval = null;
  }
  if (bot) {
    try { bot.setControlState('jump', false); } catch (_) {}
  }
}

function createBot() {
  if (!botEnabled) {
    log('Bot is disabled. Not connecting.');
    state.status = 'Stopped';
    return;
  }

  log('Creating bot with Microsoft account...');
  state.status = 'Connecting';

  bot = mineflayer.createBot({
    host:    HOST,
    port:    PORT,
    auth:    'microsoft',
    version: false,
  });

  bot.once('spawn', async () => {
    connectedAt    = Date.now();
    state.username = bot.username;
    state.status   = 'Online';
    log(`Connected as ${bot.username}.`);

    if (!afkCommandSent) {
      const delay = randomInt(2000, 5000);
      log(`Waiting ${delay}ms before sending /afk...`);
      await sleep(delay);

      const afkNumber = randomInt(5, 35);
      bot.chat(`/afk ${afkNumber}`);
      afkCommandSent = true;
      log(`Sent: /afk ${afkNumber}`);
      log('Waiting 10 seconds for /afk to take effect...');
      await sleep(10000);
      log('/afk ready.');
    } else {
      log('Skipping /afk (already sent in a previous session).');
    }

    log('Waiting for stability...');
    await sleep(3000);
    startJumping();
  });

  bot.on('end', (reason) => {
    log(`Disconnected. Reason: ${reason || 'unknown'}`);
    state.status   = 'Disconnected';
    state.username = '—';
    connectedAt    = null;
    stopJumping();
    bot = null;
    if (botEnabled) scheduleReconnect();
  });

  bot.on('error', (err) => {
    log(`Error: ${err.message}`);
  });

  bot.on('kicked', (reason) => {
    try {
      const parsed = JSON.parse(reason);
      log(`Kicked: ${parsed.text || JSON.stringify(parsed)}`);
    } catch (_) {
      log(`Kicked: ${reason}`);
    }
  });
}

function scheduleReconnect() {
  log('Reconnecting in 60 seconds...');
  state.status = 'Reconnecting...';
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    createBot();
  }, 60000);
}

const webServer = http.createServer((req, res) => {
  const url = req.url;

  if (url === '/api/status') {
    const uptime = connectedAt ? Math.floor((Date.now() - connectedAt) / 1000) : 0;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status:     state.status,
      username:   state.username,
      uptime,
      botEnabled: botEnabled,
      logs:       state.logs.slice(-50),
    }));
    return;
  }

  if (url === '/api/start' && req.method === 'POST') {
    if (!botEnabled) {
      botEnabled       = true;
      state.botEnabled = true;
      log('Bot enabled via dashboard.');
      createBot();
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url === '/api/reconnect' && req.method === 'POST') {
    log('Force reconnect triggered via dashboard.');
    stopJumping();
    if (bot) {
      try { bot.quit('Force reconnect by dashboard'); } catch (_) {}
      bot = null;
    }
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    botEnabled   = true;
    state.status = 'Connecting';
    createBot();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url === '/api/stop' && req.method === 'POST') {
    if (botEnabled) {
      botEnabled       = false;
      state.botEnabled = false;
      afkCommandSent   = false;
      log('Bot disabled via dashboard.');
      stopJumping();
      if (bot) {
        try { bot.quit('Stopped by dashboard'); } catch (_) {}
        bot = null;
      }
      state.status = 'Stopped';
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url === '/' || url === '/index.html') {
    const htmlPath = path.join(__dirname, 'dashboard.html');
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(htmlPath));
    } else {
      res.writeHead(404);
      res.end('dashboard.html not found');
    }
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

webServer.listen(WEB_PORT, () => {
  log(`Dashboard running at http://localhost:${WEB_PORT}`);
});

createBot();
