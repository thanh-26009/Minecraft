/*
 * ============================================================
 *  Minecraft AFK Bot — mineflayer (Microsoft Account)
 *  + Web Dashboard on port 25952
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
//  LUỒNG 1 — BOT MINECRAFT
// ══════════════════════════════════════════════════════════

const mineflayer = require('mineflayer');
const http       = require('http');
const https      = require('https');
const fs         = require('fs');
const path       = require('path');

// ── Configuration ──────────────────────────────────────────
const HOST     = 'donutsmp.net';
const PORT     = 25565;
const WEB_PORT = 25952;

// ⚙️ DonutSMP API — chỉnh sửa 2 dòng này
const DONUT_USER   = 'Mr_Zerone';
const DONUT_APIKEY = '6b626db44ff94db4b204ef4135e99b08';

const DONUT_REFRESH_MS = 10 * 60 * 1000; // 10 phút
// ──────────────────────────────────────────────────────────

let afkCommandSent = false;
let jumpInterval   = null;
let bot            = null;
let botEnabled     = true;
let reconnectTimer = null;

const state = {
  status:     'Stopped',
  username:   '—',
  uptime:     0,
  logs:       [],
  botEnabled: true,
};

// ── DonutSMP stats cache ───────────────────────────────────
const donutCache = {
  data:      null,   // { shards, playtime, fetchedAt }
  error:     null,   // string | null
  loading:   false,
  lastFetch: 0,
};

let connectedAt = null;

// ── Helpers ────────────────────────────────────────────────
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function log(msg) {
  const ts   = new Date().toLocaleTimeString('vi-VN');
  const line = `[${ts}] ${msg}`;
  console.log(line);
  state.logs.push(line);
  if (state.logs.length > 200) state.logs.shift();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── DonutSMP fetch (server-side, không bị CORS) ────────────
function fetchDonutStats() {
  if (donutCache.loading) return; // tránh gọi đồng thời
  donutCache.loading = true;
  donutCache.error   = null;

  log(`[DonutSMP] Đang lấy stats cho "${DONUT_USER}"...`);

  const options = {
    hostname: 'api.donutsmp.net',
    path:     `/v1/stats/${encodeURIComponent(DONUT_USER)}`,
    method:   'GET',
    headers: {
      'accept':        'application/json',
      'Authorization': DONUT_APIKEY,
    },
  };

  const req = https.request(options, (res) => {
    let raw = '';
    res.on('data', chunk => { raw += chunk; });
    res.on('end', () => {
      donutCache.loading   = false;
      donutCache.lastFetch = Date.now();

      if (res.statusCode !== 200) {
        donutCache.error = `HTTP ${res.statusCode}: ${raw.slice(0, 120)}`;
        log(`[DonutSMP] Lỗi: ${donutCache.error}`);
        scheduleNextDonutFetch();
        return;
      }

      try {
        const json = JSON.parse(raw);
        if (json.status !== 200 || !json.result) {
          throw new Error(`API trả về: ${JSON.stringify(json).slice(0, 120)}`);
        }
        const r = json.result;
        donutCache.data = {
          shards:    Number(r.shards   ?? r.Shards   ?? 0),
          playtime:  Number(r.playtime ?? r.Playtime ?? 0), // ms
          fetchedAt: Date.now(),
        };
        donutCache.error = null;
        log(`[DonutSMP] OK — Shards: ${donutCache.data.shards.toLocaleString()}, Playtime: ${donutCache.data.playtime}ms`);
      } catch (e) {
        donutCache.error = e.message;
        log(`[DonutSMP] Parse lỗi: ${e.message}`);
      }

      scheduleNextDonutFetch();
    });
  });

  req.on('error', (e) => {
    donutCache.loading = false;
    donutCache.error   = e.message;
    log(`[DonutSMP] Network lỗi: ${e.message}`);
    scheduleNextDonutFetch();
  });

  req.setTimeout(15000, () => {
    req.destroy();
    donutCache.loading = false;
    donutCache.error   = 'Timeout sau 15 giây';
    log(`[DonutSMP] Timeout.`);
    scheduleNextDonutFetch();
  });

  req.end();
}

function scheduleNextDonutFetch() {
  setTimeout(fetchDonutStats, DONUT_REFRESH_MS);
}

// ── Bot logic ──────────────────────────────────────────────
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

      const afkNumber = randomInt(5, 60);
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

// ── Web server ─────────────────────────────────────────────
const webServer = http.createServer((req, res) => {
  const url = req.url;

  // ── /api/status ──
  if (url === '/api/status') {
    const uptime = connectedAt ? Math.floor((Date.now() - connectedAt) / 1000) : 0;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status:     state.status,
      username:   state.username,
      uptime,
      botEnabled,
      logs:       state.logs.slice(-50),
    }));
    return;
  }

  // ── /api/donut-stats  (proxy không CORS) ──
  if (url === '/api/donut-stats') {
    const nextRefreshIn = Math.max(0, DONUT_REFRESH_MS - (Date.now() - donutCache.lastFetch));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      loading:       donutCache.loading,
      error:         donutCache.error,
      data:          donutCache.data,
      nextRefreshIn, // ms còn lại đến lần refresh tiếp theo
      refreshMs:     DONUT_REFRESH_MS,
    }));
    return;
  }

  // ── /api/donut-refresh  (buộc fetch ngay) ──
  if (url === '/api/donut-refresh' && req.method === 'POST') {
    donutCache.lastFetch = 0; // reset để fetchDonutStats không bị skip
    fetchDonutStats();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── /api/start ──
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

  // ── /api/reconnect ──
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

  // ── /api/stop ──
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

  // ── Serve dashboard.html ──
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

// ── Khởi động ──────────────────────────────────────────────
createBot();
fetchDonutStats(); // lấy stats ngay khi server khởi động
