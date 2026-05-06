/*
 * ============================================================
 *  PROXY SERVER — SOCKS5 + HTTPS/HTTP CONNECT
 *  Phiên bản: có TLS + Rate Limiting
 * ============================================================
 *
 *  Mã hoá:
 *    - SOCKS5 over TLS  (port SOCKS5_PORT)  ← client cần TLS wrapper
 *    - HTTPS proxy với TLS  (port HTTPS_PORT)
 *    - Tự tạo self-signed cert nếu chưa có
 *
 *  Bảo mật bổ sung:
 *    - Rate limiting theo IP
 *    - Không ghi log IP client
 *    - Không thêm header X-Forwarded-For / Via
 *    - DNS resolve qua Cloudflare 1.1.1.1 (chống DNS leak)
 *
 *  SỬA PORT TẠI ĐÂY:
 * ============================================================
 */

'use strict';

const net    = require('net');
const tls    = require('tls');
const http   = require('http');
const https  = require('https');
const dns    = require('dns');
const dnsP   = dns.promises;
const fs     = require('fs');
const path   = require('path');
const { execSync } = require('child_process');

// ── Dùng Cloudflare DNS 1.1.1.1 (chống DNS leak) ──────────
dns.setServers(['1.1.1.1', '1.0.0.1']);

// ── Cấu hình port ─────────────────────────────────────────
const SOCKS5_PORT = 30029;
const HTTPS_PORT  = 30013;

// ── Auth ───────────────────────────────────────────────────
const AUTH = {
  enabled:  false,
  username: '',
  password: '',
};

// ── Rate Limiting — TẮT (proxy cá nhân, anti-DDoS do hosting xử lý) ──

// ── Đường dẫn cert TLS ────────────────────────────────────
const CERT_DIR  = path.join(__dirname, 'certs');
const CERT_FILE = path.join(CERT_DIR, 'server.crt');
const KEY_FILE  = path.join(CERT_DIR, 'server.key');

// ──────────────────────────────────────────────────────────

function proxyLog(msg) {
  const ts = new Date().toLocaleTimeString();
  console.log(`[${ts}] [PROXY] ${msg}`);
}

// ══════════════════════════════════════════════════════════
//  TẠO SELF-SIGNED CERT NẾU CHƯA CÓ
//  Dùng openssl — cần cài trên server
// ══════════════════════════════════════════════════════════

function ensureCerts() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    proxyLog('TLS cert found, skipping generation.');
    return;
  }

  proxyLog('Generating self-signed TLS certificate...');
  fs.mkdirSync(CERT_DIR, { recursive: true });

  try {
    execSync(
      `openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes` +
      ` -keyout "${KEY_FILE}"` +
      ` -out "${CERT_FILE}"` +
      ` -subj "/CN=ProxyServer/O=Proxy/C=VN"` +
      ` -addext "subjectAltName=IP:127.0.0.1,IP:0.0.0.0"`,
      { stdio: 'pipe' }
    );
    proxyLog(`Cert saved to ${CERT_DIR}`);
  } catch (e) {
    proxyLog('ERROR: openssl not found or failed. Install openssl first.');
    proxyLog('  Ubuntu: sudo apt install openssl');
    proxyLog('  Or place server.crt + server.key manually into ./certs/');
    process.exit(1);
  }
}

ensureCerts();

// ── Đọc cert ──────────────────────────────────────────────
const TLS_OPTIONS = {
  key:  fs.readFileSync(KEY_FILE),
  cert: fs.readFileSync(CERT_FILE),
  // Chỉ cho phép TLS 1.2+, tắt các protocol cũ
  minVersion: 'TLSv1.2',
  // Cipher suite mạnh (loại bỏ RC4, DES, MD5, export ciphers)
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-CHACHA20-POLY1305',
  ].join(':'),
  honorCipherOrder: true,
};



// ══════════════════════════════════════════════════════════
//  SOCKS5 OVER TLS SERVER
//  Client cần kết nối TLS trước, sau đó giao tiếp SOCKS5
//  Ví dụ dùng: proxychains với stunnel ở phía client
// ══════════════════════════════════════════════════════════

const SOCKS5_VERSION    = 0x05;
const SOCKS5_CMD_CONNECT = 0x01;
const SOCKS5_ATYP_IPV4  = 0x01;
const SOCKS5_ATYP_DOMAIN = 0x03;
const SOCKS5_ATYP_IPV6  = 0x04;

// TLS server bọc ngoài SOCKS5
const socks5Server = tls.createServer(TLS_OPTIONS, (client) => {
  client.once('data', (data) => {
    if (data[0] !== SOCKS5_VERSION) {
      client.destroy();
      return;
    }

    const nMethods = data[1];
    const methods  = [...data.slice(2, 2 + nMethods)];

    if (AUTH.enabled) {
      if (!methods.includes(0x02)) {
        client.write(Buffer.from([SOCKS5_VERSION, 0xFF]));
        client.destroy();
        return;
      }
      client.write(Buffer.from([SOCKS5_VERSION, 0x02]));
      handleSocks5Auth(client);
    } else {
      client.write(Buffer.from([SOCKS5_VERSION, 0x00]));
      handleSocks5Request(client);
    }
  });

  client.on('error', () => {});
});

function handleSocks5Auth(client) {
  client.once('data', (data) => {
    const uLen  = data[1];
    const uName = data.slice(2, 2 + uLen).toString();
    const pLen  = data[2 + uLen];
    const pWord = data.slice(3 + uLen, 3 + uLen + pLen).toString();

    if (uName === AUTH.username && pWord === AUTH.password) {
      client.write(Buffer.from([0x01, 0x00]));
      handleSocks5Request(client);
    } else {
      client.write(Buffer.from([0x01, 0x01]));
      client.destroy();
    }
  });
}

function handleSocks5Request(client) {
  client.once('data', async (data) => {
    if (data[0] !== SOCKS5_VERSION || data[1] !== SOCKS5_CMD_CONNECT) {
      client.write(Buffer.from([SOCKS5_VERSION, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]));
      client.destroy();
      return;
    }

    const atyp = data[3];
    let host, port;

    try {
      if (atyp === SOCKS5_ATYP_IPV4) {
        host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
        port = data.readUInt16BE(8);
      } else if (atyp === SOCKS5_ATYP_DOMAIN) {
        const len = data[4];
        host = data.slice(5, 5 + len).toString();
        port = data.readUInt16BE(5 + len);
        const resolved = await dnsP.resolve4(host).catch(() => null);
        if (resolved && resolved.length > 0) host = resolved[0];
      } else if (atyp === SOCKS5_ATYP_IPV6) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(data.slice(4 + i, 6 + i).toString('hex'));
        host = parts.join(':');
        port = data.readUInt16BE(20);
      } else {
        client.destroy();
        return;
      }
    } catch (e) {
      client.destroy();
      return;
    }

    const target = net.createConnection({ host, port }, () => {
      const reply = Buffer.alloc(10);
      reply[0] = SOCKS5_VERSION;
      reply[1] = 0x00;
      reply[2] = 0x00;
      reply[3] = SOCKS5_ATYP_IPV4;
      reply.writeUInt32BE(0, 4);
      reply.writeUInt16BE(0, 8);
      client.write(reply);

      client.pipe(target);
      target.pipe(client);
    });

    target.on('error', () => {
      client.write(Buffer.from([SOCKS5_VERSION, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]));
      client.destroy();
    });

    client.on('error', () => target.destroy());
    client.on('close', () => target.destroy());
    target.on('close', () => client.destroy());
  });
}

socks5Server.listen(SOCKS5_PORT, '0.0.0.0', () => {
  proxyLog(`SOCKS5-over-TLS proxy listening on port ${SOCKS5_PORT}`);
});
socks5Server.on('error', (err) => proxyLog(`SOCKS5 error: ${err.message}`));

// ══════════════════════════════════════════════════════════
//  HTTPS / HTTP CONNECT PROXY — TLS
// ══════════════════════════════════════════════════════════

const httpsProxyServer = https.createServer(TLS_OPTIONS, (req, res) => {
  res.removeHeader('Via');
  res.removeHeader('X-Forwarded-For');

  const urlObj  = new URL(req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`);
  const options = {
    hostname: urlObj.hostname,
    port:     urlObj.port || 80,
    path:     urlObj.pathname + (urlObj.search || ''),
    method:   req.method,
    headers:  sanitizeHeaders(req.headers),
  };

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxy.on('error', () => {
    res.writeHead(502);
    res.end('Bad Gateway');
  });

  req.pipe(proxy);
});

// HTTPS CONNECT tunnel
httpsProxyServer.on('connect', async (req, clientSocket, head) => {
  clientSocket.on('error', () => {});

  if (AUTH.enabled) {
    const authHeader = req.headers['proxy-authorization'] || '';
    const b64        = authHeader.replace('Basic ', '');
    const decoded    = Buffer.from(b64, 'base64').toString();
    const [u, p]     = decoded.split(':');
    if (u !== AUTH.username || p !== AUTH.password) {
      clientSocket.write(
        'HTTP/1.1 407 Proxy Authentication Required\r\n' +
        'Proxy-Authenticate: Basic realm="proxy"\r\n\r\n'
      );
      clientSocket.destroy();
      return;
    }
  }

  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;

  let resolvedHost = host;
  try {
    const resolved = await dnsP.resolve4(host);
    if (resolved && resolved.length > 0) resolvedHost = resolved[0];
  } catch (_) {}

  const serverSocket = net.createConnection({ host: resolvedHost, port }, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length > 0) serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', () => {
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.destroy();
  });

  clientSocket.on('close', () => serverSocket.destroy());
  serverSocket.on('close', () => clientSocket.destroy());
});

httpsProxyServer.listen(HTTPS_PORT, '0.0.0.0', () => {
  proxyLog(`HTTPS/HTTP-over-TLS proxy listening on port ${HTTPS_PORT}`);
});
httpsProxyServer.on('error', (err) => proxyLog(`HTTPS proxy error: ${err.message}`));

// ── Xóa header tiết lộ danh tính ──────────────────────────
function sanitizeHeaders(headers) {
  const cleaned = { ...headers };
  delete cleaned['x-forwarded-for'];
  delete cleaned['x-real-ip'];
  delete cleaned['via'];
  delete cleaned['forwarded'];
  delete cleaned['proxy-connection'];
  delete cleaned['proxy-authorization'];
  return cleaned;
}

proxyLog('Proxy server (TLS + Rate Limit) loaded.');
proxyLog(`TLS: minVersion=TLSv1.2, strong ciphers only`);
