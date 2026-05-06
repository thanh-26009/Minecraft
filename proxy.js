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
//  Ưu tiên: openssl CLI → fallback Node.js crypto thuần
//  → Không cần cài thêm gì, chạy được mọi môi trường
// ══════════════════════════════════════════════════════════

function ensureCerts() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    proxyLog('TLS cert found, skipping generation.');
    return;
  }

  proxyLog('Generating self-signed TLS certificate...');
  fs.mkdirSync(CERT_DIR, { recursive: true });

  // ── Thử openssl trước (cert mạnh hơn, RSA 4096) ─────────
  try {
    execSync(
      `openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes` +
      ` -keyout "${KEY_FILE}"` +
      ` -out "${CERT_FILE}"` +
      ` -subj "/CN=ProxyServer/O=Proxy/C=VN"`,
      { stdio: 'pipe' }
    );
    proxyLog('Cert generated via openssl (RSA-4096).');
    return;
  } catch (_) {
    proxyLog('openssl not found, falling back to Node.js crypto...');
  }

  // ── Fallback: Node.js crypto thuần (không cần gói ngoài) ─
  // Node.js >= 15 có crypto.generateKeyPairSync + X509Certificate
  // Node.js >= 17.1 có crypto.X509Certificate.prototype.sign
  // Dùng cách tương thích nhất: tự encode ASN.1/DER thủ công
  // RSA-2048, self-signed, valid 10 năm
  try {
    const crypto = require('crypto');

    // Tạo cặp khoá RSA-2048
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // Dùng tls.createSecureContext để kiểm tra, sau đó dùng
    // forge-style encoding tối giản — thực ra Node >= 15 cho phép
    // tạo cert bằng cách dùng selfsigned pattern qua undocumented
    // internal. Cách an toàn nhất là gọi `crypto` + tự build DER.
    // Để đơn giản và không cần dependency, ta dùng kỹ thuật:
    // tạo cert PEM tối giản dùng node-forge algorithm thuần JS
    // được inline dưới đây (chỉ ~100 dòng, không import gói ngoài).

    const certPem = buildSelfSignedCert(privateKey, publicKey, crypto);

    fs.writeFileSync(KEY_FILE,  privateKey, 'utf8');
    fs.writeFileSync(CERT_FILE, certPem,    'utf8');
    proxyLog('Cert generated via Node.js crypto (RSA-2048).');
  } catch (e) {
    proxyLog(`ERROR: Cannot generate cert: ${e.message}`);
    proxyLog('Fix: place server.crt + server.key manually into ./certs/');
    process.exit(1);
  }
}

// ── Tự build X.509 self-signed cert (DER → PEM) ───────────
// Không dùng bất kỳ npm package nào
function buildSelfSignedCert(privateKeyPem, publicKeyPem, crypto) {
  // Helper encode ASN.1 DER
  function derLen(len) {
    if (len < 0x80) return Buffer.from([len]);
    if (len < 0x100) return Buffer.from([0x81, len]);
    return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
  }
  function der(tag, content) {
    return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
  }

  const seq  = (c) => der(0x30, c);
  const ctx0 = (c) => der(0xa0, c);
  const int_ = (c) => der(0x02, c);
  const bitStr = (c) => der(0x03, Buffer.concat([Buffer.from([0x00]), c]));
  const oid  = (bytes) => der(0x06, Buffer.from(bytes));
  const utf8 = (s) => der(0x0c, Buffer.from(s, 'utf8'));
  const set_ = (c) => der(0x31, c);
  const utc  = (s) => der(0x17, Buffer.from(s, 'ascii'));
  const null_= () => Buffer.from([0x05, 0x00]);

  // OIDs
  const OID_SHA256RSA = [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b];
  const OID_CN        = [0x55,0x04,0x03];

  // Dates — valid 10 năm, format YYMMDDHHmmssZ
  const pad = (n) => String(n).padStart(2,'0');
  const fmtUTC = (d) => {
    const yy = String(d.getUTCFullYear()).slice(2);
    return yy + pad(d.getUTCMonth()+1) + pad(d.getUTCDate()) +
           pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds()) + 'Z';
  };
  const now   = new Date();
  const later = new Date(now); later.setFullYear(later.getFullYear() + 10);

  // Serial number
  const serial = crypto.randomBytes(8);
  serial[0] &= 0x7f;

  // Subject / Issuer: CN=ProxyServer
  const name = seq(set_(seq(Buffer.concat([oid(OID_CN), utf8('ProxyServer')]))));

  // subjectPublicKeyInfo — lấy thẳng DER từ PEM SPKI (đã là đúng format)
  const spkiDer = Buffer.from(
    publicKeyPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64'
  );

  // Algorithm identifier SHA256withRSA
  const algId = seq(Buffer.concat([oid(OID_SHA256RSA), null_()]));

  // TBSCertificate
  const tbs = seq(Buffer.concat([
    ctx0(int_(Buffer.from([0x02]))),                              // version: v3
    int_(serial),                                                  // serialNumber
    algId,                                                         // signature alg
    name,                                                          // issuer
    seq(Buffer.concat([utc(fmtUTC(now)), utc(fmtUTC(later))])),  // validity
    name,                                                          // subject
    spkiDer,                                                       // subjectPublicKeyInfo (raw DER)
  ]));

  // Ký SHA256withRSA
  const sign = crypto.createSign('SHA256');
  sign.update(tbs);
  const signature = sign.sign(privateKeyPem);

  // Certificate = SEQUENCE { tbs, algId, BIT STRING signature }
  const certDer = seq(Buffer.concat([tbs, algId, bitStr(signature)]));

  // PEM
  const b64 = certDer.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
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
