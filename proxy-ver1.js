/*
 * ============================================================
 *  LUỒNG 2 — PROXY SERVER (độc lập hoàn toàn với bot)
 * ============================================================
 *  Hỗ trợ:
 *    - SOCKS5 proxy  (port SOCKS5_PORT)
 *    - HTTPS/HTTP CONNECT proxy  (port HTTPS_PORT)
 *
 *  Tính năng ẩn danh:
 *    - Không ghi log IP client
 *    - Không thêm header X-Forwarded-For / Via
 *    - DNS resolve qua Cloudflare 1.1.1.1 (chống DNS leak)
 *    - Không có WebRTC leak (proxy thuần TCP, không liên quan WebRTC)
 *    - Bypass chặn nội dung nhà mạng (tunnel thẳng TCP)
 *
 *  SỬA PORT TẠI ĐÂY:
 * ============================================================
 */

const net    = require('net');
const http   = require('http');
const dns    = require('dns');
const dnsP   = dns.promises;

// ── Dùng Cloudflare DNS 1.1.1.1 (chống DNS leak) ──────────
dns.setServers(['1.1.1.1', '1.0.0.1']);

// ── Cấu hình port ─────────────────────────────────────────
const SOCKS5_PORT = 30029;   // ← đổi port SOCKS5 tại đây
const HTTPS_PORT  = 30013;   // ← đổi port HTTPS tại đây

// ── Auth (để trống = không cần mật khẩu) ──────────────────
const AUTH = {
  enabled:  false,
  username: '',
  password: '',
};
// ──────────────────────────────────────────────────────────

function proxyLog(msg) {
  const ts = new Date().toLocaleTimeString();
  console.log(`[${ts}] [PROXY] ${msg}`);
}

// ══════════════════════════════════════════════════════════
//  SOCKS5 SERVER
//  RFC 1928 — https://datatracker.ietf.org/doc/html/rfc1928
// ══════════════════════════════════════════════════════════

const SOCKS5_VERSION = 0x05;
const SOCKS5_CMD_CONNECT = 0x01;
const SOCKS5_ATYP_IPV4   = 0x01;
const SOCKS5_ATYP_DOMAIN = 0x03;
const SOCKS5_ATYP_IPV6   = 0x04;

const socks5Server = net.createServer((client) => {
  client.once('data', (data) => {
    // ── Bước 1: Handshake ─────────────────────────────────
    if (data[0] !== SOCKS5_VERSION) {
      client.destroy();
      return;
    }

    const nMethods = data[1];
    const methods  = [...data.slice(2, 2 + nMethods)];

    if (AUTH.enabled) {
      // Yêu cầu username/password auth (method 0x02)
      if (!methods.includes(0x02)) {
        client.write(Buffer.from([SOCKS5_VERSION, 0xFF])); // no acceptable method
        client.destroy();
        return;
      }
      client.write(Buffer.from([SOCKS5_VERSION, 0x02]));
      handleSocks5Auth(client);
    } else {
      // No auth (method 0x00)
      client.write(Buffer.from([SOCKS5_VERSION, 0x00]));
      handleSocks5Request(client);
    }
  });

  client.on('error', () => {});
});

function handleSocks5Auth(client) {
  client.once('data', (data) => {
    // Sub-negotiation: VER(1) ULEN(1) UNAME PLEN(1) PASSWD
    const uLen  = data[1];
    const uName = data.slice(2, 2 + uLen).toString();
    const pLen  = data[2 + uLen];
    const pWord = data.slice(3 + uLen, 3 + uLen + pLen).toString();

    if (uName === AUTH.username && pWord === AUTH.password) {
      client.write(Buffer.from([0x01, 0x00])); // success
      handleSocks5Request(client);
    } else {
      client.write(Buffer.from([0x01, 0x01])); // failure
      client.destroy();
    }
  });
}

function handleSocks5Request(client) {
  client.once('data', async (data) => {
    // ── Bước 2: Request ───────────────────────────────────
    // VER CMD RSV ATYP DST.ADDR DST.PORT
    if (data[0] !== SOCKS5_VERSION || data[1] !== SOCKS5_CMD_CONNECT) {
      // Chỉ hỗ trợ CONNECT
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
        // DNS resolve qua 1.1.1.1 → chống DNS leak
        const resolved = await dnsP.resolve4(host).catch(() => null);
        if (resolved && resolved.length > 0) host = resolved[0];
      } else if (atyp === SOCKS5_ATYP_IPV6) {
        // IPv6: 16 bytes
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

    // ── Bước 3: Kết nối tới target ───────────────────────
    const target = net.createConnection({ host, port }, () => {
      // Reply success
      const reply = Buffer.alloc(10);
      reply[0] = SOCKS5_VERSION;
      reply[1] = 0x00; // success
      reply[2] = 0x00; // reserved
      reply[3] = SOCKS5_ATYP_IPV4;
      // BND.ADDR = 0.0.0.0, BND.PORT = 0
      reply.writeUInt32BE(0, 4);
      reply.writeUInt16BE(0, 8);
      client.write(reply);

      // Tunnel 2 chiều
      client.pipe(target);
      target.pipe(client);
    });

    target.on('error', () => {
      const reply = Buffer.from([SOCKS5_VERSION, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]);
      client.write(reply);
      client.destroy();
    });

    client.on('error', () => target.destroy());
    client.on('close', () => target.destroy());
    target.on('close', () => client.destroy());
  });
}

socks5Server.listen(SOCKS5_PORT, '0.0.0.0', () => {
  proxyLog(`SOCKS5 proxy listening on port ${SOCKS5_PORT}`);
});

socks5Server.on('error', (err) => {
  proxyLog(`SOCKS5 server error: ${err.message}`);
});

// ══════════════════════════════════════════════════════════
//  HTTPS / HTTP CONNECT PROXY SERVER
// ══════════════════════════════════════════════════════════

const httpsProxyServer = http.createServer((req, res) => {
  // Chặn header tiết lộ proxy
  res.removeHeader('Via');
  res.removeHeader('X-Forwarded-For');

  // HTTP thường (không phải CONNECT) — forward thẳng
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

  // Auth check nếu bật
  if (AUTH.enabled) {
    const authHeader = req.headers['proxy-authorization'] || '';
    const b64 = authHeader.replace('Basic ', '');
    const decoded = Buffer.from(b64, 'base64').toString();
    const [u, p]  = decoded.split(':');
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

  // DNS resolve qua 1.1.1.1 → chống DNS leak
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
  proxyLog(`HTTPS/HTTP proxy listening on port ${HTTPS_PORT}`);
});

httpsProxyServer.on('error', (err) => {
  proxyLog(`HTTPS proxy server error: ${err.message}`);
});

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

proxyLog('Proxy server module loaded.');
