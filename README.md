# Proxy Reverso de Alta Seguridad para Render.com

## Características de Seguridad

### 1. **Ocultación de Origen**
- Elimina todos los headers que revelan información del servidor real
- Reescribe URLs en el contenido HTML
- Elimina referencias al dominio original

### 2. **Headers Personalizados**
- `user_domain`: Dominio de Render desde donde se accede
- `user_ip`: IP real del usuario que accede

### 3. **Restricción de Rutas**
Solo permite acceso a:
- `/3co`
- `/3co/tarjetavirtual`
- Recursos estáticos necesarios (`/css`, `/js`, `/assets`)

### 4. **Anti-Inspección**
- Deshabilita click derecho
- Bloquea teclas de desarrollo (F12, Ctrl+Shift+I, etc.)
- Detecta y bloquea DevTools
- Ofusca la consola del navegador

### 5. **Headers de Seguridad**
- Helmet.js para protección adicional
- Headers CSP y XSS Protection
- No-cache para evitar almacenamiento local

## Despliegue en Render.com

### Paso 1: Preparar el Repositorio
```bash
git init
git add .
git commit -m "Initial proxy setup"
git remote add origin [tu-repositorio-github]
git push -u origin main
```

### Paso 2: Configurar en Render
1. Ve a [render.com](https://render.com) y crea una cuenta
2. Conecta tu cuenta de GitHub
3. Crea un nuevo "Web Service"
4. Selecciona tu repositorio
5. Configura:
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free

### Paso 3: Variables de Entorno
En la configuración de Render, agrega:
- `TARGET_URL`: La URL real de tu aplicación Laravel
- `NODE_ENV`: production

### Paso 4: Deploy
1. Render desplegará automáticamente
2. Obtendrás una URL tipo: `https://tu-app.onrender.com`
3. Las rutas accesibles serán:
   - `https://tu-app.onrender.com/3co`
   - `https://tu-app.onrender.com/3co/tarjetavirtual`

## Configuración del Servidor Laravel

Asegúrate de que tu aplicación Laravel pueda recibir y procesar los headers:

```php
// En un middleware o controlador
$userDomain = request()->header('user_domain');
$userIp = request()->header('user_ip');

// Loguear o procesar según necesites
Log::info('Access from proxy', [
    'domain' => $userDomain,
    'ip' => $userIp,
    'path' => request()->path()
]);
```

## Seguridad Adicional

### En Laravel (opcional)
```php
// middleware/ProxyAuth.php
public function handle($request, Closure $next)
{
    $allowedDomains = ['*.onrender.com'];
    $domain = $request->header('user_domain');
    
    if (!$domain || !$this->isDomainAllowed($domain, $allowedDomains)) {
        abort(403);
    }
    
    return $next($request);
}
```

## Monitoreo

El proxy incluye logs básicos. Para ver los logs en Render:
1. Ve al dashboard de tu servicio
2. Click en "Logs"
3. Monitorea accesos y errores

## Notas de Seguridad

- **IMPORTANTE**: Cambia `TARGET_URL` por la URL real de tu servidor
- Los métodos anti-inspección no son 100% infalibles contra usuarios avanzados
- Considera implementar autenticación adicional si manejas datos sensibles
- Monitorea regularmente los logs para detectar actividad sospechosa
- El plan gratuito de Render tiene limitaciones de tráfico

## Testing Local

```bash
# Instalar dependencias
npm install

# Crear archivo .env
cp .env.example .env
# Editar .env con tu TARGET_URL

# Ejecutar en desarrollo
npm run dev

# Probar en http://localhost:3000/3co
```