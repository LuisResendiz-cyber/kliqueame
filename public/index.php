<?php
require_once __DIR__ . '/../src/bootstrap.php';

/* -------------------------------------------------------
   NIVELES DE SEGURIDAD AVANZADOS PARA LA PÁGINA INICIAL
   ------------------------------------------------------- */

// 0. Detener cualquier salida de buffer previa y asegurar que no hay sesión activa
if (session_status() === PHP_SESSION_ACTIVE) {
    // Si hay sesión activa, cerrarla para la página pública
    session_write_close();
}

// Limpiar buffers de salida
while (ob_get_level() > 0) {
    ob_end_clean();
}

// 1. Forzar HTTPS (solo en producción)
$is_production = $_SERVER['SERVER_NAME'] !== 'localhost' && 
                 $_SERVER['SERVER_NAME'] !== '127.0.0.1' &&
                 strpos($_SERVER['SERVER_NAME'], '.local') === false;

if ($is_production && (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off')) {
    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect);
    exit;
}

// 2. Configuración de sesión SEGURA - SOLO si no hay sesión activa
if (session_status() === PHP_SESSION_NONE) {
    // Configuración segura de cookies de sesión
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => $_SERVER['SERVER_NAME'],
        'secure' => $is_production,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    
    // Solo iniciar sesión si es necesario (página pública no necesita sesión)
    // Para página de inicio, NO iniciamos sesión a menos que sea necesario
    // session_start(); // COMENTADO para página pública
}

// 3. Headers de seguridad (ANTES de cualquier salida)
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// 4. HSTS solo en producción con SSL real
if ($is_production) {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
}

// 5. Content Security Policy (CSP) estricta
$nonce = base64_encode(random_bytes(16));
$csp = "default-src 'self'; " .
       "img-src 'self' data: https:; " .
       "script-src 'self' 'nonce-$nonce'; " .
       "style-src 'self' 'nonce-$nonce' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " .
       "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
       "frame-ancestors 'none'; " .
       "form-action 'self'; " .
       "base-uri 'self'; " .
       "object-src 'none';";
header("Content-Security-Policy: " . $csp);

// 6. Cache control para contenido sensible
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// 7. Feature Policy
header("Feature-Policy: geolocation 'none'; microphone 'none'; camera 'none'");

// 8. Expect-CT (Certificate Transparency)
if ($is_production) {
    header("Expect-CT: max-age=86400, enforce");
}

// 9. Validar y sanitizar entradas
$request_uri = filter_var($_SERVER['REQUEST_URI'] ?? '', FILTER_SANITIZE_URL);
$server_name = filter_var($_SERVER['SERVER_NAME'] ?? '', FILTER_SANITIZE_URL);

// 10. Prevenir MIME sniffing adicional
header("X-Download-Options: noopen");

// 11. Protección contra referrer leaks
header("Referrer-Policy: strict-origin-when-cross-origin");

// 12. Timezone
date_default_timezone_set('America/Mexico_City');

// 13. Manejo de errores
error_reporting($is_production ? 0 : E_ALL);
ini_set('display_errors', $is_production ? '0' : '1');
ini_set('log_errors', '1');
$error_log_path = __DIR__ . '/../logs/';
if (!is_dir($error_log_path)) {
    @mkdir($error_log_path, 0755, true);
}
ini_set('error_log', $error_log_path . 'php_errors.log');

// 14. Validación de método HTTP
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'])) {
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: GET, HEAD');
    exit;
}

// 15. Headers adicionales de seguridad
header("X-Permitted-Cross-Domain-Policies: none");
header("X-DNS-Prefetch-Control: off");

// 16. Validar origen de la solicitud
function validateOrigin() {
    if (!isset($_SERVER['HTTP_ORIGIN'])) {
        return;
    }
    
    $allowed_origins = [
        'https://' . ($_SERVER['HTTP_HOST'] ?? ''),
        'http://localhost',
        'http://127.0.0.1'
    ];
    
    $origin = filter_var($_SERVER['HTTP_ORIGIN'], FILTER_SANITIZE_URL);
    if (!in_array($origin, $allowed_origins)) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }
}

validateOrigin();

// Ahora que todos los headers están configurados, podemos empezar la salida HTML
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<link rel="icon" type="image/svg+xml" href="https://desarrollo.impulse-solution.online/qlikmeapp/public/logo-qlikme-recortado.png">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="QlikMe - Tu plataforma para análisis dinámicos y tarjetas inteligentes">
<meta name="author" content="QlikMe">
<meta name="robots" content="index, follow">

<title>QlikMe - Inicio</title>

<!-- Preconnect para recursos externos -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<!-- Fuentes modernas con SRI (Subresource Integrity) -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" 
      rel="stylesheet" 
      crossorigin="anonymous">

<!-- Favicon -->
<link rel="icon" href="/qlikmeapp/favicon.ico" type="image/x-icon">
<link rel="apple-touch-icon" href="/qlikmeapp/apple-touch-icon.png">

<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
  body {
    margin: 0;
    font-family: 'Inter', sans-serif;
    background: #ffffff;
    color: #1a1a1a;
  }

  .container {
    max-width: 1100px;
    margin: auto;
    padding: 40px 20px;
    text-align: center;
  }

  /* Logo - MANTENIENDO TU ESTILO ORIGINAL */
  .hero-graphic {
    margin: 10px auto 5px;
  }

  .hero-graphic img {
    max-width: 360px;
    width: 65%;
    height: auto;
  }

  /* Hero */
  .hero {
    margin-top: -10px;
  }

  .hero-title {
    font-size: 42px;
    font-weight: 700;
    margin-bottom: 8px;
    color: #222;
  }

  .hero-subtitle {
    font-size: 20px;
    font-weight: 300;
    color: #555;
    margin-bottom: 28px;
  }

  /* Botones */
  .btn {
    display: inline-block;
    background: #00A39A;
    color: #fff;
    padding: 14px 30px;
    margin: 8px;
    border-radius: 10px;
    font-size: 18px;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.25s ease;
  }

  .btn:hover {
    background: #008b84;
    transform: translateY(-3px);
  }

  /* ------------------------ */
  /*        RESPONSIVO        */
  /* ------------------------ */

  @media (max-width: 768px) {

    .container {
      padding: 20px 15px;
    }

    .hero-graphic img {
      width: 70%;
      max-width: 240px;
    }

    .hero-title {
      font-size: 30px;
    }

    .hero-subtitle {
      font-size: 16px;
      margin-bottom: 22px;
    }

    .btn {
      width: 90%;
      max-width: 340px;
      font-size: 16px;
      padding: 13px 20px;
      margin: 7px auto;
      display: block;
    }
  }

  @media (max-width: 480px) {

    .container {
      padding: 20px 12px;
    }

    .hero-graphic img {
      width: 85%;
      max-width: 200px;
    }

    .hero-title {
      font-size: 26px;
      margin-bottom: 8px;
    }

    .hero-subtitle {
      font-size: 15px;
      margin-bottom: 18px;
    }

    .btn {
      width: 100%;
      font-size: 15px;
      padding: 12px 16px;
    }
  }
</style>
</head>

<body>

<div class="container">

  <!-- Logo centrado - TU CÓDIGO ORIGINAL -->
  <div class="hero-graphic">
      <img src="logo-qlikme-1.png" alt="QlikMe">
  </div>

  <!-- Hero -->
  <div class="hero">
    <h1 class="hero-title">Bienvenidos</h1>
    <p class="hero-subtitle">Tu plataforma para análisis dinámicos y tarjetas inteligentes.</p>

    <a href="register.php" class="btn">Crear cuenta</a>
    <a href="login.php" class="btn">Iniciar sesión</a>
    <a href="card_example.php" class="btn">Ejemplo de Tarjeta</a>
  </div>

</div>

<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
  // ============================================
  // SEGURIDAD DEL LADO DEL CLIENTE
  // ============================================

  // Sanitizar entrada
  function sanitizeInput(text) {
    if (typeof text !== 'string') return '';
    return text
      .replace(/<[^>]*>/g, '')
      .replace(/[^\p{L}\p{N}\s\-_.,@:;/?&=+#]/gu, '')
      .substring(0, 500);
  }

  // Validar URL
  function isValidUrl(string) {
    if (typeof string !== 'string') return false;
    try {
      const url = new URL(string, window.location.origin);
      const allowedProtocols = ['http:', 'https:'];
      return allowedProtocols.includes(url.protocol);
    } catch (_) {
      return false;
    }
  }

  // Prevenir ataques de timing
  let lastClickTime = 0;
  
  document.addEventListener('DOMContentLoaded', function() {
    // Validar todos los enlaces antes de navegar
    const links = document.querySelectorAll('a');
    links.forEach(link => {
      link.addEventListener('click', function(e) {
        const currentTime = Date.now();
        
        // Prevenir clicks rápidos (timing attacks)
        if (currentTime - lastClickTime < 100) {
          e.preventDefault();
          return false;
        }
        lastClickTime = currentTime;
        
        // Validar URL relativa o absoluta
        const href = this.getAttribute('href');
        if (href && href.startsWith('http')) {
          if (!isValidUrl(href)) {
            console.warn('URL sospechosa bloqueada:', href);
            e.preventDefault();
            return false;
          }
        }
        
        // Añadir clase de loading
        this.classList.add('loading');
        
        // Limpiar después de 1 segundo
        setTimeout(() => {
          this.classList.remove('loading');
        }, 1000);
        
        return true;
      });
    });
    
    // Proteger contra inyección de código
    document.addEventListener('input', function(e) {
      if (e.target.matches('input[type="text"], input[type="email"], input[type="password"], textarea')) {
        const original = e.target.value;
        const sanitized = sanitizeInput(original);
        if (original !== sanitized) {
          e.target.value = sanitized;
        }
      }
    });
    
    // Manejo de errores seguro
    window.onerror = function(msg, url, lineNo, columnNo, error) {
      console.error('Error controlado:', {msg, url, lineNo});
      return true;
    };
    
    // Protección contra ataques de fuerza bruta en botones
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
      let clickCount = 0;
      const originalText = button.innerHTML;
      
      button.addEventListener('click', function() {
        clickCount++;
        
        if (clickCount > 5) {
          this.disabled = true;
          this.innerHTML = 'Bloqueado temporalmente';
          this.style.opacity = '0.6';
          
          setTimeout(() => {
            this.disabled = false;
            this.innerHTML = originalText;
            this.style.opacity = '1';
            clickCount = 0;
          }, 30000);
        }
      });
    });
    
    // Añadir timestamps a solicitudes (CSRF protection)
    if (typeof window.csrfToken === 'undefined') {
      window.csrfToken = Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    }
  });
</script>

<!-- Font Awesome con SRI (opcional, si lo necesitas) -->
<link rel="stylesheet" 
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
      integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
      crossorigin="anonymous" 
      referrerpolicy="no-referrer">
</body>
</html>