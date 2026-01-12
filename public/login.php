<?php
require_once __DIR__ . '/../src/bootstrap.php';

/* -------------------------------------------------------
   NIVELES DE SEGURIDAD AVANZADOS PARA LOGIN
   ------------------------------------------------------- */

// 0. Detener cualquier salida de buffer previa
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

// 2. Headers de seguridad
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// 3. Content Security Policy (CSP) estricta
$nonce = base64_encode(random_bytes(16));
$csp = "default-src 'self'; " .
       "img-src 'self' data: https:; " .
       "script-src 'self' 'nonce-$nonce' https://fonts.googleapis.com; " .
       "style-src 'self' 'nonce-$nonce' https://fonts.googleapis.com; " .
       "font-src 'self' https://fonts.gstatic.com; " .
       "frame-ancestors 'none'; " .
       "form-action 'self'; " .
       "base-uri 'self'; " .
       "object-src 'none';";
header("Content-Security-Policy: " . $csp);

// 4. Cache control para formularios de login
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// 5. Feature Policy
header("Feature-Policy: geolocation 'none'; microphone 'none'; camera 'none'");

// 6. HSTS solo en producción
if ($is_production) {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
}

// 7. Validación de método HTTP
$allowed_methods = ['GET', 'POST'];
if (!in_array($_SERVER['REQUEST_METHOD'], $allowed_methods)) {
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: ' . implode(', ', $allowed_methods));
    exit;
}

// 8. Headers adicionales
header("X-Permitted-Cross-Domain-Policies: none");
header("X-DNS-Prefetch-Control: off");

// 9. Timezone
date_default_timezone_set('America/Mexico_City');

// 10. Manejo de errores (solo log en producción)
error_reporting($is_production ? 0 : E_ALL);
ini_set('display_errors', $is_production ? '0' : '1');
ini_set('log_errors', '1');
$error_log_path = __DIR__ . '/../logs/';
if (!is_dir($error_log_path)) {
    @mkdir($error_log_path, 0755, true);
}
ini_set('error_log', $error_log_path . 'php_errors.log');

// ----------------------------------------------------
// LÓGICA DE LOGIN - SEGURA (manteniendo tu funcionalidad)
// ----------------------------------------------------

if (authUser()) { 
    header('Location: dashboard.php'); 
    exit; 
}

$errors = [];
$form_data = ['email' => ''];
$login_attempts_key = 'login_attempts_' . md5($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$max_attempts = 5;
$lockout_time = 300; // 5 minutos en segundos

// Validar y procesar formulario POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. Verificar bloqueo por intentos fallidos (protección contra fuerza bruta)
    if (isset($_SESSION[$login_attempts_key])) {
        $attempts = $_SESSION[$login_attempts_key];
        
        if ($attempts['count'] >= $max_attempts && 
            (time() - $attempts['last_attempt']) < $lockout_time) {
            
            $remaining_time = $lockout_time - (time() - $attempts['last_attempt']);
            $errors[] = 'Demasiados intentos fallidos. Por favor, espera unos minutos.';
            
            // Log del bloqueo
            error_log("Intento de login bloqueado - IP: " . $_SERVER['REMOTE_ADDR'] . 
                     " - Email: " . ($_POST['email'] ?? ''));
        }
    }
    
    // 2. Validar token CSRF (si existe la función)
    if (empty($errors) && function_exists('verify_csrf_token')) {
        if (!verify_csrf_token($_POST['csrf'] ?? '')) { 
            $errors[] = 'Token de seguridad inválido.'; 
            error_log("CSRF token inválido - IP: " . $_SERVER['REMOTE_ADDR']);
        }
    }
    
    // 3. Sanitizar y validar datos
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Guardar email para rellenar formulario (sin contraseña)
    $form_data['email'] = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
    
    // 4. Validaciones básicas
    if (!$email || !$password) {
        $errors[] = 'Credenciales inválidas.';
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Por favor, introduce un correo electrónico válido.';
    }
    
    if (strlen($password) > 72) { // Límite de password_hash
        $errors[] = 'La contraseña es demasiado larga.';
    }
    
    // 5. Si no hay errores, intentar login
    if (empty($errors)) {
        try {
            // Delay aleatorio para prevenir timing attacks (200-400ms)
            usleep(rand(200000, 400000));
            
            // Buscar usuario
            $stmt = db()->prepare('
                                    SELECT id, password_hash, status
                                    FROM users
                                    WHERE email = ?
                                    LIMIT 1
                                ');
            $stmt->execute([$email]);
            $u = $stmt->fetch();
            // ⛔ Usuario suspendido
            if ($u && $u['status'] === 'suspended') {
            
                // Incrementar intentos (para no revelar estado)
                if (!isset($_SESSION[$login_attempts_key])) {
                    $_SESSION[$login_attempts_key] = [
                        'count' => 1,
                        'last_attempt' => time()
                    ];
                } else {
                    $_SESSION[$login_attempts_key]['count']++;
                    $_SESSION[$login_attempts_key]['last_attempt'] = time();
                }
            
                $errors[] = 'Tu cuenta ha sido suspendida. Contacta al administrador.';
                error_log("LOGIN BLOQUEADO (SUSPENDIDO) - User ID {$u['id']} - IP {$_SERVER['REMOTE_ADDR']}");
            
                // Delay anti timing attack
                usleep(rand(400000, 600000));
            
            } 
            // Verificar usuario y contraseña
            elseif ($u && password_verify($password, $u['password_hash'])) {
                // Login exitoso
                
                // Regenerar ID de sesión para prevenir fixation attacks
                session_regenerate_id(true);
                
                // Limpiar intentos fallidos
                unset($_SESSION[$login_attempts_key]);
                
                // Establecer datos de sesión seguros
                $_SESSION['user_id'] = (int)$u['id'];
                $_SESSION['login_time'] = time();
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? '';
                
                // Configurar cookie de sesión segura
                $cookie_params = session_get_cookie_params();
                setcookie(
                    session_name(),
                    session_id(),
                    [
                        'expires' => 0,
                        'path' => $cookie_params['path'],
                        'domain' => $cookie_params['domain'],
                        'secure' => $is_production,
                        'httponly' => true,
                        'samesite' => 'Strict'
                    ]
                );
                
                // Log exitoso (sin información sensible)
                error_log("Login exitoso - User ID: " . $u['id'] . " - IP: " . $_SERVER['REMOTE_ADDR']);
                
                // Redirigir a dashboard
                header('Location: dashboard.php');
                exit;
                
            } else {
                // Credenciales incorrectas
                
                // Incrementar contador de intentos fallidos
                if (!isset($_SESSION[$login_attempts_key])) {
                    $_SESSION[$login_attempts_key] = [
                        'count' => 1,
                        'last_attempt' => time()
                    ];
                } else {
                    $_SESSION[$login_attempts_key]['count']++;
                    $_SESSION[$login_attempts_key]['last_attempt'] = time();
                }
                
                // Mensaje genérico para no revelar información
                $errors[] = 'Email o contraseña incorrectos.';
                
                // Log del intento fallido
                error_log("Intento de login fallido - IP: " . $_SERVER['REMOTE_ADDR'] . 
                         " - Intentos: " . $_SESSION[$login_attempts_key]['count']);
                
                // Delay adicional para intentos fallidos (400-600ms)
                usleep(rand(400000, 600000));
            }
            
        } catch (Exception $e) {
            // Log del error sin mostrar detalles al usuario
            error_log("Error en login - IP: " . $_SERVER['REMOTE_ADDR'] . 
                     " - Error: " . $e->getMessage());
            
            // Mensaje genérico
            $errors[] = 'Ocurrió un error al procesar tu solicitud.';
        }
    }
}

// Generar token CSRF
$token = '';
if (function_exists('csrf_token')) {
    $token = csrf_token();
}
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="https://desarrollo.impulse-solution.online/qlikmeapp/public/logo-qlikme-recortado.png">
<title>Iniciar sesión - QlikMe</title>

<!-- Preconnect para recursos externos -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<!-- Fuentes con SRI -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" 
      rel="stylesheet" 
      crossorigin="anonymous">

<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
body {
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
    background: #f4f8f9;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}

/* Caja estilo register */
.login-box {
    width: 100%;
    max-width: 420px;
    background: #fff;
    padding: 26px;
    border-radius: 14px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.07);
    border: 1px solid #e6e9f2;
}

h2 {
    font-size: 26px;
    font-weight: 700;
    margin-bottom: 18px;
    color: #222;
}

/* Inputs estilo register */
input {
    width: 100%;
    padding: 12px 14px;
    font-size: 16px;
    border: 1px solid #ccc;
    border-radius: 10px;
    outline: none;
    transition: 0.25s;
    margin-top: 6px;
    box-sizing: border-box;
}

input:focus {
    border-color: #00A39A;
    box-shadow: 0 0 4px rgba(0,163,154,0.3);
}

label {
    display: block;
    margin-bottom: 16px;
    font-weight: 500;
    color: #444;
}

/* Botón estilo register */
button {
    width: 100%;
    background: #00A39A;
    color: #fff;
    padding: 14px;
    border: none;
    font-size: 16px;
    border-radius: 10px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s;
    position: relative;
    overflow: hidden;
}

button::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    transition: 0.5s;
}

button:hover::before {
    left: 100%;
}

button:hover {
    background: #008b84;
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,163,154,0.2);
}

button:active {
    transform: translateY(0);
}

button:disabled {
    background: #cccccc;
    cursor: not-allowed;
    transform: none;
}

button:disabled::before {
    display: none;
}

/* Error box igual al register */
.error-box {
    background: #ffefef;
    border-left: 4px solid #e53935;
    padding: 12px;
    margin-bottom: 20px;
    border-radius: 6px;
    border: 1px solid #ffcdd2;
    animation: fadeIn 0.3s ease;
}

.error-box ul {
    margin: 0;
    padding-left: 20px;
    color: #b71c1c;
    list-style-type: none;
}

.error-box li {
    margin-bottom: 5px;
    font-size: 14px;
}

p a {
    color: #00A39A;
    text-decoration: none;
    font-weight: 600;
    transition: color 0.25s;
}

p a:hover {
    color: #008b84;
    text-decoration: underline;
}

/* Protección contra selección de texto en botones */
button {
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
}
.login-footer-link {
    margin-top: 18px;
    text-align: center;
}
.forgot-link {
    font-size: 14px;
    color: #666;
    font-weight: 500;
}

.forgot-link:hover {
    color: #00A39A;
    text-decoration: underline;
}
/* Animaciones para mensajes */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Bloqueo visual */
.lockout-message {
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 12px;
    margin-bottom: 20px;
    border-radius: 6px;
    color: #856404;
    font-weight: 500;
}

/* Loading state */
.loading {
    opacity: 0.7;
    pointer-events: none;
}

/* Responsive */
@media (max-width: 480px) {
    body {
        padding: 20px;
        height: auto;
        align-items: flex-start;
        padding-top: 40px;
    }
    
    .login-box {
        padding: 22px;
    }
    
    h2 {
        font-size: 24px;
    }
}
</style>
</head>

<body>

<div class="login-box">

    <h2>Iniciar sesión</h2>

    <?php 
    // Mostrar mensaje de bloqueo si aplica
    if (isset($_SESSION[$login_attempts_key]) && 
        $_SESSION[$login_attempts_key]['count'] >= $max_attempts): 
        $remaining = $lockout_time - (time() - $_SESSION[$login_attempts_key]['last_attempt']);
        if ($remaining > 0):
    ?>
        <div class="lockout-message">
            Demasiados intentos. Espera <?= ceil($remaining/60) ?> minutos.
        </div>
    <?php 
        endif;
    endif; 
    ?>

    <?php if (!empty($errors)): ?>
        <div class="error-box">
            <ul>
                <?php foreach($errors as $e): ?>
                    <li><?= htmlspecialchars($e, ENT_QUOTES, 'UTF-8') ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="post" autocomplete="off" id="loginForm">
        <?php if ($token): ?>
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
        <?php endif; ?>

        <label>
            Email
            <input name="email" type="email" 
                   value="<?= $form_data['email'] ?>" 
                   required
                   maxlength="255"
                   autocomplete="email"
                   <?php 
                   // Deshabilitar campo si hay bloqueo activo
                   if (isset($_SESSION[$login_attempts_key]) && 
                       $_SESSION[$login_attempts_key]['count'] >= $max_attempts &&
                       (time() - $_SESSION[$login_attempts_key]['last_attempt']) < $lockout_time) {
                       echo 'disabled';
                   }
                   ?>>
        </label>

        <label>
            Contraseña
            <input name="password" type="password" 
                   required
                   maxlength="72"
                   autocomplete="current-password"
                   <?php 
                   // Deshabilitar campo si hay bloqueo activo
                   if (isset($_SESSION[$login_attempts_key]) && 
                       $_SESSION[$login_attempts_key]['count'] >= $max_attempts &&
                       (time() - $_SESSION[$login_attempts_key]['last_attempt']) < $lockout_time) {
                       echo 'disabled';
                   }
                   ?>>
        </label>

        <button type="submit" id="submitBtn"
                <?php 
                // Deshabilitar botón si hay bloqueo activo
                if (isset($_SESSION[$login_attempts_key]) && 
                    $_SESSION[$login_attempts_key]['count'] >= $max_attempts &&
                    (time() - $_SESSION[$login_attempts_key]['last_attempt']) < $lockout_time) {
                    echo 'disabled';
                }
                ?>>
            Entrar
        </button>
    </form>
    <div class="login-footer-link">
        <a href="forgot_password.php" class="forgot-link">
            ¿Olvidaste tu contraseña?
        </a>
    </div>
    <p class="login-footer-link">
        <a href="register.php">Crear cuenta</a>
    </p>

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

// Validar email
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Prevenir ataques de timing
let lastSubmitTime = 0;
let submitCount = 0;
const maxSubmits = 3;
const resetTime = 60000; // 1 minuto

// Verificar si hay bloqueo del servidor
const isLocked = <?php 
    if (isset($_SESSION[$login_attempts_key]) && 
        $_SESSION[$login_attempts_key]['count'] >= $max_attempts &&
        (time() - $_SESSION[$login_attempts_key]['last_attempt']) < $lockout_time) {
        echo 'true';
    } else {
        echo 'false';
    }
?>;

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    
    // Si está bloqueado, actualizar estado
    if (isLocked) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Bloqueado temporalmente';
    }
    
    // Validar formulario al enviar
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Si está bloqueado, prevenir envío
        if (isLocked) {
            alert('Por favor, espera antes de intentar nuevamente.');
            return false;
        }
        
        const currentTime = Date.now();
        
        // Prevenir envíos rápidos (timing attacks)
        if (currentTime - lastSubmitTime < 1000) {
            alert('Por favor, espera un momento antes de intentar nuevamente.');
            return false;
        }
        lastSubmitTime = currentTime;
        
        // Controlar intentos de fuerza bruta en cliente
        submitCount++;
        if (submitCount > maxSubmits) {
            submitBtn.disabled = true;
            submitBtn.textContent = `Demasiados intentos. Espera ${resetTime/1000} segundos.`;
            
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Entrar';
                submitCount = 0;
            }, resetTime);
            
            return false;
        }
        
        // Validar formulario
        const email = form.querySelector('input[name="email"]').value.trim();
        const password = form.querySelector('input[name="password"]').value;
        
        let errors = [];
        
        if (!isValidEmail(email)) {
            errors.push('Por favor, introduce un correo electrónico válido.');
        }
        
        if (password.length === 0) {
            errors.push('La contraseña es requerida.');
        }
        
        if (password.length > 72) {
            errors.push('La contraseña es demasiado larga.');
        }
        
        if (errors.length > 0) {
            alert(errors.join('\n'));
            return false;
        }
        
        // Sanitizar datos antes de enviar
        const emailInput = form.querySelector('input[name="email"]');
        const originalEmail = emailInput.value;
        const sanitizedEmail = sanitizeInput(originalEmail);
        if (originalEmail !== sanitizedEmail) {
            emailInput.value = sanitizedEmail;
        }
        
        // Mostrar estado de carga
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verificando...';
        form.classList.add('loading');
        
        // Enviar formulario después de validación
        setTimeout(() => {
            form.submit();
        }, 100);
        
        return true;
    });
    
    // Proteger contra inyección de código en inputs
    form.querySelectorAll('input[type="text"], input[type="email"]').forEach(input => {
        input.addEventListener('input', function() {
            const original = this.value;
            const sanitized = sanitizeInput(original);
            if (original !== sanitized) {
                this.value = sanitized;
            }
        });
    });
    
    // Prevenir copia/pega malicioso en contraseña
    const passwordInput = form.querySelector('input[name="password"]');
    passwordInput.addEventListener('paste', function(e) {
        const pastedData = e.clipboardData.getData('text');
        if (pastedData.length > 72) {
            e.preventDefault();
            alert('La contraseña no puede exceder los 72 caracteres.');
        }
    });
    
    // Detectar actividad de bot (movimiento del mouse)
    let mouseMovement = false;
    document.addEventListener('mousemove', function() {
        mouseMovement = true;
    });
    
    form.addEventListener('submit', function() {
        if (!mouseMovement && submitCount > 1) {
            // Podría ser un bot
            console.log('Posible bot detectado');
            // Añadir delay adicional
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verificando...';
            
            setTimeout(() => {
                if (!isLocked) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Entrar';
                }
            }, 2000);
        }
    });
    
    // Manejo de errores seguro
    window.onerror = function(msg, url, lineNo, columnNo, error) {
        console.error('Error controlado:', {msg, url, lineNo});
        return true;
    };
    
    // Auto-enfoque en el primer campo
    if (!isLocked) {
        form.querySelector('input[name="email"]').focus();
    }
});
</script>
</body>
</html>