<?php
require_once __DIR__ . '/../src/bootstrap.php';

/* -------------------------------------------------------
   NIVELES DE SEGURIDAD AVANZADOS PARA REGISTRO
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
       "script-src 'self' 'nonce-$nonce'; " .
       "style-src 'self' 'nonce-$nonce' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " .
       "style-src-attr 'unsafe-inline'; " .
       "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
       "frame-ancestors 'none'; " .
       "form-action 'self'; " .
       "base-uri 'self'; " .
       "object-src 'none';";
header("Content-Security-Policy: " . $csp);

// 4. Cache control para formularios
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

// 10. Manejo de errores
error_reporting($is_production ? 0 : E_ALL);
ini_set('display_errors', $is_production ? '0' : '1');
ini_set('log_errors', '1');
$error_log_path = __DIR__ . '/../logs/';
if (!is_dir($error_log_path)) {
    @mkdir($error_log_path, 0755, true);
}
ini_set('error_log', $error_log_path . 'php_errors.log');

// ----------------------------------------------------
// LÓGICA DEL REGISTRO - SEGURA
// ----------------------------------------------------

// Verificar si el usuario ya está autenticado
if (authUser()) { 
    header('Location: dashboard.php'); 
    exit; 
}

$errors = [];
$success_message = '';
$form_data = [
    'name' => '',
    'email' => ''
];

// Validar y procesar formulario POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. Validar token CSRF
    if (!verify_csrf_token($_POST['csrf'] ?? '')) { 
        $errors[] = 'Token de seguridad inválido. Por favor, recarga la página.'; 
        error_log("CSRF token inválido en registro - IP: " . $_SERVER['REMOTE_ADDR']);
    }
    
    // 2. Sanitizar y validar datos
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Guardar datos para rellenar formulario (sin contraseña)
    $form_data['name'] = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    $form_data['email'] = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
    
    // 3. Validaciones específicas
    
    // Nombre: solo letras, números y espacios básicos
    if (empty($name)) {
        $errors[] = 'El nombre es requerido.';
    } elseif (strlen($name) < 2 || strlen($name) > 100) {
        $errors[] = 'El nombre debe tener entre 2 y 100 caracteres.';
    } elseif (!preg_match('/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9\s\-\'\.]+$/u', $name)) {
        $errors[] = 'El nombre contiene caracteres no válidos.';
    }
    
    // Email: validación estricta
    if (empty($email)) {
        $errors[] = 'El correo electrónico es requerido.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Por favor, introduce un correo electrónico válido.';
    } elseif (strlen($email) > 255) {
        $errors[] = 'El correo electrónico es demasiado largo.';
    }
    
    // Contraseña: validaciones de seguridad
    if (empty($password)) {
        $errors[] = 'La contraseña es requerida.';
    } elseif (strlen($password) < 8) {
        $errors[] = 'La contraseña debe tener al menos 8 caracteres.';
    } elseif (strlen($password) > 72) { // Límite de password_hash
        $errors[] = 'La contraseña es demasiado larga (máximo 72 caracteres).';
    } elseif (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos una letra mayúscula.';
    } elseif (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos una letra minúscula.';
    } elseif (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos un número.';
    } elseif (!preg_match('/[!@#$%^&*()\-_=+{}\[\]:;,.<>?]/', $password)) {
        $errors[] = 'La contraseña debe contener al menos un carácter especial (!@#$%^&*()-_=+{}[]:;,.<>?).';
    }
    
    // 4. Si no hay errores, procesar registro
    if (empty($errors)) {
        try {
            // Verificar si el email ya existe
            $stmt = db()->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
            $stmt->execute([$email]);
            
            if ($stmt->fetch()) {
                // No revelar que el email existe (protección contra enumeración)
                // Simular procesamiento para ocultar timing attacks
                usleep(rand(100000, 300000)); // Delay aleatorio
                
                // Mensaje genérico
                $success_message = 'Si el correo no está registrado, recibirás un mensaje de confirmación.';
                
                // Log del intento
                error_log("Intento de registro con email existente: $email - IP: " . $_SERVER['REMOTE_ADDR']);
            } else {
                // Crear hash seguro de contraseña
                $hash = password_hash($password, PASSWORD_DEFAULT);
                
                // Preparar consulta con parámetros nombrados para mayor claridad
                $stmt = db()->prepare(
                    'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, NOW())'
                );
                
                // Ejecutar con parámetros
                $stmt->execute([$name, $email, $hash]);
                
                // Obtener ID del nuevo usuario
                $user_id = db()->lastInsertId();
                
                // Log exitoso
                error_log("Usuario registrado exitosamente - ID: $user_id - Email: $email");
                
                // Redirigir a login con mensaje genérico
                header('Location: login.php?registered=1');
                exit;
            }
            
        } catch (Exception $e) {
            // Log del error sin mostrar detalles al usuario
            error_log("Error en registro: " . $e->getMessage() . " - IP: " . $_SERVER['REMOTE_ADDR']);
            $errors[] = 'Ocurrió un error al procesar tu registro. Por favor, intenta nuevamente.';
        }
    }
}

// Generar nuevo token CSRF
$token = csrf_token();
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="https://desarrollo.impulse-solution.online/qlikmeapp/public/logo-qlikme-recortado.png">
<title>Registro - QlikMe</title>

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
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}

/* FULL MOBILE – Tipo app */
.mobile-full-wrapper {
    width: 100%;
    max-width: 600px;
    margin: auto;
    padding: 20px;
}

.mobile-title {
    font-size: 28px;
    font-weight: 700;
    text-align: left;
    margin-bottom: 20px;
    color: #222;
}

.mobile-box {
    width: 100%;
    background: #fff;
    padding: 22px;
    border-radius: 14px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.07);
    border: 1px solid #e6e9f2;
}

label {
    display: block;
    margin-bottom: 18px;
    font-weight: 500;
    color: #444;
}

input {
    width: 100%;
    padding: 12px 14px;
    font-size: 16px;
    border: 1px solid #ccc;
    border-radius: 10px;
    outline: none;
    transition: 0.25s;
    box-sizing: border-box;
    margin-top: 6px;
}

input:focus {
    border-color: #00A39A;
    box-shadow: 0 0 4px rgba(0,163,154,0.3);
}

input[type="password"] {
    font-family: monospace;
    letter-spacing: 1px;
}

button {
    width: 100%;
    background: #00A39A;
    color: #fff;
    padding: 14px;
    border: none;
    font-size: 16px;
    border-radius: 10px;
    margin-top: 10px;
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

.error-box {
    background: #ffefef;
    border-left: 4px solid #e53935;
    padding: 12px;
    margin-bottom: 20px;
    border-radius: 6px;
    border: 1px solid #ffcdd2;
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

.success-box {
    background: #e8f5e9;
    border-left: 4px solid #4caf50;
    padding: 12px;
    margin-bottom: 20px;
    border-radius: 6px;
    border: 1px solid #c8e6c9;
    color: #2e7d32;
    font-weight: 500;
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

.password-strength {
    margin-top: 4px;
    font-size: 12px;
    color: #666;
}

.password-requirements {
    font-size: 12px;
    color: #666;
    margin-top: 8px;
    padding-left: 15px;
}

.password-requirements li {
    margin-bottom: 3px;
}

.requirement-met {
    color: #4caf50;
}

.requirement-not-met {
    color: #e53935;
}

.loading {
    opacity: 0.7;
    pointer-events: none;
}

/* Responsive */
@media (max-width: 480px) {
    .mobile-full-wrapper {
        padding: 15px;
    }
    .mobile-box {
        padding: 18px;
    }
    .mobile-title {
        font-size: 24px;
    }
    body {
        padding: 10px;
    }
}

/* Protección contra selección de texto en botones */
button {
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
}

/* Animaciones para mensajes */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
}

.error-box, .success-box {
    animation: fadeIn 0.3s ease;
}

/* Icono para mostrar/ocultar contraseña */
.password-wrapper {
    position: relative;
}

.toggle-password {
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
    font-size: 18px;
    color: #666;
    background: none;
    border: none;
    padding: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.toggle-password:hover {
    color: #00A39A;
}
</style>
</head>

<body>

<div class="mobile-full-wrapper">

    <h2 class="mobile-title">Crear cuenta</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-box">
            <ul>
                <?php foreach($errors as $e): ?>
                    <li><?= htmlspecialchars($e, ENT_QUOTES, 'UTF-8') ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
    
    <?php if (!empty($success_message)): ?>
        <div class="success-box">
            <?= htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>

    <div class="mobile-box">

        <form method="post" autocomplete="off" id="registerForm">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">

            <label>
                Nombre completo
                <input name="name" type="text" 
                       value="<?= $form_data['name'] ?>" 
                       required 
                       maxlength="100"
                       pattern="[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9\s\-'.]+"
                       title="Solo letras, números, espacios, guiones, apóstrofes y puntos">
            </label>

            <label>
                Correo electrónico
                <input name="email" type="email" 
                       value="<?= $form_data['email'] ?>" 
                       required
                       maxlength="255"
                       autocomplete="email">
            </label>

            <label class="password-wrapper">
                Contraseña
                <input name="password" type="password" 
                       required
                       minlength="8"
                       maxlength="72"
                       autocomplete="new-password"
                       id="passwordInput"
                       title="Mínimo 8 caracteres, 1 mayúscula, 1 minúscula, 1 número y 1 carácter especial (!@#$%^&*()-_=+{}[]:;,.<>?)">
                <button type="button" class="toggle-password" id="togglePassword" aria-label="Mostrar/ocultar contraseña">👁️</button>
                <div class="password-strength" id="passwordStrength"></div>
                <ul class="password-requirements" id="passwordRequirements">
                    <li class="requirement-not-met" id="reqLength">Mínimo 8 caracteres</li>
                    <li class="requirement-not-met" id="reqUpper">Al menos una mayúscula</li>
                    <li class="requirement-not-met" id="reqLower">Al menos una minúscula</li>
                    <li class="requirement-not-met" id="reqNumber">Al menos un número</li>
                    <li class="requirement-not-met" id="reqSpecial">Al menos un carácter especial (!@#$%^&*()-_=+{}[]:;,.<>?)</li>
                </ul>
            </label>

            <button type="submit" id="submitBtn">Registrarme</button>
        </form>

        <p style="margin-top:18px; text-align:center;">
            <a href="login.php">Ya tengo una cuenta</a>
        </p>

    </div>

</div>

<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
// ============================================
// SEGURIDAD DEL LADO DEL CLIENTE
// ============================================

// Definir caracteres especiales permitidos (DEBE COINCIDIR CON PHP)
const ALLOWED_SPECIAL_CHARS = '!@#$%^&*()-_=+{}[]:;,.<>?';
// Regex para validar caracteres especiales (escapado correcto)
const SPECIAL_CHARS_REGEX = /[!@#$%^&*()\-_=+{}\[\]:;,.<>?]/;

// Sanitizar entrada
function sanitizeInput(text) {
    if (typeof text !== 'string') return '';
    return text
        .replace(/<[^>]*>/g, '')
        .replace(/[^a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s\-_.,@:;/?&=+#]/g, '')
        .substring(0, 500);
}

// Validar email
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Validar fortaleza de contraseña
function checkPasswordStrength(password) {
    const requirements = {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: SPECIAL_CHARS_REGEX.test(password)
    };
    
    let strength = 0;
    Object.values(requirements).forEach(req => {
        if (req) strength++;
    });
    
    return { requirements, strength };
}

// Mostrar fortaleza de contraseña
function updatePasswordStrength() {
    const password = document.getElementById('passwordInput').value;
    const { requirements, strength } = checkPasswordStrength(password);
    
    const strengthText = document.getElementById('passwordStrength');
    const strengthColors = ['#e53935', '#ff9800', '#ffc107', '#8bc34a', '#4caf50'];
    const strengthMessages = ['Muy débil', 'Débil', 'Regular', 'Fuerte', 'Muy fuerte'];
    
    if (password.length === 0) {
        strengthText.textContent = '';
        // Resetear todos los requisitos
        document.getElementById('reqLength').className = 'requirement-not-met';
        document.getElementById('reqUpper').className = 'requirement-not-met';
        document.getElementById('reqLower').className = 'requirement-not-met';
        document.getElementById('reqNumber').className = 'requirement-not-met';
        document.getElementById('reqSpecial').className = 'requirement-not-met';
        return;
    }
    
    strengthText.textContent = `Fortaleza: ${strengthMessages[strength]}`;
    strengthText.style.color = strengthColors[strength];
    
    // Actualizar indicadores de requisitos
    document.getElementById('reqLength').className = requirements.length ? 'requirement-met' : 'requirement-not-met';
    document.getElementById('reqUpper').className = requirements.upper ? 'requirement-met' : 'requirement-not-met';
    document.getElementById('reqLower').className = requirements.lower ? 'requirement-met' : 'requirement-not-met';
    document.getElementById('reqNumber').className = requirements.number ? 'requirement-met' : 'requirement-not-met';
    document.getElementById('reqSpecial').className = requirements.special ? 'requirement-met' : 'requirement-not-met';
    
    // Actualizar tooltip
    const specialElement = document.getElementById('reqSpecial');
    if (specialElement) {
        specialElement.title = `Caracteres especiales permitidos: ${ALLOWED_SPECIAL_CHARS}`;
    }
}

// Permitir caracteres especiales en el input de contraseña
function allowSpecialCharsInPassword(e) {
    // Permitir todas las teclas de control
    const allowedKeys = [
        'Backspace', 'Tab', 'Enter', 'Shift', 'Control', 'Alt', 
        'Escape', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown',
        'Home', 'End', 'Insert', 'Delete', 'PageUp', 'PageDown'
    ];
    
    // Si es una tecla de control permitida, dejarla pasar
    if (allowedKeys.includes(e.key)) {
        return true;
    }
    
    // Permitir combinaciones de teclas (Ctrl+C, Ctrl+V, etc.)
    if (e.ctrlKey || e.metaKey) {
        return true;
    }
    
    // Permitir caracteres alfanuméricos
    if (/^[a-zA-Z0-9]$/.test(e.key)) {
        return true;
    }
    
    // Permitir caracteres especiales definidos
    if (ALLOWED_SPECIAL_CHARS.includes(e.key)) {
        return true;
    }
    
    // Permitir espacio
    if (e.key === ' ') {
        return true;
    }
    
    // Para cualquier otra tecla, prevenir
    e.preventDefault();
    return false;
}

// Validar formulario antes de enviar
function validateForm() {
    const nameInput = document.querySelector('input[name="name"]');
    const emailInput = document.querySelector('input[name="email"]');
    const passwordInput = document.getElementById('passwordInput');
    
    const name = nameInput ? nameInput.value.trim() : '';
    const email = emailInput ? emailInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value : '';
    
    let errors = [];
    
    // Validar nombre
    if (name.length < 2 || name.length > 100) {
        errors.push('El nombre debe tener entre 2 y 100 caracteres.');
    }
    
    // Validar caracteres del nombre
    const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9\s\-\'\.]+$/;
    if (name && !nameRegex.test(name)) {
        errors.push('El nombre contiene caracteres no válidos. Solo se permiten letras, números, espacios, guiones, apóstrofes y puntos.');
    }
    
    // Validar email
    if (!isValidEmail(email)) {
        errors.push('Por favor, introduce un correo electrónico válido.');
    }
    
    if (email.length > 255) {
        errors.push('El correo electrónico es demasiado largo.');
    }
    
    // Validar contraseña
    const { requirements } = checkPasswordStrength(password);
    
    if (!requirements.length) {
        errors.push('La contraseña debe tener al menos 8 caracteres.');
    }
    if (!requirements.upper) {
        errors.push('La contraseña debe contener al menos una letra mayúscula.');
    }
    if (!requirements.lower) {
        errors.push('La contraseña debe contener al menos una letra minúscula.');
    }
    if (!requirements.number) {
        errors.push('La contraseña debe contener al menos un número.');
    }
    if (!requirements.special) {
        errors.push(`La contraseña debe contener al menos un carácter especial. Permitidos: ${ALLOWED_SPECIAL_CHARS}`);
    }
    
    return errors;
}

// Prevenir ataques de timing
let lastSubmitTime = 0;
let submitCount = 0;
const maxSubmits = 5;
const resetTime = 30000; // 30 segundos

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('registerForm');
    const submitBtn = document.getElementById('submitBtn');
    const passwordInput = document.getElementById('passwordInput');
    const togglePasswordBtn = document.getElementById('togglePassword');
    
    if (!form || !submitBtn || !passwordInput) {
        console.error('Elementos del formulario no encontrados');
        return;
    }
    
    // Configurar toggle de contraseña
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
        });
    }
    
    // Permitir caracteres especiales mientras se escribe
    passwordInput.addEventListener('keydown', allowSpecialCharsInPassword);
    
    // Actualizar fortaleza de contraseña en tiempo real
    passwordInput.addEventListener('input', updatePasswordStrength);
    
    // Validar formulario al enviar
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const currentTime = Date.now();
        
        // Prevenir envíos rápidos (timing attacks)
        if (currentTime - lastSubmitTime < 1000) {
            alert('Por favor, espera un momento antes de intentar nuevamente.');
            return false;
        }
        lastSubmitTime = currentTime;
        
        // Controlar intentos de fuerza bruta
        submitCount++;
        if (submitCount > maxSubmits) {
            submitBtn.disabled = true;
            submitBtn.textContent = `Demasiados intentos. Espera ${resetTime/1000} segundos.`;
            
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Registrarme';
                submitCount = 0;
            }, resetTime);
            
            return false;
        }
        
        // Validar formulario
        const errors = validateForm();
        if (errors.length > 0) {
            alert(errors.join('\n'));
            return false;
        }
        
        // Sanitizar datos antes de enviar
        const inputs = this.querySelectorAll('input[type="text"], input[type="email"]');
        inputs.forEach(input => {
            const original = input.value;
            const sanitized = sanitizeInput(original);
            if (original !== sanitized) {
                input.value = sanitized;
            }
        });
        
        // Mostrar estado de carga
        submitBtn.disabled = true;
        submitBtn.textContent = 'Procesando...';
        this.classList.add('loading');
        
        // Enviar formulario después de validación
        setTimeout(() => {
            this.submit();
        }, 100);
        
        return true;
    });
    
    // Proteger contra inyección de código en inputs
    form.querySelectorAll('input:not([name="password"])').forEach(input => {
        input.addEventListener('input', function() {
            const original = this.value;
            const sanitized = sanitizeInput(original);
            if (original !== sanitized) {
                this.value = sanitized;
            }
        });
    });
    
    // Prevenir copiar/pegar de contraseñas muy largas
    passwordInput.addEventListener('paste', function(e) {
        const pastedData = e.clipboardData.getData('text');
        if (pastedData.length > 72) {
            e.preventDefault();
            alert('La contraseña no puede exceder los 72 caracteres.');
            return;
        }
        
        // También verificar caracteres permitidos
        const invalidChars = pastedData.match(new RegExp(`[^a-zA-Z0-9${ALLOWED_SPECIAL_CHARS.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')}\\s]`, 'g'));
        if (invalidChars && invalidChars.length > 0) {
            console.warn('Se intentaron pegar caracteres no permitidos:', invalidChars);
            // No prevenir, solo mostrar advertencia
        }
    });
    
    // Inicializar fortaleza de contraseña
    updatePasswordStrength();
    
    // Actualizar tooltip de caracteres especiales
    const specialElement = document.getElementById('reqSpecial');
    if (specialElement) {
        specialElement.title = `Caracteres especiales permitidos: ${ALLOWED_SPECIAL_CHARS}`;
    }
});

// Manejo de errores seguro
window.addEventListener('error', function(e) {
    console.error('Error controlado:', e.message);
    return true;
});

// Protección adicional
if (window.console && window.console.log) {
    const originalLog = console.log;
    console.log = function(...args) {
        // Filtrar datos sensibles
        const filtered = args.map(arg => {
            if (typeof arg === 'string') {
                return arg.replace(/(password|token|csrf)=[^&]*/gi, '$1=***');
            }
            return arg;
        });
        originalLog.apply(console, filtered);
    };
}
</script>
</body>
</html>