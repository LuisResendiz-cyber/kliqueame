<?php
require_once __DIR__ . '/../src/bootstrap.php';

/* -------------------------------------------------------
   HEADERS DE SEGURIDAD (MISMA LÍNEA QLIKME)
------------------------------------------------------- */

// Limpiar buffers
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Forzar HTTPS en producción
$is_production = $_SERVER['SERVER_NAME'] !== 'localhost'
    && $_SERVER['SERVER_NAME'] !== '127.0.0.1'
    && strpos($_SERVER['SERVER_NAME'], '.local') === false;

if ($is_production && (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off')) {
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit;
}

// Headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");

// CSP
$nonce = base64_encode(random_bytes(16));
$csp = "default-src 'self'; "
     . "style-src 'self' 'nonce-$nonce' https://fonts.googleapis.com; "
     . "font-src 'self' https://fonts.gstatic.com; "
     . "form-action 'self'; "
     . "base-uri 'self'; "
     . "frame-ancestors 'none';";
header("Content-Security-Policy: $csp");

// Cache control
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// -------------------------------------------------------
// VALIDAR TOKEN
// -------------------------------------------------------

$token = trim($_GET['token'] ?? '');

$stmt = db()->prepare(
    'SELECT user_id, expiry FROM password_resets WHERE token = ? LIMIT 1'
);
$stmt->execute([$token]);
$data = $stmt->fetch();

if (!$data || strtotime($data['expiry']) < time()) {
    header('Location: forgot_password.php?error=Enlace inválido o expirado');
    exit;
}
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Restablecer contraseña - QlikMe</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">

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

.reset-wrapper {
    width: 100%;
    max-width: 420px;
    padding: 20px;
}

.reset-box {
    background: #fff;
    padding: 26px;
    border-radius: 14px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.07);
    border: 1px solid #e6e9f2;
}

h2 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 18px;
    color: #222;
    text-align: center;
}

label {
    display: block;
    margin-bottom: 16px;
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
    margin-top: 6px;
    box-sizing: border-box;
}

input:focus {
    border-color: #00A39A;
    box-shadow: 0 0 4px rgba(0,163,154,0.3);
}

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
    margin-top: 10px;
}

button:hover {
    background: #008b84;
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,163,154,0.2);
}

.password-help {
    font-size: 12px;
    color: #666;
    margin-top: 8px;
    line-height: 1.4;
}

.footer-link {
    margin-top: 18px;
    text-align: center;
}

.footer-link a {
    color: #00A39A;
    text-decoration: none;
    font-weight: 600;
}

.footer-link a:hover {
    text-decoration: underline;
}

@media (max-width: 480px) {
    .reset-box {
        padding: 22px;
    }
    h2 {
        font-size: 22px;
    }
}
</style>
</head>

<body>

<div class="reset-wrapper">
    <div class="reset-box">
        <h2>Restablecer contraseña</h2>

        <form method="post" action="update_password.php" autocomplete="off">
            <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">

            <label>
                Nueva contraseña
                <input type="password"
                       name="password"
                       required
                       minlength="8"
                       maxlength="72"
                       autocomplete="new-password">
            </label>

            <label>
                Confirmar contraseña
                <input type="password"
                       name="confirm"
                       required
                       minlength="8"
                       maxlength="72"
                       autocomplete="new-password">
            </label>

            <div class="password-help">
                Mínimo 8 caracteres. Usa una combinación segura.
            </div>

            <button type="submit">Actualizar contraseña</button>
        </form>

        <div class="footer-link">
            <a href="login.php">Volver a iniciar sesión</a>
        </div>
    </div>
</div>

</body>
</html>