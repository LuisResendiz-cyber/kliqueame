<?php
require_once __DIR__ . '/../src/bootstrap.php';

// ==============================
// PHPMailer
// ==============================
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../PHPMailer/src/Exception.php';
require_once __DIR__ . '/../PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/../PHPMailer/src/SMTP.php';

error_log('SEND_RESET_LINK EJECUTADO');
error_log(print_r($_POST, true));

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: forgot_password.php');
    exit;
}

$email = trim($_POST['email'] ?? '');

if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: forgot_password.php?error=Correo inválido');
    exit;
}

// Buscar usuario
$stmt = db()->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
$stmt->execute([$email]);
$user = $stmt->fetch();

if (!$user) {
    // Mensaje genérico (no revelar si existe)
    header('Location: forgot_password.php?success=Si el correo existe, recibirás un enlace');
    exit;
}

// Generar token
$token  = bin2hex(random_bytes(32));
$expiry = date('Y-m-d H:i:s', time() + 3600);

// Guardar token
$stmt = db()->prepare(
    'INSERT INTO password_resets (user_id, token, expiry) VALUES (?, ?, ?)'
);
$stmt->execute([$user['id'], $token, $expiry]);

$resetLink = "https://app.datamapworks.com.mx/qlikmeapp/public/reset_password.php?token=$token";

// ==============================
// ENVÍO DE CORREO (SMTP cPanel)
// ==============================
$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host       = 'mail.datamapworks.com.mx';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'no-reply@datamapworks.com.mx';
    $mail->Password   = 'Lcmu837%';
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;

    $mail->setFrom('no-reply@datamapworks.com.mx', 'Qlikme');
    $mail->addAddress($email);

    $mail->isHTML(true);
    $mail->Subject = 'Recuperación de contraseña - Qlikme';
    $mail->Body = "
        <p>Hola,</p>
        <p>Recibimos una solicitud para restablecer tu contraseña.</p>
        <p>
            <a href='$resetLink' style='
                display:inline-block;
                padding:12px 20px;
                background:#00A39A;
                color:#fff;
                text-decoration:none;
                border-radius:8px;
                font-weight:600;
            '>Restablecer contraseña</a>
        </p>
        <p>Este enlace expirará en 1 hora.</p>
        <p>Si no solicitaste este cambio, ignora este correo.</p>
        <br>
        <p><strong>Equipo Qlikme</strong></p>
    ";

    $mail->AltBody = "Restablece tu contraseña aquí:\n$resetLink\n\nEste enlace expira en 1 hora.";

    $mail->send();

    header('Location: forgot_password.php?success=Revisa tu correo');
    exit;

} catch (Exception $e) {
    error_log('ERROR SMTP: ' . $mail->ErrorInfo);
    header('Location: forgot_password.php?error=No se pudo enviar el correo. Intenta más tarde');
    exit;
}