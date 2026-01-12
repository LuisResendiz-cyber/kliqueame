<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../PHPMailer/src/Exception.php';
require_once __DIR__ . '/../PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/../PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 2; // 🔥 DEBUG TOTAL
$mail->isSMTP();
$mail->Host = 'smtp.titan.email';
$mail->SMTPAuth = true;
$mail->Username = 'no-reply@qlikme.com';
$mail->Password = 'PASSWORD_REAL';
$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;

$mail->setFrom('no-reply@qlikme.com', 'Qlikme');
$mail->addAddress('TU_CORREO_PERSONAL@gmail.com');

$mail->Subject = 'Test SMTP Qlikme';
$mail->Body = 'SMTP funcionando';

$mail->send();

echo 'Correo enviado correctamente';