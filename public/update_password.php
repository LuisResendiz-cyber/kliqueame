<?php
require_once __DIR__ . '/../src/bootstrap.php';

$token = $_POST['token'] ?? '';
$password = $_POST['password'] ?? '';
$confirm = $_POST['confirm'] ?? '';

if ($password !== $confirm) {
    header("Location: reset_password.php?token=$token&error=Las contraseñas no coinciden");
    exit;
}

$stmt = db()->prepare(
    'SELECT user_id FROM password_resets WHERE token = ? AND expiry > NOW()'
);
$stmt->execute([$token]);
$data = $stmt->fetch();

if (!$data) {
    header('Location: forgot_password.php?error=Token inválido');
    exit;
}

// Actualizar password
$hash = password_hash($password, PASSWORD_DEFAULT);

$stmt = db()->prepare(
    'UPDATE users SET password_hash = ? WHERE id = ?'
);
$stmt->execute([$hash, $data['user_id']]);

// Eliminar token
$stmt = db()->prepare('DELETE FROM password_resets WHERE token = ?');
$stmt->execute([$token]);

header('Location: index.php?success=Contraseña actualizada');
exit;