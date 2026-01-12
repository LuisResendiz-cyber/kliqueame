<?php
require_once __DIR__ . '/../src/bootstrap.php';
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Recuperar contraseña - Qlikme</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="https://desarrollo.impulse-solution.online/qlikmeapp/public/logo-qlikme-recortado.png">
<style>
body{
    font-family: Inter, sans-serif;
    background:#f4f8f9;
    display:flex;
    align-items:center;
    justify-content:center;
    height:100vh;
}
.box{
    background:#fff;
    padding:30px;
    border-radius:14px;
    max-width:400px;
    width:100%;
    box-shadow:0 4px 14px rgba(0,0,0,.1);
}
button{
    width:100%;
    background:#00A39A;
    color:#fff;
    padding:14px;
    border:none;
    border-radius:10px;
    font-weight:600;
}
</style>
</head>
<body>

<div class="box">
    <h2>¿Olvidaste tu contraseña?</h2>

    <?php if (!empty($_GET['error'])): ?>
        <p style="color:red"><?= htmlspecialchars($_GET['error']) ?></p>
    <?php endif; ?>

    <?php if (!empty($_GET['success'])): ?>
        <p style="color:green"><?= htmlspecialchars($_GET['success']) ?></p>
    <?php endif; ?>

    <form method="post" action="send_reset_link.php">
        <input type="email" name="email" required placeholder="Tu correo"
               style="width:100%;padding:12px;margin:12px 0">
        <button type="submit">Enviar enlace</button>
    </form>
</div>

</body>
</html>