<?php
// qr.php - genera QR básico sin librerías externas

$text = $_GET['text'] ?? '';
if (!$text) {
    http_response_code(400);
    echo 'No text provided';
    exit;
}

header('Content-Type: image/png');

// Usamos la API de Google Charts para generar el QR
// Tamaño: 200x200
$qrUrl = 'https://chart.googleapis.com/chart?cht=qr&chs=200x200&chl=' . urlencode($text) . '&choe=UTF-8';

// Traemos la imagen desde Google Charts y la mostramos
$qrImage = file_get_contents($qrUrl);
if ($qrImage === false) {
    http_response_code(500);
    echo 'Error generando QR';
    exit;
}

echo $qrImage;