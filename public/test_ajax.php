<?php
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'message' => 'Test exitoso',
    'timestamp' => date('Y-m-d H:i:s'),
    'method' => $_SERVER['REQUEST_METHOD'],
    'data' => json_decode(file_get_contents('php://input'), true)
]);
?>