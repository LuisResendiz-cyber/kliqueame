<?php
// bootstrap - PDO, CSRF helpers, auth helper
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

// load .env simple parser (key=value)
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $_ENV[trim($parts[0])] = trim($parts[1], "\"'");
        }
    }
}

// db connection
try {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $_ENV['DB_HOST'] ?? 'localhost', $_ENV['DB_NAME'] ?? '');
    $pdo = new PDO($dsn, $_ENV['DB_USER'] ?? '', $_ENV['DB_PASS'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    die('Error en conexión: ' . $e->getMessage());
}

function db() { global $pdo; return $pdo; }
function authUser() { return $_SESSION['user_id'] ?? null; }

function enforceUserStatus() {
    if (!authUser()) return;

    $stmt = db()->prepare('SELECT status FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if ($user && $user['status'] === 'suspended') {
        session_destroy();
        header('Location: login.php?error=Cuenta suspendida');
        exit;
    }
}

// CSRF
function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(24));
    }
    return $_SESSION['csrf_token'];
}
function verify_csrf_token($tok) {
    return is_string($tok) && isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $tok);
}
