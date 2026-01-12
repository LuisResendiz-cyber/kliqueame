<?php
require_once __DIR__ . '/../src/bootstrap.php';
if (!authUser()) { header('Location: login.php'); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: dashboard.php'); exit; }
if (!verify_csrf_token($_POST['csrf'] ?? '')) { die('Token invalido'); }

$user_id = authUser();
$name = trim($_POST['name'] ?? '');
$title = trim($_POST['title'] ?? '');
$remove_logo = isset($_POST['remove_logo']) && $_POST['remove_logo'] == '1';
// validate inputs
if (empty($name)) { die('Nombre requerido'); }

// =============================================
// PROCESAR ENLACES CON ORDEN PERSONALIZADO
// =============================================
$links_order = $_POST['links_order'] ?? '[]';
$ordered_links = json_decode($links_order, true) ?: [];

// Si hay orden personalizado, usarlo en lugar del orden del formulario
if (!empty($ordered_links)) {
    $links = [];
    foreach ($ordered_links as $link) {
        $lab = trim($link['label'] ?? '');
        $u = trim($link['url'] ?? '');
        
        if ($lab && $u) {
            if (strpos($u, 'mailto:') === 0 || strpos($u, 'tel:') === 0) {
                $valid = true;
            } else {
                $parts = parse_url($u);
                $valid = isset($parts['scheme']) && in_array($parts['scheme'], ['http','https']);
            }
            if ($valid) {
                $links[] = ['label' => $lab, 'url' => $u];
            }
        }
    }
    $links_json = json_encode($links, JSON_UNESCAPED_UNICODE);
} else {
    // Mantener la ligica original si no hay orden personalizado (fallback)
    $labels = $_POST['label'] ?? [];
    $urls = $_POST['url'] ?? [];
    $links = [];
    for ($i=0;$i<count($labels) && $i<count($urls);$i++) {
        $lab = trim($labels[$i]);
        $u = trim($urls[$i]);
        if ($lab && $u) {
            if (strpos($u, 'mailto:') === 0 || strpos($u, 'tel:') === 0) {
                $valid = true;
            } else {
                $parts = parse_url($u);
                $valid = isset($parts['scheme']) && in_array($parts['scheme'], ['http','https']);
            }
            if ($valid) {
                $links[] = ['label'=>$lab, 'url'=>$u];
            }
        }
    }
    $links_json = json_encode($links, JSON_UNESCAPED_UNICODE);
}

// =============================================
// MANEJO DE LOGO (MANTIENE LA LOGICA ORIGINAL)
// =============================================
$logo_path = null;
if (!empty($_FILES['logo']['name'])) {
    $f = $_FILES['logo'];
    //if ($f['error'] === 0 && $f['size'] <= 512000) {
    if ($f['error'] === 0 && $f['size'] <= 5242880) { // hasta 5 MB
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $f['tmp_name']);
        finfo_close($finfo);
        if (in_array($mime, ['image/png','image/jpeg'])) {
            $ext = $mime === 'image/png' ? '.png' : '.jpg';
            $safe = bin2hex(random_bytes(8)).$ext;
            $target_dir = __DIR__ . '/../uploads/';
            if (!is_dir($target_dir)) mkdir($target_dir, 0755, true);
            $dest = $target_dir . $safe;
            if (move_uploaded_file($f['tmp_name'], $dest)) {
                $logo_path = 'uploads/' . $safe;
            }
        }
    }
}

// =============================================
// INSERTAR O ACTUALIZAR EN BASE DE DATOS
// =============================================
$pdo = db();
$stmt = $pdo->prepare('SELECT id, logo FROM cards WHERE user_id = ? LIMIT 1');
$stmt->execute([$user_id]);
$exists = $stmt->fetch();

// Determine final logo path
if ($remove_logo) {
    $logo_to_save = null;
    // Delete old logo file if exists
    if ($exists && !empty($exists['logo'])) {
        $old_logo_path = __DIR__ . '/../' . $exists['logo'];
        if (file_exists($old_logo_path)) {
            unlink($old_logo_path);
        }
    }
} else {
    $logo_to_save = $logo_path ?: ($exists['logo'] ?? null);
}

if ($exists) {
    $stmt = $pdo->prepare('UPDATE cards SET name = ?, title = ?, links = ?, logo = ? WHERE user_id = ?');
    $stmt->execute([$name, $title, $links_json, $logo_to_save, $user_id]);
} else {
    $stmt = $pdo->prepare('INSERT INTO cards (user_id, name, title, links, logo) VALUES (?,?,?,?,?)');
    $stmt->execute([$user_id, $name, $title, $links_json, $logo_to_save]);
}

// Delete old logo file if replaced
if ($logo_path && $exists && !empty($exists['logo']) && $exists['logo'] !== $logo_path) {
    $old_logo_path = __DIR__ . '/../' . $exists['logo'];
    if (file_exists($old_logo_path)) {
        unlink($old_logo_path);
    }
}

header('Location: dashboard.php');
exit;