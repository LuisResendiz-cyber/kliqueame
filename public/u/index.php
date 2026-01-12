<?php
require_once __DIR__ . '/../../src/bootstrap.php';

// ============================================
// 1. HEADERS DE SEGURIDAD
// ============================================
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Generar nonce para CSP
$nonce = base64_encode(random_bytes(16));
$csp = "default-src 'self'; " .
       "img-src 'self' data: https:; " .
       "script-src 'self' 'nonce-$nonce' https://cdnjs.cloudflare.com; " .
       "script-src-attr 'unsafe-hashes'; " .
       "style-src 'self' 'nonce-$nonce' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " .
       "style-src-elem 'self' 'nonce-$nonce' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " .
       "style-src-attr 'unsafe-hashes'; " .
       "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
       "connect-src 'self'; " .
       "frame-ancestors 'none';";
header("Content-Security-Policy: " . $csp);

// ============================================
// 2. VALIDACIÓN DE PARÁMETROS
// ============================================
$user = (int)($_GET['user'] ?? 0);
if ($user <= 0) { 
    http_response_code(400); 
    echo 'Parámetro inválido'; 
    exit; 
}

// Log de acceso (opcional para auditoría)
error_log("Acceso a tarjeta digital - Usuario: $user - IP: " . $_SERVER['REMOTE_ADDR']);

// ============================================
// 3. CONSULTA SEGURA CON PREPARED STATEMENTS
// ============================================
$stmt = db()->prepare('SELECT * FROM cards WHERE user_id = ? LIMIT 1');
$stmt->execute([$user]);
$card = $stmt->fetch();

if (!$card) { 
    http_response_code(404); 
    echo 'Tarjeta no encontrada'; 
    exit; 
}

// ============================================
// 4. SANITIZACIÓN DE COLORES
// ============================================
function sanitizeColor($color, $default = '#ffffff') {
    if (preg_match('/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/', $color)) {
        return $color;
    }
    return $default;
}

function getContrastColor($hexcolor) {
    $hexcolor = preg_replace('/[^A-Fa-f0-9]/', '', $hexcolor); // Solo hex
    
    if (strlen($hexcolor) == 3) {
        $hexcolor = $hexcolor[0] . $hexcolor[0] . $hexcolor[1] . $hexcolor[1] . $hexcolor[2] . $hexcolor[2];
    }
    
    if (strlen($hexcolor) != 6) {
        return '#000000';
    }
    
    $r = hexdec(substr($hexcolor, 0, 2));
    $g = hexdec(substr($hexcolor, 2, 2));
    $b = hexdec(substr($hexcolor, 4, 2));
    
    $yiq = (($r * 299) + ($g * 587) + ($b * 114)) / 1000;
    
    return ($yiq >= 128) ? '#000000' : '#ffffff';
}

$cardBgColor = sanitizeColor($card['background_color'] ?? '#ffffff');
$cardTextColor = sanitizeColor($card['text_color'] ?? '#333333');
$cardBtnColor = sanitizeColor($card['button_color'] ?? '#4a6cf7');
$cardBtnTextColor = sanitizeColor($card['button_text_color'] ?? getContrastColor($card['button_color'] ?? '#4a6cf7'));

// ============================================
// 5. MANEJO SEGURO DE IMÁGENES
// ============================================
$cardBgImage = $card['background_image'] ?? '';

if (!empty($cardBgImage)) {
    if (strpos($cardBgImage, 'data:image') === 0) {
        // Validar base64 seguro
        if (!preg_match('/^data:image\/(png|jpeg|jpg|gif);base64,[A-Za-z0-9+\/=]+$/', $cardBgImage)) {
            $cardBgImage = '';
            error_log("Base64 inválido en tarjeta - Usuario: $user");
        }
    } 
    else if (strpos($cardBgImage, 'http://') === 0 || strpos($cardBgImage, 'https://') === 0) {
        // Validar URL externa
        if (!filter_var($cardBgImage, FILTER_VALIDATE_URL)) {
            $cardBgImage = '';
        }
        // Limitar a protocolos seguros
        else if (strpos($cardBgImage, 'http://') === 0 && !strpos($cardBgImage, 'localhost')) {
            // Permitir HTTP solo en localhost
            $cardBgImage = '';
        }
    }
    else {
        // PREVENIR PATH TRAVERSAL en rutas locales
        $cardBgImage = preg_replace('/\.\.\//', '', $cardBgImage);
        $cardBgImage = preg_replace('/\.\.\\\\/', '', $cardBgImage);
        $cardBgImage = ltrim($cardBgImage, '/');
        
        // Verificar que sea una ruta permitida
        $allowed_paths = ['uploads/', 'assets/'];
        $is_allowed = false;
        foreach ($allowed_paths as $path) {
            if (strpos($cardBgImage, $path) === 0) {
                $is_allowed = true;
                break;
            }
        }
        
        if (!$is_allowed) {
            $cardBgImage = '';
            error_log("Ruta no permitida en tarjeta: $cardBgImage - Usuario: $user");
        } else {
            $cardBgImage = '/qlikmeapp/' . htmlspecialchars($cardBgImage, ENT_QUOTES, 'UTF-8');
        }
    }
}

// ============================================
// 6. SANITIZACIÓN DE ENLACES (MISMA LÓGICA QUE DASHBOARD)
// ============================================
$links = [];

if (!empty($card['links'])) {
    $decoded = json_decode($card['links'], true);

    if (is_array($decoded)) {
        foreach ($decoded as $link) {
            if (!isset($link['label'], $link['url'])) {
                continue;
            }

            // Sanitizar label
            $clean_label = preg_replace('/[^\p{L}\p{N}\s\-_.,@]/u', '', $link['label']);
            $clean_label = substr($clean_label, 0, 100);

            // URL original
            $clean_url = trim($link['url']);

            if ($clean_url === '') {
                continue;
            }

            // === VALIDACIONES ESPECIALES (IGUAL QUE DASHBOARD) ===

            // TEL
            if (strpos($clean_url, 'tel:') === 0) {
                $phone = substr($clean_url, 4);
                if (preg_match('/^\+?[\d\s\(\)\-]{7,}$/', $phone)) {
                    $links[] = [
                        'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                        'url'   => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                    ];
                }
                continue;
            }

            // MAILTO
            if (strpos($clean_url, 'mailto:') === 0) {
                $links[] = [
                    'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                    'url'   => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                ];
                continue;
            }

            // WHATSAPP
            if (strpos($clean_url, 'whatsapp:') === 0 || strpos($clean_url, 'https://wa.me/') === 0) {
                $links[] = [
                    'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                    'url'   => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                ];
                continue;
            }

            // HTTP / HTTPS normales
            if (filter_var($clean_url, FILTER_VALIDATE_URL)) {
                $parsed = parse_url($clean_url);
                if ($parsed && in_array($parsed['scheme'], ['http', 'https'])) {
                    $links[] = [
                        'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                        'url'   => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                    ];
                }
            }
        }
    }
}

// ============================================
// 7. CONSTRUCCIÓN DE URL SEGURA
// ============================================
$allowed_domains = ['app.datamapworks.com.mx', 'tudominio.com'];
$current_domain = parse_url($_SERVER['HTTP_HOST'] ?? '', PHP_URL_HOST);
$domain = in_array($current_domain, $allowed_domains) ? $current_domain : $allowed_domains[0];

$cardUrl = "https://{$domain}/qlikmeapp/public/u/index.php?user=" . urlencode($user);

// ============================================
// 8. FUNCIÓN PARA OBTENER ICONOS SEGUROS
// ============================================
function getLinkIconFA($url) {
    if (empty($url)) return 'fas fa-link';
    
    $url = strtolower($url);
    
    // Lista blanca de dominios permitidos
    $allowed_patterns = [
        'whatsapp' => 'fab fa-whatsapp',
        'wa.me' => 'fab fa-whatsapp',
        'instagram.com' => 'fab fa-instagram',
        'facebook.com' => 'fab fa-facebook-f',
        'twitter.com' => 'fab fa-twitter',
        'x.com' => 'fab fa-twitter',
        'linkedin.com' => 'fab fa-linkedin-in',
        'youtube.com' => 'fab fa-youtube',
        'youtu.be' => 'fab fa-youtube',
        'tiktok.com' => 'fab fa-tiktok',
        'mailto:' => 'fas fa-envelope',
        'tel:' => 'fas fa-phone-alt',
        'spotify.com' => 'fab fa-spotify',
        't.me' => 'fab fa-telegram',
        'telegram' => 'fab fa-telegram',
        'pinterest' => 'fab fa-pinterest',
        'github.com' => 'fab fa-github',
        'maps.google' => 'fas fa-map-marker-alt',
        'goo.gl/maps' => 'fas fa-map-marker-alt',
        'maps.apple.com' => 'fas fa-map-marker-alt',
        'calendar' => 'fas fa-calendar-alt',
        'calendly' => 'fas fa-calendar-alt',
        'paypal' => 'fas fa-credit-card',
        'mercadopago' => 'fas fa-credit-card'
    ];
    
    foreach ($allowed_patterns as $pattern => $icon) {
        if (strpos($url, $pattern) !== false) {
            return $icon;
        }
    }
    
    // URLs http/https genéricas
    if (strpos($url, 'http://') === 0 || strpos($url, 'https://') === 0) {
        return 'fas fa-globe';
    }
    
    return 'fas fa-link';
}

// ============================================
// 9. PREPARAR DATOS PARA VISTA
// ============================================
$card_name = htmlspecialchars($card['name'] ?? '', ENT_QUOTES, 'UTF-8');
$card_title = htmlspecialchars($card['title'] ?? '', ENT_QUOTES, 'UTF-8');
$logo_path = !empty($card['logo']) ? htmlspecialchars($card['logo'], ENT_QUOTES, 'UTF-8') : '';

// Opacidad para imagen de fondo
$bg_image_opacity = ($cardBgColor !== '#ffffff' && $cardBgColor !== '#fff') ? '0.8' : '1';

// Generar un ID único para la imagen de logo para manejo con JavaScript
$logo_id = 'logo-' . bin2hex(random_bytes(8));
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <link rel="icon" type="image/svg+xml" href="https://app.datamapworks.com.mx/qlikmeapp/public/logo-qlikme-recortado.png">
    <title><?= $card_name ?> - Qlikme Digital Card</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <!-- Font Awesome con integridad SRI -->
    <link rel="stylesheet" 
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    <style nonce="<?= $nonce ?>">
        /* Base - Homologado con dashboard */
        :root {
            --primary: #00A39A;
            --primary-dark: #008b84;
            --bg: #f4f8f9;
            --card: #ffffff;
            --text: #222;
            --text-muted: #444;
            --border: #ccc;
            /* Variables dinámicas desde PHP */
            --user-btn-color: <?= $cardBtnColor ?>;
            --user-btn-text-color: <?= $cardBtnTextColor ?>;
        }

        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow-x: hidden;
        }

        /* Container principal */
        .card-container {
            width: 100%;
            max-width: 400px;
            margin: 0 auto;
            position: relative;
        }

        /* Tarjeta - APLICA PERSONALIZACIÓN DESDE DB */
        .digital-card {
            width: 100%;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            border: 1px solid #e6e9f2;
            text-align: center;
            position: relative;
            overflow: hidden;
            background-color: <?= $cardBgColor ?>;
        }

        /* Imagen de fondo */
        .digital-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 0;
            pointer-events: none;
            <?php if (!empty($cardBgImage)): ?>
                background-image: url('<?= $cardBgImage ?>');
                background-size: cover;
                background-position: center;
                background-repeat: no-repeat;
                background-blend-mode: normal;
                opacity: <?= $bg_image_opacity ?>;
            <?php endif; ?>
        }

        /* Asegurar que todo el contenido esté por ENCIMA de la imagen */
        .digital-card > * {
            position: relative;
            z-index: 1;
        }

        /* Logo */
        .card-logo {
            width: 140px;
            height: 140px;
            object-fit: contain;
            border-radius: 16px;
            border: 2px solid rgba(230, 233, 242, 0.5);
            background: #fff;
            margin: 0 auto 25px;
            display: block;
            position: relative;
            z-index: 1;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            max-width: 100%;
        }

        .logo-error {
            width: 140px;
            height: 140px;
            border-radius: 16px;
            background: linear-gradient(135deg, #f3f6ff 0%, #e6e9f2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
            font-weight: 700;
            margin: 0 auto 25px;
            position: relative;
            z-index: 1;
            border: 2px dashed #e6e9f2;
        }

        .logo-error i {
            font-size: 48px;
            opacity: 0.7;
        }

        /* Textos - COLOR DESDE DB */
        .card-name {
            font-size: 28px;
            font-weight: 700;
            margin: 0 0 10px 0;
            color: <?= $cardTextColor ?>;
            <?php if (!empty($cardBgImage)): ?>
                background-color: rgba(255, 255, 255, 0.85);
                display: inline-block;
                padding: 8px 20px;
                border-radius: 12px;
                backdrop-filter: blur(4px);
            <?php endif; ?>
            word-break: break-word;
            line-height: 1.3;
        }

        .card-title {
            margin: 0 0 30px 0;
            font-size: 17px;
            color: <?= $cardTextColor ?>;
            opacity: 0.9;
            <?php if (!empty($cardBgImage)): ?>
                background-color: rgba(255, 255, 255, 0.85);
                display: inline-block;
                padding: 6px 16px;
                border-radius: 10px;
                backdrop-filter: blur(4px);
            <?php endif; ?>
            word-break: break-word;
            line-height: 1.4;
        }

        /* Enlaces - USAN COLOR PERSONALIZADO DEL USUARIO */
        .links-container {
            display: flex;
            flex-direction: column;
            gap: 14px;
            margin: 30px 0;
        }

        .card-link {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px 24px;
            border-radius: 14px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            width: 100%;
            box-sizing: border-box;
            /* Color personalizado del usuario */
            background: var(--user-btn-color);
            color: var(--user-btn-text-color);
            border: none;
            position: relative;
            z-index: 1;
            gap: 15px;
            font-size: 16px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            overflow: hidden;
        }

        .card-link::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: 0.5s;
        }

        .card-link:hover::before {
            left: 100%;
        }

        .card-link:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
            opacity: 0.95;
        }

        /* Iconos dentro de los enlaces - COLOR DEL TEXTO DEL USUARIO */
        .link-icon {
            font-size: 22px;
            width: 26px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.3s ease;
            color: var(--user-btn-text-color);
        }

        .card-link:hover .link-icon {
            transform: scale(1.1);
        }

        .link-text {
            flex: 1;
            text-align: center;
            letter-spacing: 0.3px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        /* Sección de compartir */
        .share-section {
            margin-top: 30px;
            padding-top: 30px;
            border-top: 1px solid rgba(230, 233, 242, 0.5);
            position: relative;
            z-index: 1;
        }

        /* Botón de compartir - COLOR DEL USUARIO */
        .share-btn {
            background: var(--user-btn-color);
            color: var(--user-btn-text-color);
            border: none;
            border-radius: 14px;
            padding: 18px 30px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            font-size: 17px;
            position: relative;
            z-index: 1;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            overflow: hidden;
            margin: 0 auto;
        }

        .share-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: 0.5s;
        }

        .share-btn:hover::before {
            left: 100%;
        }

        .share-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
            opacity: 0.95;
        }

        /* Icono en botón de compartir */
        .share-icon {
            font-size: 20px;
            color: inherit;
        }

        .share-btn:hover .share-icon {
            transform: scale(1.1);
            transition: transform 0.3s ease;
        }

        /* Clase para ocultar elementos */
        .hidden {
            display: none !important;
        }

        /* Responsive */
        @media (max-width: 480px) {
            body {
                padding: 15px;
            }
            
            .card-container {
                margin: 0;
            }
            
            .digital-card {
                padding: 25px;
                border-radius: 18px;
            }
            
            .share-btn {
                padding: 16px 24px;
                font-size: 16px;
            }
            
            .card-link {
                padding: 14px 20px;
                border-radius: 12px;
            }
            
            .link-icon {
                font-size: 20px;
                width: 24px;
            }
            
            .card-name {
                font-size: 24px;
            }
            
            .card-title {
                font-size: 16px;
            }
        }

        @media (max-width: 350px) {
            .digital-card {
                padding: 20px;
            }
            
            .card-link {
                padding: 12px 16px;
                font-size: 15px;
            }
            
            .share-btn {
                padding: 14px 20px;
                font-size: 15px;
            }
        }

        /* Estados de carga */
        .loading {
            opacity: 0.7;
            pointer-events: none;
        }
        /* Powered by Qlikme */
.powered-by {
    margin-top: 24px;
    text-align: center;
    opacity: 0.85;
}

.powered-divider {
    width: 40px;
    height: 2px;
    background: rgba(0, 0, 0, 0.12);
    margin: 0 auto 12px;
    border-radius: 2px;
}

.powered-by small {
    display: block;
    font-size: 12px;
    color: rgba(0, 0, 0, 0.55);
    margin-bottom: 4px;
}

.powered-by a {
    font-size: 14px;
    font-weight: 600;
    color: var(--user-btn-color);
    text-decoration: none;
    letter-spacing: 0.2px;
    transition: all 0.25s ease;
}

.powered-by a:hover {
    opacity: 0.9;
    text-decoration: underline;
}

        /* Animación para notificaciones */
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translateX(-50%) translateY(-10px); }
            10% { opacity: 1; transform: translateX(-50%) translateY(0); }
            90% { opacity: 1; transform: translateX(-50%) translateY(0); }
            100% { opacity: 0; transform: translateX(-50%) translateY(-10px); }
        }

        /* Efecto de brillo al pasar el mouse */
        @keyframes shine {
            to {
                background-position: 200% center;
            }
        }

        .card-link, .share-btn {
            background-size: 200% auto;
        }

        /* Mejorar legibilidad en fondos claros */
        .card-link {
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        /* Protección contra text selection */
        .card-link, .share-btn {
            user-select: none;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
        }
    </style>
</head>
<body>
    <div class="card-container">
        <div class="digital-card">
            <!-- Logo -->
            <?php if(!empty($logo_path)): 
                // Sanitizar ruta del logo
                $safe_logo_path = preg_replace('/\.\.\//', '', $logo_path);
                $logo_url = '/qlikmeapp/' . htmlspecialchars($safe_logo_path, ENT_QUOTES, 'UTF-8');
            ?>
                <img src="<?= $logo_url ?>" 
                     alt="logo" 
                     class="card-logo"
                     id="<?= $logo_id ?>"
                     crossorigin="anonymous">
                <div class="logo-error hidden" id="logo-error-<?= $logo_id ?>">
                    <i class="fas fa-user-circle"></i>
                </div>
            <?php else: ?>
                <div class="logo-error">
                    <i class="fas fa-user-circle"></i>
                </div>
            <?php endif; ?>

            <!-- Información personal -->
            <h1 class="card-name"><?= $card_name ?></h1>
            <p class="card-title"><?= $card_title ?></p>

            <!-- Enlaces CON COLOR PERSONALIZADO DEL USUARIO -->
            <div class="links-container">
                <?php foreach($links as $l): 
                    $iconFA = getLinkIconFA($l['url'] ?? '');
                    // Sanitizar URL y label para atributos HTML
                    $safe_url = htmlspecialchars($l['url'], ENT_QUOTES, 'UTF-8');
                    $safe_label = htmlspecialchars($l['label'], ENT_QUOTES, 'UTF-8');
                ?>
                    <a href="<?= $safe_url ?>" 
                       target="_blank" 
                       rel="noopener noreferrer" 
                       class="card-link"
                       title="<?= $safe_label ?>">
                        <i class="link-icon <?= $iconFA ?>"></i>
                        <span class="link-text"><?= $safe_label ?></span>
                    </a>
                <?php endforeach; ?>
            </div>

            <!-- Sección de compartir - SOLO BOTÓN -->
            <div class="share-section">
                <button id="shareCard" class="share-btn" aria-label="Compartir tarjeta digital">
                    <i class="share-icon fas fa-share-alt"></i>
                    <span>Compartir tarjeta</span>
                </button>
            </div>
            <div class="powered-by">
                <div class="powered-divider"></div>
                <small>Tarjeta creada con</small>
                <a href="https://qlikme.com/wordpress/"
                   target="_blank"
                   rel="noopener noreferrer">
                    Qlikme
                </a>
            </div>
        </div>
    </div>

    <script nonce="<?= $nonce ?>">
        // ============================================
        // FUNCIONES DE SEGURIDAD
        // ============================================
        
        // Sanitizar entrada de usuario
        function sanitizeInput(text) {
            if (typeof text !== 'string') return '';
            return text
                .replace(/<[^>]*>/g, '') // Eliminar HTML
                .replace(/[^\p{L}\p{N}\s\-_.,@:;/?&=+#]/gu, '') // Solo caracteres seguros
                .substring(0, 500);
        }

        // Validar URL
        function isValidUrl(string) {
            if (typeof string !== 'string') return false;
            try {
                const url = new URL(string);
                const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'whatsapp:'];
                return allowedProtocols.includes(url.protocol);
            } catch (_) {
                return false;
            }
        }

        // Sanitizar colores CSS
        function sanitizeColorCSS(color) {
            if (/^#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})$/.test(color)) {
                return color;
            }
            return '#4a6cf7';
        }

        // ============================================
        // FUNCIONALIDAD PRINCIPAL
        // ============================================
        
        document.addEventListener('DOMContentLoaded', function() {
            const shareBtn = document.getElementById('shareCard');
            const cardUrl = "<?= htmlspecialchars($cardUrl, ENT_QUOTES, 'UTF-8') ?>";
            const cardContainer = document.querySelector('.digital-card');
            
            // Obtener colores del usuario desde PHP
            const userBtnColor = sanitizeColorCSS("<?= $cardBtnColor ?>");
            const userBtnTextColor = sanitizeColorCSS("<?= $cardBtnTextColor ?>");

            // Manejo de error para la imagen del logo
            <?php if(!empty($logo_path)): ?>
            const logoImg = document.getElementById('<?= $logo_id ?>');
            const logoError = document.getElementById('logo-error-<?= $logo_id ?>');
            
            if (logoImg) {
                logoImg.addEventListener('error', function() {
                    // Ocultar la imagen que falló
                    this.classList.add('hidden');
                    
                    // Mostrar el contenedor de error
                    if (logoError) {
                        logoError.classList.remove('hidden');
                    }
                });
                
                // También verificar si la imagen ya falló al cargar
                if (logoImg.complete && logoImg.naturalHeight === 0) {
                    logoImg.classList.add('hidden');
                    if (logoError) {
                        logoError.classList.remove('hidden');
                    }
                }
            }
            <?php endif; ?>

            // Función para mostrar mensaje seguro
            function showMessage(message) {
                const safeMessage = sanitizeInput(message);
                
                const messageEl = document.createElement('div');
                messageEl.textContent = safeMessage;
                messageEl.style.cssText = `
                    position: fixed;
                    top: 20px;
                    left: 50%;
                    transform: translateX(-50%);
                    background: ${userBtnColor};
                    color: ${userBtnTextColor};
                    padding: 14px 24px;
                    border-radius: 12px;
                    font-weight: 600;
                    z-index: 1000;
                    box-shadow: 0 6px 20px rgba(0,0,0,0.15);
                    animation: fadeInOut 3s ease-in-out;
                    font-size: 15px;
                    backdrop-filter: blur(4px);
                    border: 2px solid ${userBtnTextColor}20;
                    max-width: 90%;
                    word-break: break-word;
                    text-align: center;
                `;
                
                document.body.appendChild(messageEl);
                
                setTimeout(() => {
                    if (messageEl.parentNode) {
                        messageEl.parentNode.removeChild(messageEl);
                    }
                }, 3000);
            }

            // Compartir la tarjeta digital
            shareBtn.addEventListener('click', async function() {
                if (cardContainer.classList.contains('loading')) return;
                
                cardContainer.classList.add('loading');
                
                try {
                    if (navigator.share) {
                        const shareData = {
                            title: sanitizeInput('Mi tarjeta digital - <?= $card_name ?>'),
                            text: sanitizeInput('Visita mi tarjeta digital:'),
                            url: cardUrl
                        };
                        
                        // Validar que la URL sea segura antes de compartir
                        if (!isValidUrl(cardUrl)) {
                            throw new Error('URL no válida');
                        }
                        
                        await navigator.share(shareData);
                    } else {
                        // Fallback: copiar al portapapeles
                        await copyToClipboard(cardUrl);
                    }
                } catch (error) {
                    console.error('Error al compartir:', error);
                    
                    // Solo mostrar mensaje de error si no fue cancelado por el usuario
                    if (error.name !== 'AbortError') {
                        // Fallback seguro
                        if (await copyToClipboard(cardUrl)) {
                            showMessage('Enlace copiado al portapapeles');
                        } else {
                            showMessage('Copia este enlace: ' + cardUrl.substring(0, 50) + '...');
                        }
                    }
                } finally {
                    setTimeout(() => {
                        cardContainer.classList.remove('loading');
                    }, 500);
                }
            });

            // Función para copiar al portapapeles
            async function copyToClipboard(text) {
                if (!text || typeof text !== 'string') return false;
                
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(text);
                        return true;
                    } else {
                        // Fallback para navegadores más antiguos
                        const textArea = document.createElement('textarea');
                        textArea.value = text;
                        textArea.style.position = 'fixed';
                        textArea.style.opacity = '0';
                        textArea.style.left = '-9999px';
                        document.body.appendChild(textArea);
                        
                        textArea.select();
                        textArea.setSelectionRange(0, 99999);
                        
                        const successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        
                        return successful;
                    }
                } catch (error) {
                    console.error('Error al copiar:', error);
                    return false;
                }
            }

            // Efectos hover mejorados con validación
            const interactiveElements = document.querySelectorAll('.card-link, .share-btn');
            interactiveElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    if (!this.classList.contains('loading')) {
                        this.style.transform = 'translateY(-3px)';
                    }
                });
                
                element.addEventListener('mouseleave', function() {
                    if (!this.classList.contains('loading')) {
                        this.style.transform = 'translateY(0)';
                    }
                });
                
                // Prevenir doble clic rápido
                element.addEventListener('click', function(e) {
                    if (this.classList.contains('disabled')) {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                    }
                    
                    this.classList.add('disabled');
                    setTimeout(() => {
                        this.classList.remove('disabled');
                    }, 1000);
                });
            });

            // Validar enlaces antes de abrirlos
            document.querySelectorAll('.card-link').forEach(link => {
                link.addEventListener('click', function(e) {
                    const href = this.getAttribute('href');
                    
                    // Validar URL antes de abrir
                    if (!isValidUrl(href)) {
                        e.preventDefault();
                        console.warn('URL no válida:', href);
                        showMessage('Enlace no válido');
                        return false;
                    }
                    
                    // Verificar que sea un protocolo permitido
                    try {
                        const url = new URL(href);
                        const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'whatsapp:'];
                        
                        if (!allowedProtocols.includes(url.protocol)) {
                            e.preventDefault();
                            console.warn('Protocolo no permitido:', url.protocol);
                            showMessage('Protocolo no permitido');
                            return false;
                        }
                    } catch (error) {
                        e.preventDefault();
                        console.warn('URL mal formada:', href);
                        showMessage('Enlace mal formado');
                        return false;
                    }
                    
                    // Todo OK, permitir navegación
                    return true;
                });
            });

            // Añadir efecto de pulso sutil a los enlaces (solo si hay enlaces)
            const links = document.querySelectorAll('.card-link');
            if (links.length > 0) {
                setTimeout(() => {
                    links.forEach((link, index) => {
                        setTimeout(() => {
                            link.style.transform = 'translateY(-2px)';
                            setTimeout(() => {
                                link.style.transform = 'translateY(0)';
                            }, 300);
                        }, index * 100);
                    });
                }, 500);
            }

            // Prevenir inyección de código en atributos
            document.querySelectorAll('[title]').forEach(el => {
                const title = el.getAttribute('title');
                if (title) {
                    el.setAttribute('title', sanitizeInput(title));
                }
            });

            // Protección contra ataques de timing
            let lastClickTime = 0;
            document.addEventListener('click', function(e) {
                const currentTime = Date.now();
                if (currentTime - lastClickTime < 100) {
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
                lastClickTime = currentTime;
            });

            // Manejo de errores global
            window.onerror = function(msg, url, lineNo, columnNo, error) {
                console.error('Error:', {msg, url, lineNo});
                // No mostrar detalles al usuario
                return true; // Prevenir que el error se propague
            };
        });
    </script>
</body>
</html>