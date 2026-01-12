<?php
require_once __DIR__ . '/../src/bootstrap.php';
$stmt = db()->prepare('SELECT status FROM users WHERE id = ?');
$stmt->execute([$_SESSION['user_id'] ?? 0]);

if ($stmt->fetchColumn() === 'suspended') {
    session_destroy();
    header('Location: login.php?error=suspended');
    exit;
}
if (!authUser()) { 
    header('Location: login.php');
    exit; 
}
$user_id = (int) authUser(); // Forzar tipo entero
if ($user_id <= 0) {
    // Log de intento sospechoso
    error_log("ID de usuario inválido en dashboard.php - IP: " . $_SERVER['REMOTE_ADDR']);
    header('Location: logout.php');
    exit;
}
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
$nonce = base64_encode(random_bytes(16));
$csp = "default-src 'self'; " .
       "img-src 'self' data: https:; " .
       "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
       "style-src 'self' 'unsafe-inline'; " .
       "font-src 'self'; " .
       "connect-src 'self'; " .
       "frame-ancestors 'none';";
header("Content-Security-Policy: " . $csp);
$stmt = db()->prepare('SELECT * FROM cards WHERE user_id = ? LIMIT 1');
$stmt->execute([$user_id]);
$card = $stmt->fetch() ?: ['name'=>'', 'title'=>'', 'links'=>'', 'logo'=>''];
function sanitizeColor($color, $default = '#ffffff') {
    // Permitir solo formato hexadecimal válido
    if (preg_match('/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/', $color)) {
        return $color;
    }
    return $default;
}
$cardBgColor = sanitizeColor($card['background_color'] ?? '#ffffff');
$cardTextColor = sanitizeColor($card['text_color'] ?? '#333333');
$cardBtnColor = sanitizeColor($card['button_color'] ?? '#4a6cf7');
$cardBtnTextColor = sanitizeColor($card['button_text_color'] ?? getContrastColor($card['button_color'] ?? '#4a6cf7'));
$cardBgImage = $card['background_image'] ?? '';
if (!empty($cardBgImage)) {
    // Verificar si es base64
    if (strpos($cardBgImage, 'data:image') === 0) {
        // Validar formato base64 seguro
        if (!preg_match('/^data:image\/(png|jpeg|jpg|gif);base64,[A-Za-z0-9+\/=]+$/', $cardBgImage)) {
            $cardBgImage = ''; // Invalidar si no cumple
            error_log("Base64 inválido detectado - Usuario: $user_id");
        }
    }
    // Verificar si es URL externa
    else if (strpos($cardBgImage, 'http://') === 0 || strpos($cardBgImage, 'https://') === 0) {
        // Validar URL segura
        $parsed = parse_url($cardBgImage);
        if (!$parsed || !filter_var($cardBgImage, FILTER_VALIDATE_URL)) {
            $cardBgImage = '';
            error_log("URL externa inválida - Usuario: $user_id");
        }
        // Limitar a protocolos seguros
        else if ($parsed['scheme'] !== 'https' && $parsed['scheme'] !== 'http') {
            $cardBgImage = '';
        }
    }
    // Ruta local
    else {
        // PREVENIR PATH TRAVERSAL
        $cardBgImage = preg_replace('/\.\.\//', '', $cardBgImage); // Eliminar ../ 
        $cardBgImage = preg_replace('/\.\.\\\\/', '', $cardBgImage); // Eliminar ..\
        $cardBgImage = ltrim($cardBgImage, '/'); // Eliminar slash inicial
        
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
            error_log("Ruta no permitida: $cardBgImage - Usuario: $user_id");
        } else {
            // Construir ruta segura
            $cardBgImage = '/qlikmeapp/' . htmlspecialchars($cardBgImage, ENT_QUOTES, 'UTF-8');
            
            // Verificar existencia (opcional, pero segura)
            $local_path = $_SERVER['DOCUMENT_ROOT'] . parse_url($cardBgImage, PHP_URL_PATH);
            if (!file_exists($local_path)) {
                // Solo log, no mostrar error al usuario
                error_log("Archivo no encontrado: $local_path");
            }
        }
    }
}
$links = [];
if (!empty($card['links'])) {
    $decoded = json_decode($card['links'], true);
    if (is_array($decoded)) {
        foreach ($decoded as $link) {
            // Validar cada enlace
            if (isset($link['label'], $link['url'])) {
                // Sanitizar label (solo texto básico)
                $clean_label = preg_replace('/[^\p{L}\p{N}\s\-_.,@]/u', '', $link['label']);
                $clean_label = substr($clean_label, 0, 100); // Limitar longitud
                
                // Validar URL - PERMITIR tel: y otros protocolos
                $clean_url = filter_var($link['url'], FILTER_SANITIZE_URL);
                
                // Validación especial para tel:
                if (strpos($clean_url, 'tel:') === 0) {
                    // Validar formato básico de teléfono
                    $phone_part = substr($clean_url, 4);
                    if (preg_match('/^\+?[\d\s\(\)\-]{7,}$/', $phone_part)) {
                        $links[] = [
                            'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                            'url' => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                        ];
                        continue;
                    }
                }
                
                // Para otras URLs, usar validación normal
                if (filter_var($clean_url, FILTER_VALIDATE_URL)) {
                    // Protocolos permitidos
                    $allowed_protocols = ['http:', 'https:', 'mailto:', 'tel:', 'whatsapp:'];
                    $parsed = parse_url($clean_url);
                    if ($parsed && isset($parsed['scheme']) && in_array($parsed['scheme'] . ':', $allowed_protocols)) {
                        $links[] = [
                            'label' => htmlspecialchars($clean_label, ENT_QUOTES, 'UTF-8'),
                            'url' => htmlspecialchars($clean_url, ENT_QUOTES, 'UTF-8')
                        ];
                    }
                }
            }
        }
    }
}
$token = csrf_token();
$base_url = '/qlikmeapp/';
function safe($arr, $i, $key, $default = '') {
    if (!is_array($arr) || !isset($arr[$i])) {
        return $default;
    }
    $value = $arr[$i][$key] ?? $default;
    // Sanitizar según contexto
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
function getContrastColor($hexcolor) {
    $hexcolor = preg_replace('/[^A-Fa-f0-9]/', '', $hexcolor); // Solo hex
    if (strlen($hexcolor) == 3) {
        $hexcolor = $hexcolor[0] . $hexcolor[0] . $hexcolor[1] . $hexcolor[1] . $hexcolor[2] . $hexcolor[2];
    }
    
    if (strlen($hexcolor) != 6) {
        return '#000000'; // Default
    }
    
    $r = hexdec(substr($hexcolor, 0, 2));
    $g = hexdec(substr($hexcolor, 2, 2));
    $b = hexdec(substr($hexcolor, 4, 2));
    
    $yiq = (($r * 299) + ($g * 587) + ($b * 114)) / 1000;
    
    return ($yiq >= 128) ? '#000000' : '#ffffff';
}
require_once __DIR__ . '/../src/libs/phpqrcode/qrlib.php';
$allowed_domains = ['app.datamapworks.com.mx', 'tudominio.com'];
$current_domain = parse_url($_SERVER['HTTP_HOST'] ?? '', PHP_URL_HOST);
$domain = in_array($current_domain, $allowed_domains) ? $current_domain : $allowed_domains[0];
$cardUrl = "https://{$domain}/qlikmeapp/public/u/index.php?user=" . urlencode($user_id);
// Generar QR
ob_start();
QRcode::png($cardUrl, null, QR_ECLEVEL_L, 4, 2);
$qrImage = ob_get_contents();
ob_end_clean();
$qrBase64 = base64_encode($qrImage);
$max_links = 6;
$links = array_slice($links, 0, $max_links);
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Dashboard - Mi Tarjeta Digital</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="icon" type="image/svg+xml" href="https://app.datamapworks.com.mx/qlikmeapp/public/logo-qlikme-recortado.png">
    <!-- Agregar SortableJS con integridad -->
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
    <link rel="stylesheet" href="/qlikmeapp/assets/css/dashboard.css">
</head>
<body>
<header>
    <h1>Qlikme — Panel</h1>
    <div class="actions">
        <a href="/qlikmeapp/public/u/index.php?user=<?= urlencode($user_id) ?>" target="_blank" rel="noopener noreferrer">Ver mi tarjeta</a>
        <a href="logout.php">Cerrar sesión</a>
    </div>
</header>
<main>
    <h2>Editar mi tarjeta digital</h2>
    <div class="grid">
        <!-- LEFT: form -->
        <div class="panel">
            <form id="cardForm" method="post" action="save_card.php" enctype="multipart/form-data">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
                <!-- Campo oculto para guardar el orden -->
                <input type="hidden" name="links_order" id="linksOrder" value="">

                <label>Nombre</label>
                <input name="name" type="text" 
                       value="<?= htmlspecialchars($card['name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" 
                       required
                       maxlength="100"
                       pattern="[\p{L}\p{N}\s\-_.,@]+"
                       title="Solo letras, números y espacios básicos">

                <label>Título / Puesto</label>
                <input name="title" type="text" 
                       value="<?= htmlspecialchars($card['title'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                       maxlength="100">

                <label>Logo (PNG/JPG máx 500KB)</label>
                <input type="file" name="logo" accept=".png,.jpg,.jpeg" onchange="validateImage(this, 5000)">
                <?php 
                if (!empty($card['logo'])): 
                    $logo_path = preg_replace('/\.\.\//', '', $card['logo']);
                    $logo_url = $base_url . htmlspecialchars($logo_path, ENT_QUOTES, 'UTF-8');
                ?>
                    <div>
                        <img src="<?= $logo_url ?>" 
                         alt="Logo actual" 
                         class="logo-preview"
                         onerror="this.style.display='none'">
                        <div style="margin-top:8px"><label><input type="checkbox" name="remove_logo" value="1"> Eliminar logo actual</label></div>
                    </div>
                <?php else: ?>
                    <div class="muted">No hay logo cargado</div>
                <?php endif; ?>

                <div style="height:14px"></div>

                <label>Enlaces (máx 6) - <span style="color:var(--primary)">Arrastra para reordenar</span></label>
                <div class="slots" id="slots">
                    <?php
                    // If there are existing links, map them into slots; otherwise create empty slots up to up to 3 visible and rest empty
                    $existing = $links;
                    $countExisting = count($existing);
                    $initialSlots = max(3, min(6, $countExisting));
                    for ($i = 0; $i < $initialSlots; $i++):
                        $lab = safe($existing, $i, 'label', '');
                        $url = safe($existing, $i, 'url', '');
                    ?>
                        <div class="slot" data-index="<?= $i ?>">
                            <div class="slot-head">
                                <div style="display:flex; align-items:center;">
                                    <div class="drag-handle" title="Arrastrar para reordenar">☰</div>
                                    <div class="slot-index">Enlace <?= $i+1 ?></div>
                                </div>
                                <button type="button" class="remove-btn" title="Eliminar" onclick="removeSlot(this)">×</button>
                            </div>

                            <div class="row">
                                <select class="type-select small" data-index="<?= $i ?>">
                                    <option value="custom">Personalizado</option>
                                    <option value="website">Sitio web</option>
                                    <option value="whatsapp">WhatsApp</option>
                                    <option value="instagram">Instagram</option>
                                    <option value="x">X (Twitter)</option>
                                    <option value="linkedin">LinkedIn</option>
                                    <option value="email">Correo</option>
                                    <option value="phone">Teléfono</option>
                                </select>

                                <input name="label[]" class="label-input" 
                                       placeholder="Etiqueta (ej. Contácto)" 
                                       value="<?= $lab ?>"
                                       maxlength="100">
                            </div>

                            <div class="type-fields" style="margin-top:6px">
                                <!-- website -->
                                <div class="fields-website" style="display:none">
                                    <label class="muted">URL del sitio</label>
                                    <input type="url" class="input-website" placeholder="https://midominio.com">
                                </div>

                                <!-- whatsapp -->
                                <div class="fields-whatsapp" style="display:none">
                                    <label class="muted">Número (ej. 5215512345678)</label>
                                    <input type="text" class="input-whatsapp-phone" placeholder="5215512345678" pattern="\d{10,15}">
                                    <label class="muted">Mensaje</label>
                                    <input type="text" class="input-whatsapp-msg" placeholder="Hola, me interesa..." maxlength="500">
                                </div>

                                <!-- instagram -->
                                <div class="fields-instagram" style="display:none">
                                    <label class="muted">Usuario Instagram (sin @)</label>
                                    <input type="text" class="input-instagram" placeholder="miusuario" pattern="[a-zA-Z0-9._]+">
                                </div>

                                <!-- x -->
                                <div class="fields-x" style="display:none">
                                    <label class="muted">Usuario X (sin @)</label>
                                    <input type="text" class="input-x" placeholder="miusuario" pattern="[a-zA-Z0-9_]+">
                                </div>

                                <!-- linkedin -->
                                <div class="fields-linkedin" style="display:none">
                                    <label class="muted">URL pública de LinkedIn</label>
                                    <input type="url" class="input-linkedin" placeholder="https://www.linkedin.com/in/tu-perfil/">
                                </div>

                                <!-- email -->
                                <div class="fields-email" style="display:none">
                                    <label class="muted">Correo</label>
                                    <input type="email" class="input-email" placeholder="nombre@dominio.com">
                                    <label class="muted">Asunto (opcional)</label>
                                    <input type="text" class="input-email-subject" placeholder="Asunto" maxlength="200">
                                </div>

                                <!-- phone -->
                                <div class="fields-phone" style="display:none">
                                    <label class="muted">Número telefónico</label>
                                    <input type="text" class="input-phone" placeholder="+52 55 1234 5678" pattern="[\d\s\(\)\+\-]{7,}">
                                </div>

                                <!-- custom -->
                                <div class="fields-custom" style="display:none">
                                    <label class="muted">URL personalizada</label>
                                    <input type="url" class="input-custom-url readonly-url" placeholder="https://..." >
                                </div>
                            </div>

                            <!-- CAMBIO: Input oculto para guardar la URL, pero visible para debugging -->
                            <input type="hidden" name="url[]" class="url-input" value="<?= $url ?>">
                            
                            <!-- Agregamos un pequeño indicador visual para mostrar qué URL se guardará -->
                            <div class="hint muted" style="margin-top: 8px; font-size: 12px; padding: 6px; background: #f8f9fa; border-radius: 6px;">
                                <strong>URL que se guardará:</strong>
                                <span class="url-preview" style="display: block; margin-top: 4px; font-family: monospace; font-size: 11px; color: #666; word-break: break-all;">
                                    <?= htmlspecialchars($url ?: 'Se generará automáticamente', ENT_QUOTES, 'UTF-8') ?>
                                </span>
                                <small style="display: block; margin-top: 4px; color: #999;">Esta URL se enviará al servidor automáticamente</small>
                            </div>
                        </div>
                    <?php endfor; ?>

                </div>

                <div style="margin-top:12px; display:flex; gap:10px; align-items:center">
                    <button type="button" id="addBtn" class="add-link">+ Añadir enlace</button>
                    <div class="muted" style="font-size:13px">Máximo 6 enlaces</div>
                </div>

                <div class="actions">
                    <button type="button" class="btn-secondary" id="clearAll">Limpiar</button>
                    <button type="submit" class="btn-save">💾 Guardar cambios</button>
                </div>
            </form>
        </div>
        <!-- RIGHT: preview -->
        <div class="panel preview">
            <div style="display:flex; flex-direction:column; align-items:center">
                <?php 
                if (!empty($card['logo'])): 
                    $logo_path = preg_replace('/\.\.\//', '', $card['logo']);
                    $logo_url = $base_url . htmlspecialchars($logo_path, ENT_QUOTES, 'UTF-8');
                ?>
                    <img src="<?= $logo_url ?>" alt="Logo actual" class="logo-preview" data-handle-error>
                    <div style="width:120px;height:120px;border-radius:12px;background:#f3f6ff;display:none;align-items:center;justify-content:center;color:var(--text-muted);font-weight:700">
                        SIN LOGO
                    </div>
                <?php else: ?>
                    <div style="width:120px;height:120px;border-radius:12px;background:#f3f6ff;display:flex;align-items:center;justify-content:center;color:var(--text-muted);font-weight:700">
                        SIN LOGO
                    </div>
                <?php endif; ?>
                <h4><?= htmlspecialchars($card['name'] ?: 'Tu nombre', ENT_QUOTES, 'UTF-8') ?></h4>
                <p class="muted"><?= htmlspecialchars($card['title'] ?? 'Tu puesto', ENT_QUOTES, 'UTF-8') ?></p>

                <!-- Contenedor de enlaces -->
                <div id="preview-links" class="links-container" style="width:100%; margin-top:12px">
                    <?php if (!empty($card['links'])): ?>
                        <?php 
                        $links = json_decode($card['links'], true);
                        if (is_array($links)): 
                            foreach ($links as $link): 
                                if (isset($link['label'], $link['url'])):
                        ?>
                            <a href="<?= htmlspecialchars($link['url'], ENT_QUOTES, 'UTF-8') ?>" 
                               target="_blank" 
                               rel="noopener noreferrer"
                               class="link-button"
                               style="background: <?= $cardBtnColor ?>; color: <?= $cardBtnTextColor ?>;">
                                <?= htmlspecialchars($link['label'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                            </a>
                        <?php 
                                endif;
                            endforeach; 
                        endif; 
                        ?>
                    <?php endif; ?>
                </div>

                <a class="btn" id="preview-open" href="/qlikmeapp/public/u/index.php?user=<?= urlencode($user_id) ?>" target="_blank" rel="noopener noreferrer">Abrir tarjeta pública</a>
                
                <!-- Código QR con botones -->
                <div style="margin-top: 12px; text-align: center;">
                    <img 
                        id="qrImage"
                        src="data:image/png;base64,<?= $qrBase64 ?>"
                        alt="QR de la tarjeta"
                        style="width: 120px; height: 120px; border: 1px solid #ddd; padding: 8px; background: white; border-radius: 8px;">
                    <p class="hint muted" style="margin-top: 8px; font-size: 12px;">Escanea para ver la tarjeta</p>
                    
                    <!-- Botones de Descargar QR y Compartir -->
                    <div class="qr-buttons">
                        <button id="downloadQR" class="qr-btn secondary">
                            📥 Descargar QR
                        </button>
                        <button id="shareCard" class="qr-btn">
                            🔗 Compartir
                        </button>
                    </div>
                    
                    <!-- Controles de impresión -->
                    <div style="margin-top:10px; text-align:center;">
                        <label for="printOrientation" class="muted" style="display:block; margin-bottom:8px; font-size:13px;">Orientación:</label>
                        <select id="printOrientation" style="padding:8px 10px; border-radius:8px; border:1px solid #e6e9f2; margin-bottom:10px;">
                            <option value="horizontal">Horizontal (85 × 55 mm)</option>
                            <option value="vertical">Vertical (55 × 85 mm)</option>
                        </select>
                        <label for="cardsPerPage" class="muted" style="display:block; margin-bottom:8px; font-size:13px; margin-top:10px;">Tarjetas por hoja:</label>
                        <select id="cardsPerPage" style="padding:8px 10px; border-radius:8px; border:1px solid #e6e9f2; margin-bottom:10px;">
                            <option value="1">1 tarjeta</option>
                            <option value="2">2 tarjetas</option>
                            <option value="4">4 tarjetas</option>
                            <option value="8">8 tarjetas</option>
                            <option value="10">10 tarjetas</option>
                        </select>
                        <div>
                            <button id="printCard" class="qr-btn" style="margin-top:8px;">
                                🖨️ Imprimir tarjeta (preimpresión)
                            </button>
                        </div>
                    </div>
                </div>
                <div class="hint muted">Los cambios se verán al guardar.</div>
                <!-- Panel de personalización de la tarjeta -->
                <div class="personalization-panel">
                    <h4 style="margin-top: 0; margin-bottom: 16px;">Personalizar Tarjeta</h4>
                    
                    <div class="personalization-controls">
                        <!-- Selector de color de fondo -->
                        <div class="control-group" style="margin-bottom: 12px;">
                            <label style="display: block; margin-bottom: 6px; font-size: 13px; font-weight: 500;">
                                Color de fondo:
                            </label>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <input type="color" id="cardBgColor" value="<?= htmlspecialchars($cardBgColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="width: 40px; height: 40px; border: none; border-radius:8px; cursor: pointer;">
                                <input type="text" id="cardBgColorText" value="<?= htmlspecialchars($cardBgColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="flex: 1; padding: 8px 12px; border: 1px solid #e6e9f2; border-radius:8px; font-size: 13px;" pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$">
                                <button type="button" id="resetBgColor" class="reset-btn" style="padding: 8px 12px; background: #f3f6ff; border: 1px solid #e6e9f2; border-radius:8px; cursor: pointer;">
                                    Restablecer
                                </button>
                            </div>
                        </div>
                        
                        <!-- Selector de color de texto -->
                        <div class="control-group" style="margin-bottom: 12px;">
                            <label style="display: block; margin-bottom: 6px; font-size: 13px; font-weight: 500;">
                                Color de texto:
                            </label>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <input type="color" id="cardTextColor" value="<?= htmlspecialchars($cardTextColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="width: 40px; height: 40px; border: none; border-radius:8px; cursor: pointer;">
                                <input type="text" id="cardTextColorText" value="<?= htmlspecialchars($cardTextColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="flex: 1; padding: 8px 12px; border: 1px solid #e6e9f2; border-radius:8px; font-size: 13px;" pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$">
                                <button type="button" id="resetTextColor" class="reset-btn" style="padding: 8px 12px; background: #f3f6ff; border: 1px solid #e6e9f2; border-radius:8px; cursor: pointer;">
                                    Restablecer
                                </button>
                            </div>
                        </div>
                        
                        <!-- Selector de color de botones -->
                        <div class="control-group" style="margin-bottom: 12px;">
                            <label style="display: block; margin-bottom: 6px; font-size: 13px; font-weight: 500;">
                                Color de botones:
                            </label>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <input type="color" id="cardBtnColor" value="<?= htmlspecialchars($cardBtnColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="width: 40px; height: 40px; border: none; border-radius:8px; cursor: pointer;">
                                <input type="text" id="cardBtnColorText" value="<?= htmlspecialchars($cardBtnColor, ENT_QUOTES, 'UTF-8') ?>" 
                                       style="flex: 1; padding: 8px 12px; border: 1px solid #e6e9f2; border-radius:8px; font-size: 13px;" pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$">
                                <button type="button" id="resetBtnColor" class="reset-btn" style="padding: 8px 12px; background: #f3f6ff; border: 1px solid #e6e9f2; border-radius:8px; cursor: pointer;">
                                    Restablecer
                                </button>
                            </div>
                        </div>
                        
                        <!-- Selector de imagen de fondo -->
                        <div class="control-group" style="margin-bottom: 16px;">
                            <label style="display: block; margin-bottom: 6px; font-size: 13px; font-weight: 500;">
                                Imagen de fondo:
                            </label>
                            <div style="display: flex; flex-direction: column; gap: 8px;">
                                <input type="file" id="cardBgImage" accept=".png,.jpg,.jpeg">
                                <div style="display: flex; gap: 8px;">
                                    <button type="button" id="previewBgImage" class="action-btn" style="flex: 1; padding: 8px 12px; background: #4a6cf7; color: white; border: none; border-radius:8px; cursor: pointer;">
                                        Vista previa
                                    </button>
                                    <button type="button" id="removeBgImage" class="action-btn secondary" style="flex: 1; padding: 8px 12px; background: #f3f6ff; border: 1px solid #e6e9f2; border-radius:8px; cursor: pointer; color: #000;">
                                        Eliminar
                                    </button>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Botón de guardar personalización -->
                        <div class="action-buttons" style="display: flex; gap: 8px; margin-top: 16px;">
                            <button type="button" id="saveCustomization" class="action-btn" style="width: 100%; padding: 12px 16px; background: #10b981; color: white; border: none; border-radius:8px; font-weight: 500; cursor: pointer; font-size: 14px;">
                                💾 Guardar personalización
                            </button>
                        </div>
                        
                        <!-- Previsualización de imagen de fondo -->
                        <div id="bgImagePreview" style="margin-top: 12px; display: <?= !empty($cardBgImage) ? 'block' : 'none' ?>;">
                            <p style="font-size: 13px; margin-bottom: 6px;">Vista previa:</p>
                            <div id="previewImageContainer" style="width: 100%; height: 100px; border: 1px dashed #e6e9f2; border-radius:8px; overflow: hidden; background-size: cover; background-position: center; <?= !empty($cardBgImage) ? "background-image: url('" . htmlspecialchars($cardBgImage, ENT_QUOTES, 'UTF-8') . "')" : '' ?>"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</main>
<script nonce="<?= $nonce ?>">
function sanitizeColorCSS(color) {
    if (typeof color !== 'string') return '#4a6cf7';
    if (/^#([A-Fa-f0-9]{3}|[A-Fa-f0-9]{6})$/.test(color)) {
        return color;
    }
    return '#4a6cf7'; // Default seguro
}
function validateImage(input, maxSizeKB) {
    if (input.files && input.files[0]) {
        const file = input.files[0];
        const size = file.size / 1024; // KB
        
        // Validar tipo
        const validTypes = ['image/jpeg', 'image/jpg', 'image/png'];
        if (!validTypes.includes(file.type)) {
            alert('Formato no válido. Solo JPG y PNG.');
            input.value = '';
            return false;
        }
        
        // Validar tamaño
        if (size > maxSizeKB) {
            alert(`El archivo es muy grande. Máximo: ${maxSizeKB}KB`);
            input.value = '';
            return false;
        }
        
        // Validar dimensiones (opcional)
        const img = new Image();
        img.onload = function() {
            if (this.width > 2000 || this.height > 2000) {
                alert('Imagen muy grande. Máximo 2000x2000px');
                input.value = '';
            }
        };
        img.src = URL.createObjectURL(file);
    }
    return true;
}
// Sanitizar entrada de usuario
function sanitizeInput(text) {
    if (typeof text !== 'string') return '';
    return text
        .replace(/<[^>]*>/g, '') // Eliminar HTML
        .replace(/[^\p{L}\p{N}\s\-_.,@:;/?&=+#]/gu, '') // Solo caracteres seguros
        .substring(0, 500); // Limitar longitud
}
// Validar URL - CORREGIDA PARA TEL:
function isValidUrl(string) {
    if (typeof string !== 'string') return false;
    
    // Permitir tel: sin validación estricta de URL
    if (string.startsWith('tel:')) {
        const phoneNumber = string.substring(4);
        // Validar que el número tenga al menos algunos dígitos
        const digitsOnly = phoneNumber.replace(/\D/g, '');
        return digitsOnly.length >= 7;
    }
    
    // Permitir whatsapp: sin validación estricta
    if (string.startsWith('whatsapp:')) {
        return true;
    }
    
    try {
        const url = new URL(string);
        const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'whatsapp:'];
        return allowedProtocols.includes(url.protocol);
    } catch (_) {
        return false;
    }
}
document.addEventListener('DOMContentLoaded', function() {
    // Inicializar panel de personalización
    setTimeout(initPersonalizationPanel, 300);
});
function initPersonalizationPanel() {
    console.log('Inicializando panel de personalización...');
    
    // Referencias a los elementos de la tarjeta de previsualización
    const cardPreview = document.querySelector('.panel.preview');
    
    // Elementos de control
    const bgColorPicker = document.getElementById('cardBgColor');
    const bgColorText = document.getElementById('cardBgColorText');
    const textColorPicker = document.getElementById('cardTextColor');
    const textColorText = document.getElementById('cardTextColorText');
    const btnColorPicker = document.getElementById('cardBtnColor');
    const btnColorText = document.getElementById('cardBtnColorText');
    const bgImageInput = document.getElementById('cardBgImage');
    const previewBgImageBtn = document.getElementById('previewBgImage');
    const removeBgImageBtn = document.getElementById('removeBgImage');
    const saveBtn = document.getElementById('saveCustomization');
    const resetBgColorBtn = document.getElementById('resetBgColor');
    const resetTextColorBtn = document.getElementById('resetTextColor');
    const resetBtnColorBtn = document.getElementById('resetBtnColor');
    const bgImagePreview = document.getElementById('bgImagePreview');
    const previewImageContainer = document.getElementById('previewImageContainer');
    
    // Variable para guardar la imagen de fondo ORIGINAL (desde PHP)
    let originalBackgroundImage = '<?= !empty($cardBgImage) ? htmlspecialchars($cardBgImage, ENT_QUOTES, 'UTF-8') : "" ?>';
    
    // Variable para guardar si hay una imagen NUEVA seleccionada
    let hasNewImage = false;
    let newImageData = '';
    
    // Sincronizar color pickers con inputs de texto y aplicar cambios automáticamente
    bgColorPicker.addEventListener('input', function() {
        bgColorText.value = this.value;
        aplicarCambiosAutomaticos();
    });
    
    bgColorText.addEventListener('input', function() {
        if (bgColorText.value.match(/^#[0-9A-F]{6}$/i)) {
            bgColorPicker.value = bgColorText.value;
            aplicarCambiosAutomaticos();
        }
    });
    
    textColorPicker.addEventListener('input', function() {
        textColorText.value = this.value;
        aplicarCambiosAutomaticos();
    });
    
    textColorText.addEventListener('input', function() {
        if (textColorText.value.match(/^#[0-9A-F]{6}$/i)) {
            textColorPicker.value = textColorText.value;
            aplicarCambiosAutomaticos();
        }
    });
    
    btnColorPicker.addEventListener('input', function() {
        btnColorText.value = this.value;
        aplicarCambiosAutomaticos();
    });
    
    btnColorText.addEventListener('input', function() {
        if (btnColorText.value.match(/^#[0-9A-F]{6}$/i)) {
            btnColorPicker.value = btnColorText.value;
            aplicarCambiosAutomaticos();
        }
    });
    
    // Restablecer color de fondo
    resetBgColorBtn.addEventListener('click', function() {
        bgColorPicker.value = '#ffffff';
        bgColorText.value = '#ffffff';
        aplicarCambiosAutomaticos();
        showNotification('Color de fondo restablecido', 'info');
    });
    
    // Restablecer color de texto
    resetTextColorBtn.addEventListener('click', function() {
        textColorPicker.value = '#333333';
        textColorText.value = '#333333';
        aplicarCambiosAutomaticos();
        showNotification('Color de texto restablecido', 'info');
    });
    
    // Restablecer color de botones
    resetBtnColorBtn.addEventListener('click', function() {
        btnColorPicker.value = '#4a6cf7';
        btnColorText.value = '#4a6cf7';
        aplicarCambiosAutomaticos();
        showNotification('Color de botones restablecido', 'info');
    });
    
    // Vista previa de imagen de fondo
    previewBgImageBtn.addEventListener('click', function() {
        if (bgImageInput.files && bgImageInput.files[0]) {
            // Validar imagen
            const file = bgImageInput.files[0];
            const validTypes = ['image/jpeg', 'image/jpg', 'image/png'];
            
            if (!validTypes.includes(file.type)) {
                showNotification('Formato no válido. Solo JPG y PNG.', 'error');
                return;
            }
            
            if (file.size > 5000 * 1024) {
                showNotification('Imagen demasiado grande. Máximo 500KB.', 'error');
                return;
            }
            
            const reader = new FileReader();
            reader.onload = function(e) {
                // Validar que sea un base64 de imagen válido
                if (!e.target.result.startsWith('data:image/')) {
                    showNotification('Archivo de imagen no válido', 'error');
                    return;
                }
                
                // Guardar el base64 completo
                newImageData = e.target.result;
                previewImageContainer.style.backgroundImage = `url(${newImageData})`;
                bgImagePreview.style.display = 'block';
                hasNewImage = true;
                // Aplicar cambios automáticamente
                aplicarCambiosAutomaticos();
            }
            reader.readAsDataURL(bgImageInput.files[0]);
        } else {
            showNotification('Selecciona una imagen primero', 'info');
        }
    });
    
    // Eliminar imagen de fondo
    removeBgImageBtn.addEventListener('click', function() {
        bgImageInput.value = '';
        previewImageContainer.style.backgroundImage = '';
        bgImagePreview.style.display = 'none';
        hasNewImage = false;
        newImageData = '';
        // Aplicar cambios automáticamente
        aplicarCambiosAutomaticos();
        showNotification('Imagen de fondo eliminada', 'info');
    });
    
    // Función para aplicar cambios automáticamente
    function aplicarCambiosAutomaticos() {
        const bgColor = sanitizeColorCSS(bgColorText.value);
        const textColor = sanitizeColorCSS(textColorText.value);
        const buttonBgColor = sanitizeColorCSS(btnColorText.value);
        const buttonTextColor = getContrastColor(buttonBgColor);
        
        // Aplicar color de texto
        const textElements = cardPreview.querySelectorAll('h4, p, .muted, .hint');
        textElements.forEach(element => {
            element.style.color = textColor;
        });
        
        // Aplicar color de botones
        const allButtons = cardPreview.querySelectorAll('.btn, .qr-btn, button, .link-button');
        allButtons.forEach(button => {
            if (!button.classList.contains('secondary')) {
                button.style.backgroundColor = buttonBgColor;
                button.style.color = buttonTextColor;
            }
        });
        
        // Determinar imagen actual
        let currentBgImage = '';
        if (hasNewImage && newImageData) {
            currentBgImage = newImageData;
        } else if (originalBackgroundImage && !hasNewImage) {
            currentBgImage = originalBackgroundImage;
        }
        
        // Aplicar fondo
        if (currentBgImage) {
            // Sanitizar URL de imagen
            const safeBgImage = currentBgImage.replace(/[<>"']/g, '');
            cardPreview.style.backgroundImage = `url('${safeBgImage}')`;
            cardPreview.style.backgroundSize = 'cover';
            cardPreview.style.backgroundPosition = 'center';
            cardPreview.style.backgroundRepeat = 'no-repeat';
            cardPreview.style.backgroundBlendMode = 'normal';
            
            // Si el color es blanco, usar transparente
            if (bgColor.toLowerCase() === '#ffffff' || bgColor.toLowerCase() === '#fff') {
                cardPreview.style.backgroundColor = 'transparent';
            } else {
                // Aplicar color con transparencia
                cardPreview.style.backgroundColor = bgColor + '80';
            }
        } else {
            // Si no hay imagen, color sólido
            cardPreview.style.backgroundColor = bgColor;
            cardPreview.style.backgroundImage = 'none';
        }
        
        // Guardar referencia para los botones de enlaces
        window.currentButtonColor = buttonBgColor;
        window.currentButtonTextColor = buttonTextColor;
    }
    
    // Guardar cambios (enviar al servidor)
    saveBtn.addEventListener('click', async function() {
        console.log('=== GUARDANDO PERSONALIZACIÓN ===');
        try {
            // Calcular color de contraste
            const buttonBgColor = sanitizeColorCSS(btnColorText.value);
            const buttonTextColor = getContrastColor(buttonBgColor);
            
            // Obtener imagen de fondo
            let backgroundImageData = '';
            
            if (hasNewImage && newImageData) {
                // Validar base64
                if (newImageData.startsWith('data:image/')) {
                    backgroundImageData = newImageData;
                } else {
                    throw new Error('Imagen no válida');
                }
            } else if (originalBackgroundImage && !hasNewImage) {
                // Si no hay imagen nueva pero hay original, mantener la original
                backgroundImageData = originalBackgroundImage;
            }
            
            // Si se hizo clic en "Eliminar" (sin vista previa y sin archivo)
            if (bgImagePreview.style.display === 'none' && !hasNewImage) {
                backgroundImageData = ''; // Enviar cadena vacía para eliminar
            }
            
            // Validar colores
            const bgColor = sanitizeColorCSS(bgColorText.value);
            const textColor = sanitizeColorCSS(textColorText.value);
            const btnColor = sanitizeColorCSS(btnColorText.value);
            
            // Crear datos
            const customizationData = {
                backgroundColor: bgColor,
                textColor: textColor,
                buttonColor: btnColor,
                buttonTextColor: buttonTextColor,
                backgroundImage: backgroundImageData
            };
            
            // Validar datos
            if (!isValidColor(bgColor) || !isValidColor(textColor) || !isValidColor(btnColor)) {
                throw new Error('Colores no válidos');
            }
            
            // Mostrar indicador de carga
            const originalText = saveBtn.textContent;
            saveBtn.textContent = '🔄 Guardando...';
            saveBtn.disabled = true;
            
            // Endpoint
            const endpoint = '/qlikmeapp/src/guardar_personalizacion.php';
            
            // Hacer la petición
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(customizationData)
            });
            
            // Obtener respuesta
            const responseText = await response.text();
            
            // Parsear JSON
            let data;
            try {
                data = JSON.parse(responseText);
            } catch (e) {
                throw new Error('Respuesta del servidor no es JSON válido');
            }
            
            if (data.success) {
                showNotification('✅ ' + data.message, 'success');
                
                // Recargar la página para ver cambios
                setTimeout(() => {
                    location.reload();
                }, 1500);
            } else {
                showNotification('❌ Error: ' + data.message, 'error');
                saveBtn.textContent = originalText;
                saveBtn.disabled = false;
            }
            
        } catch (error) {
            console.error('🔥 Error en la petición:', error);
            showNotification('🔥 Error: ' + error.message, 'error');
            saveBtn.textContent = 'Guardar cambios';
            saveBtn.disabled = false;
        }
    });
    
    // Función para calcular color de contraste para texto
    function getContrastColor(hexcolor) {
        if (!hexcolor) return '#ffffff';
        
        hexcolor = hexcolor.replace("#", "");
        
        if (hexcolor.length === 3) {
            hexcolor = hexcolor[0] + hexcolor[0] + hexcolor[1] + hexcolor[1] + hexcolor[2] + hexcolor[2];
        }
        
        if (!/^[0-9A-F]{6}$/i.test(hexcolor)) {
            return '#000000';
        }
        
        const r = parseInt(hexcolor.substr(0, 2), 16);
        const g = parseInt(hexcolor.substr(2, 2), 16);
        const b = parseInt(hexcolor.substr(4, 2), 16);
        const yiq = ((r * 299) + (g * 587) + (b * 114)) / 1000;
        return (yiq >= 128) ? '#000000' : '#ffffff';
    }
    
    // Función para validar color
    function isValidColor(color) {
        return /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color);
    }
    
    // Función para mostrar notificaciones
    function showNotification(message, type) {
        const existingNotif = document.querySelector('.custom-notification');
        if (existingNotif) existingNotif.remove();
        
        const notification = document.createElement('div');
        notification.className = 'custom-notification';
        notification.textContent = sanitizeInput(message);
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
            color: white;
            border-radius: 8px;
            z-index: 9999;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: slideIn 0.3s ease;
            font-family: inherit;
            font-size: 14px;
            max-width: 300px;
            word-break: break-word;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
    
    // Aplicar cambios iniciales
    aplicarCambiosAutomaticos();
    
    console.log('Panel de personalización inicializado correctamente');
}
function createSlotElement(index, labelValue = '', urlValue = '') {
    const wrapper = document.createElement('div');
    wrapper.className = 'slot';
    wrapper.setAttribute('data-index', index);
    
    // Sanitizar valores
    const safeLabel = sanitizeInput(labelValue);
    const safeUrl = isValidUrl(urlValue) ? urlValue : '';
    
    wrapper.innerHTML = `
        <div class="slot-head">
            <div style="display:flex; align-items:center;">
                <div class="drag-handle" title="Arrastrar para reordenar">☰</div>
                <div class="slot-index">Enlace ${index+1}</div>
            </div>
            <button type="button" class="remove-btn" title="Eliminar" onclick="removeSlot(this)">×</button>
        </div>
        <div class="row">
            <select class="type-select small" data-index="${index}">
                <option value="custom">Personalizado</option>
                <option value="website">Sitio web</option>
                <option value="whatsapp">WhatsApp</option>
                <option value="instagram">Instagram</option>
                <option value="x">X (Twitter)</option>
                <option value="linkedin">LinkedIn</option>
                <option value="email">Correo</option>
                <option value="phone">Teléfono</option>
            </select>
            <input name="label[]" class="label-input" placeholder="Etiqueta (ej. Contácto)" value="${escapeHtml(safeLabel)}" maxlength="100">
        </div>

        <div class="type-fields" style="margin-top:6px">
            <div class="fields-website" style="display:none">
                <label class="muted">URL del sitio</label>
                <input type="url" class="input-website" placeholder="https://midominio.com">
            </div>

            <div class="fields-whatsapp" style="display:none">
                <label class="muted">Número (ej. 5215512345678)</label>
                <input type="text" class="input-whatsapp-phone" placeholder="5215512345678" pattern="\\d{10,15}">
                <label class="muted">Mensaje</label>
                <input type="text" class="input-whatsapp-msg" placeholder="Hola, me interesa..." maxlength="500">
            </div>

            <div class="fields-instagram" style="display:none">
                <label class="muted">Usuario Instagram (sin @)</label>
                <input type="text" class="input-instagram" placeholder="miusuario" pattern="[a-zA-Z0-9._]+">
            </div>

            <div class="fields-x" style="display:none">
                <label class="muted">Usuario X (sin @)</label>
                <input type="text" class="input-x" placeholder="miusuario" pattern="[a-zA-Z0-9_]+">
            </div>

            <div class="fields-linkedin" style="display:none">
                <label class="muted">URL pública de LinkedIn</label>
                <input type="url" class="input-linkedin" placeholder="https://www.linkedin.com/in/tu-perfil/">
            </div>

            <div class="fields-email" style="display:none">
                <label class="muted">Correo</label>
                <input type="email" class="input-email" placeholder="nombre@dominio.com">
                <label class="muted">Asunto (opcional)</label>
                    <input type="text" class="input-email-subject" placeholder="Asunto" maxlength="200">
            </div>

            <div class="fields-phone" style="display:none">
                <label class="muted">Número telefónico</label>
                <input type="text" class="input-phone" placeholder="+52 55 1234 5678" pattern="[\\d\\s\\(\\)\\+\\-]{7,}">
            </div>

            <div class="fields-custom" style="display:none">
                <label class="muted">URL personalizada</label>
                <input type="url" class="input-custom-url readonly-url" placeholder="https://..." >
            </div>
        </div>

        <!-- Input oculto para guardar la URL -->
        <input type="hidden" name="url[]" class="url-input" value="${escapeHtml(safeUrl)}">
        
        <!-- Agregamos un pequeño indicador visual para mostrar qué URL se guardará -->
        <div class="hint muted" style="margin-top: 8px; font-size: 12px; padding: 6px; background: #f8f9fa; border-radius: 6px;">
            <strong>URL que se guardará:</strong>
            <span class="url-preview" style="display: block; margin-top: 4px; font-family: monospace; font-size: 11px; color: #666; word-break: break-all;">
                ${escapeHtml(safeUrl) || 'Se generará automáticamente'}
            </span>
            <small style="display: block; margin-top: 4px; color: #999;">Esta URL se enviará al servidor automáticamente</small>
        </div>
    `;
    return wrapper;
}

/* escape helper para evitar XSS */
function escapeHtml(s) {
    if (!s) return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

/* remove slot */
function removeSlot(btn){
    const slot = btn.closest('.slot');
    if (!slot) return;
    slot.remove();
    updateSlotIndexes();
    updatePreview();
    updateOrderField();
}

/* update slot indexes after reordering */
function updateSlotIndexes() {
    const slots = document.querySelectorAll('.slot');
    slots.forEach((slot, index) => {
        const indexElement = slot.querySelector('.slot-index');
        if (indexElement) {
            indexElement.textContent = `Enlace ${index + 1}`;
        }
        slot.setAttribute('data-index', index);
    });
}

/* update hidden order field */
function updateOrderField() {
    const slots = document.querySelectorAll('.slot');
    const order = Array.from(slots).map(slot => {
        const label = sanitizeInput(slot.querySelector('.label-input').value);
        const url = slot.querySelector('.url-input').value;
        return { label, url };
    });
    document.getElementById('linksOrder').value = JSON.stringify(order);
}

/* detect type from url (best-effort) */
function detectTypeFromUrl(u){
    if (!u) return 'custom';
    try{
        if (u.indexOf('mailto:') === 0) return 'email';
        if (u.indexOf('tel:') === 0) return 'phone';
        if (u.indexOf('whatsapp:') === 0) return 'whatsapp';
        const url = new URL(u);
        const host = url.host.toLowerCase();
        if (host.includes('wa.me') || host.includes('whatsapp')) return 'whatsapp';
        if (host.includes('instagram.com')) return 'instagram';
        if (host.includes('x.com') || host.includes('twitter.com')) return 'x';
        if (host.includes('linkedin.com')) return 'linkedin';
        if (url.protocol === 'http:' || url.protocol === 'https:') return 'website';
    }catch(e){
        // fallback
        if (u.indexOf('mailto:') === 0) return 'email';
        if (u.indexOf('tel:') === 0) return 'phone';
        if (u.indexOf('whatsapp:') === 0) return 'whatsapp';
    }
    return 'custom';
}

/* generate URL based on selected fields for a slot element */
function updateUrlForSlot(slotEl){
    const type = slotEl.querySelector('.type-select').value;
    const urlInput = slotEl.querySelector('.url-input');
    const urlPreview = slotEl.querySelector('.url-preview'); // Nuevo elemento para mostrar
    let generated = '';

    console.log('=== DEBUG: Actualizando URL para slot ===');
    console.log('Tipo seleccionado:', type);

    if (type === 'website'){
        let v = slotEl.querySelector('.input-website').value.trim();
        v = v.replace(/[<>"']/g, ''); // Sanitizar
        if (v && !v.startsWith('http')) {
            v = 'https://' + v;
        }
        generated = v;
    } else if (type === 'whatsapp'){
        const num = (slotEl.querySelector('.input-whatsapp-phone').value || '').replace(/\D/g,'').trim();
        let msg = (slotEl.querySelector('.input-whatsapp-msg').value || '').trim();
        if (num){
            generated = 'https://wa.me/' + num;
            if (msg) generated += '?text=' + encodeURIComponent(msg.substring(0, 500));
        } else generated = '';
    } else if (type === 'instagram'){
        const user = (slotEl.querySelector('.input-instagram').value || '').trim().replace(/^@/,'');
        if (user) generated = 'https://instagram.com/' + encodeURIComponent(user.substring(0, 50));
    } else if (type === 'x'){
        const user = (slotEl.querySelector('.input-x').value || '').trim().replace(/^@/,'');
        if (user) generated = 'https://x.com/' + encodeURIComponent(user.substring(0, 50));
    } else if (type === 'linkedin'){
        const linkedinUrl = (slotEl.querySelector('.input-linkedin').value || '').trim();
        if (linkedinUrl) {
            // Validar que sea una URL de LinkedIn válida
            if (linkedinUrl.includes('linkedin.com/') && (linkedinUrl.startsWith('http://') || linkedinUrl.startsWith('https://'))) {
                generated = linkedinUrl;
            } else {
                // Si el usuario solo puso el path, construir la URL completa
                const cleanPath = linkedinUrl.replace(/^\/+/, '').replace(/[<>"']/g, '');
                generated = 'https://www.linkedin.com/' + cleanPath;
            }
        } else {
            generated = '';
        }
    } else if (type === 'email'){
        const email = (slotEl.querySelector('.input-email').value || '').trim();
        const subj = (slotEl.querySelector('.input-email-subject').value || '').trim();
        if (email){
            generated = 'mailto:' + encodeURIComponent(email);
            if (subj) generated += '?subject=' + encodeURIComponent(subj.substring(0, 200));
        }
    } else if (type === 'phone'){
        const numInput = slotEl.querySelector('.input-phone');
        const num = numInput ? numInput.value || '' : '';
        const cleanNum = num.trim().replace(/\s/g, '');
        
        console.log('DEBUG: Número telefónico crudo:', num);
        console.log('DEBUG: Número limpio:', cleanNum);
        
        if (cleanNum) {
            // Limpiar: permitir solo dígitos, +, espacios y paréntesis
            let finalNum = cleanNum.replace(/[^\d\+\(\)\s\-]/g, '');
            
            console.log('DEBUG: Número después de limpiar caracteres:', finalNum);
            
            // Si no empieza con +, agregar +
            if (!finalNum.startsWith('+')) {
                // Remover cualquier código de país 52 o 1 si no hay +
                finalNum = finalNum.replace(/^52/, '').replace(/^1/, '');
                finalNum = '+' + finalNum.replace(/\D/g, ''); // Solo números después del +
            }
            
            console.log('DEBUG: Número final:', finalNum);
            
            // Validación más flexible
            const digitsOnly = finalNum.replace(/\D/g, '');
            console.log('DEBUG: Dígitos solo:', digitsOnly, 'longitud:', digitsOnly.length);
            
            if (digitsOnly.length >= 7) { // Al menos 7 dígitos (número local)
                generated = 'tel:' + finalNum;
                console.log('DEBUG: URL generada:', generated);
            } else {
                generated = '';
                console.warn('Número telefónico muy corto:', cleanNum, 'dígitos:', digitsOnly.length);
                showNotification('Número telefónico muy corto. Mínimo 7 dígitos.', 'error');
            }
        } else {
            generated = '';
            console.log('DEBUG: Número vacío');
        }
    }

    // Validar URL final
    console.log('DEBUG: URL generada antes de validar:', generated);
    
    if (generated && !isValidUrl(generated)) {
        console.warn('URL no válida generada:', generated);
        if (type !== 'phone' && type !== 'whatsapp') {
            generated = '';
        }
    }
    
    // Actualizar el input hidden
    urlInput.value = generated;
    
    // Actualizar el preview visual
    if (urlPreview) {
        urlPreview.textContent = generated || 'Se generará automáticamente';
        if (generated) {
            urlPreview.style.color = '#10b981'; // Verde para indicar URL válida
            urlPreview.title = generated;
        } else {
            urlPreview.style.color = '#666';
            urlPreview.title = '';
        }
    }
    
    updatePreview();
    updateOrderField();
}

/* show/hide fields for slot according to type */
function showFieldsFor(slotEl, type){
    const map = {
        website: '.fields-website',
        whatsapp: '.fields-whatsapp',
        instagram: '.fields-instagram',
        x: '.fields-x',
        linkedin: '.fields-linkedin',
        email: '.fields-email',
        phone: '.fields-phone',
        custom: '.fields-custom'
    };
    // hide all then show selected
    const containers = slotEl.querySelectorAll('.type-fields > div');
    containers.forEach(d => d.style.display = 'none');
    const sel = slotEl.querySelector(map[type]);
    if (sel) sel.style.display = 'block';

    // readonly control para campo custom
    const customUrlInput = slotEl.querySelector('.input-custom-url');
    if (customUrlInput) {
        customUrlInput.readOnly = (type !== 'custom');
        if (type === 'custom') {
            customUrlInput.classList.remove('readonly-url');
        } else {
            customUrlInput.classList.add('readonly-url');
        }
    }
}

/* init a slot element (attach listeners, try prefill) */
function initSlot(slotEl){
    const select = slotEl.querySelector('.type-select');
    const labelInput = slotEl.querySelector('.label-input');
    const urlInput = slotEl.querySelector('.url-input');
    const urlPreview = slotEl.querySelector('.url-preview');

    // detect type from existing url
    const existing = urlInput.value.trim();
    let detected = existing ? detectTypeFromUrl(existing) : 'custom';
    select.value = detected;
    // prefill type-specific fields from existing url if possible (best-effort)
    try {
        if (existing){
            if (detected === 'whatsapp'){
                const u = new URL(existing);
                const num = u.pathname.replace(/\//g,'') || '';
                const text = u.searchParams.get('text') || '';
                slotEl.querySelector('.input-whatsapp-phone').value = num;
                slotEl.querySelector('.input-whatsapp-msg').value = decodeURIComponent(text || '');
            } else if (detected === 'instagram'){
                const parts = existing.split('/').filter(Boolean);
                slotEl.querySelector('.input-instagram').value = parts.pop() || '';
            } else if (detected === 'x'){
                const parts = existing.split('/').filter(Boolean);
                slotEl.querySelector('.input-x').value = parts.pop() || '';
            } else if (detected === 'linkedin'){
                // Para URLs existentes de LinkedIn, extraer la URL completa
                if (existing.includes('linkedin.com/')) {
                    slotEl.querySelector('.input-linkedin').value = existing;
                } else {
                    // Si no es una URL completa, intentar extraer el path
                    const parts = existing.split('/').filter(Boolean);
                    if (parts.length > 0) {
                        slotEl.querySelector('.input-linkedin').value = 'https://www.linkedin.com/' + parts.join('/');
                    }
                }
            } else if (detected === 'email'){
                if (existing.indexOf('mailto:') === 0){
                    const rest = existing.replace('mailto:','');
                    const mail = rest.split('?')[0];
                    slotEl.querySelector('.input-email').value = decodeURIComponent(mail || '');
                    const q = rest.split('?')[1] || '';
                    const params = new URLSearchParams(q);
                    if (params.get('subject')) slotEl.querySelector('.input-email-subject').value = decodeURIComponent(params.get('subject'));
                }
            } else if (detected === 'phone'){
                if (existing.indexOf('tel:') === 0){
                    const phone = existing.replace('tel:','');
                    slotEl.querySelector('.input-phone').value = decodeURIComponent(phone || '');
                }
            } else if (detected === 'website'){
                slotEl.querySelector('.input-website').value = existing;
            } else {
                slotEl.querySelector('.input-custom-url').value = existing;
            }
        }
    } catch(e){ 
        console.log('Error al prefill:', e);
    }
    
    // Actualizar preview visual inicial
    if (urlPreview) {
        urlPreview.textContent = existing || 'Se generará automáticamente';
        if (existing) {
            urlPreview.style.color = '#10b981';
            urlPreview.title = existing;
        }
    }
    
    // show fields
    showFieldsFor(slotEl, detected);
    // attach select listener
    select.addEventListener('change', function(){
        showFieldsFor(slotEl, this.value);
        updateUrlForSlot(slotEl);
    });
    // attach inputs listeners for auto-generation
    const inputs = slotEl.querySelectorAll('.type-fields input');
    inputs.forEach(inp => {
        inp.addEventListener('input', function(){ updateUrlForSlot(slotEl); });
    });
    // attach label input listener
    labelInput.addEventListener('input', function(){
        updatePreview();
        updateOrderField();
    });
}

/* update preview area on right */
function updatePreview(){
    const preview = document.getElementById('preview-links');
    preview.innerHTML = '';
    const slots = document.querySelectorAll('.slot');
    slots.forEach(s => {
        const label = sanitizeInput(s.querySelector('.label-input').value);
        const url = s.querySelector('.url-input').value.trim();
        if (label && url && isValidUrl(url)){
            const a = document.createElement('a');
            a.href = encodeURI(url);
            a.target = '_blank';
            a.rel = 'noopener noreferrer'; // Prevenir tabnabbing
            a.textContent = label;
            a.className = 'link-button';
            a.style.display = 'block';
            a.style.margin = '6px auto';
            // Aplicar colores actuales si existen
            if (window.currentButtonColor && window.currentButtonTextColor) {
                a.style.backgroundColor = sanitizeColorCSS(window.currentButtonColor);
                a.style.color = sanitizeColorCSS(window.currentButtonTextColor);
            }
            preview.appendChild(a);
        }
    });
}

/* init existing slots rendered from PHP */
document.addEventListener('DOMContentLoaded', function(){
    const slotsContainer = document.getElementById('slots');
    // Initialize Sortable drag & drop
    const sortable = Sortable.create(slotsContainer, {
        handle: '.drag-handle',
        animation: 150,
        ghostClass: 'dragging',
        onEnd: function(evt) {
            updateSlotIndexes();
            updatePreview();
            updateOrderField();
        }
    });
    
    // init each pre-rendered slot
    const existingSlots = slotsContainer.querySelectorAll('.slot');
    existingSlots.forEach(s => initSlot(s));
    
    // attach add behavior
    document.getElementById('addBtn').addEventListener('click', function(){
        const current = slotsContainer.querySelectorAll('.slot').length;
        if (current >= 6) { 
            alert('Máximo 6 enlaces'); 
            return; 
        }
        const slotEl = createSlotElement(current, '', '');
        slotsContainer.appendChild(slotEl);
        initSlot(slotEl);
        updateSlotIndexes();
        updatePreview();
        updateOrderField();
    });
    
    // clear button
    document.getElementById('clearAll').addEventListener('click', function(){
        if (!confirm('¿Limpiar todos los enlaces en pantalla? (No se guardará hasta que presiones Guardar)')) return;
        const nodes = Array.from(document.querySelectorAll('#slots .slot'));
        nodes.forEach(n => n.remove());
        // add a single empty slot
        const s = createSlotElement(0,'','');
        document.getElementById('slots').appendChild(s);
        initSlot(s);
        updatePreview();
        updateOrderField();
    });
    
    // Botones QR - Descargar y Compartir
    const cardUrl = "<?= htmlspecialchars($cardUrl, ENT_QUOTES, 'UTF-8') ?>";
    
    // Descargar QR - VERSIÓN SIMPLIFICADA Y FUNCIONAL
    document.getElementById('downloadQR').addEventListener('click', function() {
        // Método más simple y directo
        try {
            const qrImage = document.getElementById('qrImage');
            const link = document.createElement('a');
            link.href = qrImage.src;
            link.download = 'QR_Tarjeta_Digital.png';
            
            // Agregar al DOM temporalmente
            document.body.appendChild(link);
            link.click();
            
            // Limpiar
            setTimeout(() => {
                document.body.removeChild(link);
            }, 100);
            
            console.log('Descarga de QR iniciada');
        } catch (error) {
            console.error('Error al descargar QR:', error);
            
            // Método alternativo si el anterior falla
            try {
                const link = document.createElement('a');
                link.href = 'data:image/png;base64,<?= $qrBase64 ?>';
                link.download = 'QR_Tarjeta_Digital.png';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            } catch (e) {
                alert('No se pudo descargar el QR. Por favor, haz clic derecho en la imagen y selecciona "Guardar imagen como..."');
            }
        }
    });
    
    // Compartir tarjeta
    document.getElementById('shareCard').addEventListener('click', async function() {
        if (navigator.share) {
            try {
                await navigator.share({
                    title: 'Mi tarjeta digital',
                    text: 'Visita mi tarjeta digital:',
                    url: cardUrl
                });
            } catch (err) {
                console.log('Error al compartir:', err);
                // Fallback
                fallbackShare(cardUrl);
            }
        } else {
            fallbackShare(cardUrl);
        }
    });
    
    function fallbackShare(url) {
        navigator.clipboard.writeText(url).then(function() {
            alert('✅ Enlace copiado al portapapeles: ' + url.substring(0, 50) + '...');
        }).catch(function() {
            alert('📋 Tu navegador no soporta compartir directamente. Copia este enlace:\n' + url);
        });
    }
    
    // Función para mostrar notificaciones (global)
    window.showNotification = function(message, type) {
        const existingNotif = document.querySelector('.custom-notification');
        if (existingNotif) existingNotif.remove();
        
        const notification = document.createElement('div');
        notification.className = 'custom-notification';
        notification.textContent = sanitizeInput(message);
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
            color: white;
            border-radius: 8px;
            z-index: 9999;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: slideIn 0.3s ease;
            font-family: inherit;
            font-size: 14px;
            max-width: 300px;
            word-break: break-word;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 3000);
    };
    
    // ensure preview initially
    updatePreview();
    updateOrderField();
    
    // on form submit, regenerate urls (in case user didn't change fields)
    document.getElementById('cardForm').addEventListener('submit', function(e){
        console.log('=== DEBUG: ENVÍO DE FORMULARIO ===');
        // Validar formulario antes de enviar
        console.log('=== DEBUG: ENVÍO DE FORMULARIO ===');
    
    // Mostrar todos los datos que se enviarán
    const formData = new FormData(this);
    console.log('Datos del formulario:');
    for (let [key, value] of formData.entries()) {
        console.log(`${key}:`, value);
    }
    
    // Mostrar información específica de cada slot
    const slots = document.querySelectorAll('.slot');
    console.log('Total de slots:', slots.length);
    
    slots.forEach((slot, index) => {
        const label = slot.querySelector('.label-input').value;
        const url = slot.querySelector('.url-input').value;
        const type = slot.querySelector('.type-select').value;
        console.log(`Slot ${index}:`, { label, url, type });
    });
        let isValid = true;
        let errorMessage = '';
        
        slots.forEach(slot => {
            const urlInput = slot.querySelector('.url-input');
            const labelInput = slot.querySelector('.label-input');
            const label = labelInput.value.trim();
            const url = urlInput.value.trim();
            
            if (label && !url) {
                isValid = false;
                errorMessage = `Falta URL para el enlace "${label.substring(0, 20)}..."`;
            }
            
            if (url && !isValidUrl(url)) {
                isValid = false;
                errorMessage = `URL no válida en enlace "${label.substring(0, 20)}..."`;
            }
        });
        
        if (!isValid) {
            e.preventDefault();
            alert(errorMessage);
            return false;
        }
        
        // Validar máximo 6 enlaces
        if (slots.length > 6) {
            e.preventDefault();
            alert('Máximo 6 enlaces permitidos');
            return false;
        }
        
        // Regenerar URLs antes de enviar
        slots.forEach(s => updateUrlForSlot(s));
        
        return true;
    });
    
    /* --------------------- Impresión / Preimpresión --------------------- */
    document.getElementById('printCard').addEventListener('click', function() {
        // recoger orientación y cantidad de tarjetas
        const orientation = document.getElementById('printOrientation').value || 'horizontal';
        const cardsPerPage = parseInt(document.getElementById('cardsPerPage').value) || 1;
    
        // datos básicos de la tarjeta desde el DOM
        const name = sanitizeInput((document.querySelector('.preview h4') || { textContent: '' }).textContent.trim());
        const title = sanitizeInput((document.querySelector('.preview p') || { textContent: '' }).textContent.trim());
    
        // logo (si existe en preview)
        const logoEl = document.querySelector('.preview .logo');
        const logoSrc = logoEl ? logoEl.src : '';
    
        // QR (base64 ya generado en PHP)
        const qrBase64 = '<?= $qrBase64 ?>'; // viene desde PHP
    
        // Extraer número de teléfono y correo desde los slots (si existen)
        let phone = '';
        let email = '';
        // search for tel: and mailto: in url-inputs
        document.querySelectorAll('.slot .url-input').forEach(inp => {
            const v = (inp.value || '').trim();
            if (!v) return;
            if (v.indexOf('tel:') === 0 && !phone) {
                phone = sanitizeInput(decodeURIComponent(v.replace('tel:','')));
            } else if (v.indexOf('mailto:') === 0 && !email) {
                const mailPart = v.replace('mailto:','').split('?')[0];
                email = sanitizeInput(decodeURIComponent(mailPart));
            } else {
                // attempt to detect phone in plain numbers
                if (!phone && v.match(/^\+?\d{7,15}$/)) phone = sanitizeInput(v);
            }
        });
    
        // si no hay phone/email desde slots, intenta buscar en botones o preview (best-effort)
        if (!phone) {
            const telLink = document.querySelector('.preview a[href^="tel:"]');
            if (telLink) phone = sanitizeInput(decodeURIComponent(telLink.getAttribute('href').replace('tel:','')));
        }
        if (!email) {
            const mailLink = document.querySelector('.preview a[href^="mailto:"]');
            if (mailLink) {
                const mailPart = mailLink.getAttribute('href').replace('mailto:','').split('?')[0];
                email = sanitizeInput(decodeURIComponent(mailPart));
            }
        }
    
        // Calcular layout basado en cantidad de tarjetas
        const gridConfig = calculateGridLayout(cardsPerPage, orientation);
        
        // construir HTML para impresión en nueva ventana
        const html = generatePrintHTML(orientation, cardsPerPage, gridConfig, {
            name, title, logoSrc, qrBase64, phone, email
        });
    
        // abre ventana y escribe HTML
        const w = window.open('', '_blank', 'toolbar=0,location=0,menubar=0,width=800,height=600');
        if (!w) { 
            alert('Se ha bloqueado la apertura de la ventana. Permite popups para esta página o usa el botón de imprimir del navegador.'); 
            return; 
        }
        
        w.document.open();
        w.document.write(html);
        w.document.close();
    
        // Esperar a que se carguen imágenes y después imprimir
        const tryPrint = () => {
            try {
                w.focus();
                w.print();
            } catch (e) {
                console.error('Error al intentar imprimir', e);
            }
        };
    
        w.onload = function() { setTimeout(tryPrint, 500); };
        setTimeout(tryPrint, 1500);
    });
    
    /* Función para calcular el layout de la cuadrícula */
    function calculateGridLayout(cardsPerPage, orientation) {
        // Dimensiones fijas de tarjeta estándar
        const cardWidth = orientation === 'horizontal' ? 85 : 55;
        const cardHeight = orientation === 'horizontal' ? 55 : 85;
        let cols, rows, cardsPerSheet;
        if (orientation === 'horizontal') {
            switch(cardsPerPage) {
                case 1:
                    cols = 1; rows = 1; cardsPerSheet = 1;
                    break;
                case 2:
                    cols = 2; rows = 1; cardsPerSheet = 2; // 85×2 = 170mm (cabe en 210mm)
                    break;
                case 4:
                    cols = 2; rows = 2; cardsPerSheet = 4; // 85×2 = 170mm × 55×2 = 110mm
                    break;
                case 8:
                    cols = 2; rows = 4; cardsPerSheet = 8; // 85×2 = 170mm × 55×4 = 220mm (necesita 2 páginas)
                    break;
                case 10:
                    cols = 2; rows = 5; cardsPerSheet = 10; // 85×2 = 170mm × 55×5 = 275mm (necesita 2-3 páginas)
                    break;
                default:
                    cols = 1; rows = 1; cardsPerSheet = 1;
            }
        } else {
            switch(cardsPerPage) {
                case 1:
                    cols = 1; rows = 1; cardsPerSheet = 1;
                    break;
                case 2:
                    cols = 2; rows = 1; cardsPerSheet = 2; // 55×2 = 110mm (cabe en 210mm)
                    break;
                case 4:
                    cols = 4; rows = 1; cardsPerSheet = 4; // 55×4 = 220mm (necesita 2 páginas)
                    break;
                case 8:
                    cols = 4; rows = 2; cardsPerSheet = 8; // 55×4 = 220mm × 85×2 = 170mm
                    break;
                case 10:
                    cols = 5; rows = 2; cardsPerSheet = 10; // 55×5 = 275mm × 85×2 = 170mm (necesita 2 páginas)
                    break;
                default:
                    cols = 1; rows = 1; cardsPerSheet = 1;
            }
        }
        return {
            grid: `${cols}x${rows}`,
            cols: cols,
            rows: rows,
            cardWidth: cardWidth + 'mm',
            cardHeight: cardHeight + 'mm',
            cardsPerSheet: cardsPerSheet
        };
    }
    
    /* Función para generar el HTML de impresión */
    function generatePrintHTML(orientation, cardsPerPage, gridConfig, data) {
        const { name, title, logoSrc, qrBase64, phone, email } = data;
        
        // Sanitizar datos
        const safeName = escapeHtml(name);
        const safeTitle = escapeHtml(title);
        const safePhone = escapeHtml(phone);
        const safeEmail = escapeHtml(email);
        
        // Calcular cuántas hojas necesitamos
        const totalSheets = Math.ceil(cardsPerPage / gridConfig.cardsPerSheet);
        
        let sheetsHTML = '';
        
        for (let sheet = 0; sheet < totalSheets; sheet++) {
            const startCard = sheet * gridConfig.cardsPerSheet;
            const endCard = Math.min(startCard + gridConfig.cardsPerSheet, cardsPerPage);
            const cardsThisSheet = endCard - startCard;
            
            let cardsHTML = '';
            for (let i = 0; i < cardsThisSheet; i++) {
                cardsHTML += generateSingleCardHTML(orientation, { 
                    name: safeName, 
                    title: safeTitle, 
                    logoSrc, 
                    qrBase64, 
                    phone: safePhone, 
                    email: safeEmail 
                });
            }
            
            sheetsHTML += `
            <div class="sheet ${sheet > 0 ? 'page-break' : ''}">
                <div class="print-container">
                    <div class="cards-grid" style="
                        grid-template-columns: repeat(${gridConfig.cols}, 1fr);
                        grid-template-rows: repeat(${gridConfig.rows}, 1fr);
                    ">
                        ${cardsHTML}
                    </div>
                    <div class="print-info">
                        Página ${sheet + 1} de ${totalSheets} • ${cardsThisSheet} tarjetas • ${orientation} • ${new Date().toLocaleDateString()}
                    </div>
                </div>
            </div>
            `;
        }
        
        return `
    <!doctype html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>Imprimir ${cardsPerPage} Tarjetas</title>
    <link rel="stylesheet" href="/qlikmeapp/assets/css/dashboard1.css">
    </head>
    <body>
        ${sheetsHTML}
    </body>
    </html>
        `;
    }
    
    /* Función para generar una sola tarjeta */
    function generateSingleCardHTML(orientation, data) {
        const { name, title, logoSrc, qrBase64, phone, email } = data;
        if (orientation === 'horizontal') {
            return `
    <div class="card horizontal">
        <div class="card-content">
            <div class="left-section">
                ${logoSrc ? `<img class="logo" src="${escapeHtml(logoSrc)}" alt="logo" onerror="this.style.display='none'">` : ''}
                <div class="meta">
                    <div class="name">${safeName}</div>
                    <div class="title">${safeTitle}</div>
                    <div class="contacts">
                        ${phone ? `<div>📞 ${safePhone}</div>` : ''}
                        ${email ? `<div>✉️ ${safeEmail}</div>` : ''}
                    </div>
                </div>
            </div>
            <img class="qr" src="data:image/png;base64,${qrBase64}" alt="QR">
        </div>
    </div>
            `;
        } else {
            return `
    <div class="card vertical">
        <div class="logo-section">
            ${logoSrc ? `<img class="logo" src="${escapeHtml(logoSrc)}" alt="logo" onerror="this.style.display='none'">` : ''}
            <div class="name">${safeName}</div>
            <div class="title">${safeTitle}</div>
        </div>
        <div class="contacts-section">
            <div class="contacts">
                ${phone ? `<div>📞 ${safePhone}</div>` : ''}
                ${email ? `<div>✉️ ${safeEmail}</div>` : ''}
            </div>
        </div>
        <div class="qr-section">
            <img class="qr" src="data:image/png;base64,${qrBase64}" alt="QR">
        </div>
    </div>
            `;
        }
    }
});
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('img[data-handle-error]').forEach(img => {
        img.addEventListener('error', function() {
            this.style.display = 'none';
        });
    });
});
</script>
</body>
</html>