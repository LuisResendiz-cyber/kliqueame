<?php
// ============================================
// ARCHIVO COMPLETO PARA GUARDAR PERSONALIZACIÓN
// ============================================

// Configuración
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

// Iniciar buffer para capturar errores
ob_start();

// Si es GET, mostrar info (solo para debug)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    ob_end_clean();
    echo '<!DOCTYPE html>
    <html>
    <head><title>Endpoint Personalización</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h1>✅ Endpoint funcionando</h1>
        <p>PHP Version: ' . PHP_VERSION . '</p>
        <p>Archivo: ' . basename(__FILE__) . '</p>
        <p>Listo para recibir peticiones POST</p>
    </body>
    </html>';
    exit;
}

// Solo procesar POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ob_end_clean();
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Método no permitido']);
    exit;
}

// ============================================
// CONEXIÓN A LA BASE DE DATOS Y AUTENTICACIÓN
// ============================================

try {
    // Incluir bootstrap
    require_once __DIR__ . '/bootstrap.php';
    
    // Verificar autenticación
    if (!authUser()) {
        ob_end_clean();
        header('Content-Type: application/json');
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'No autorizado']);
        exit;
    }
    
    $user_id = authUser();
    
    // Obtener conexión a la base de datos
    $pdo = db();
    
    // ============================================
    // PROCESAR DATOS DE ENTRADA (JSON)
    // ============================================
    
    // Obtener datos JSON
    $jsonInput = file_get_contents('php://input');
    
    if (empty($jsonInput)) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'No se recibieron datos JSON']);
        exit;
    }
    
    $data = json_decode($jsonInput, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'JSON inválido']);
        exit;
    }
    
    // Validar campos requeridos
    if (empty($data['backgroundColor']) || empty($data['textColor']) || empty($data['buttonColor'])) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Faltan campos requeridos']);
        exit;
    }
    
    // Sanitizar datos de colores
    $backgroundColor = substr(trim($data['backgroundColor']), 0, 7);
    $textColor = substr(trim($data['textColor']), 0, 7);
    $buttonColor = substr(trim($data['buttonColor']), 0, 7);
    $buttonTextColor = isset($data['buttonTextColor']) ? substr(trim($data['buttonTextColor']), 0, 7) : '#ffffff';
    
    // ============================================
    // MANEJO DE IMAGEN DE FONDO (IGUAL QUE EL LOGO)
    // ============================================
    
    $backgroundImagePath = null;
    
    // Verificar si hay imagen de fondo en base64
    if (isset($data['backgroundImage']) && !empty($data['backgroundImage'])) {
        $backgroundImageData = $data['backgroundImage'];
        
        // Si es base64 (data:image/...), procesarla como archivo
        if (strpos($backgroundImageData, 'data:image') === 0) {
            // Extraer datos base64
            $base64Parts = explode(',', $backgroundImageData);
            if (count($base64Parts) !== 2) {
                throw new Exception('Formato base64 inválido');
            }
            
            $imageData = $base64Parts[1];
            $imageBinary = base64_decode($imageData);
            
            if ($imageBinary === false) {
                throw new Exception('Error decodificando imagen base64');
            }
            
            // Obtener información MIME del header base64
            $mimeHeader = explode(':', $base64Parts[0])[1] ?? '';
            $mimeHeader = explode(';', $mimeHeader)[0] ?? '';
            
            // Determinar extensión basada en el tipo MIME
            $extension = '.png'; // por defecto
            if (strpos($mimeHeader, 'jpeg') !== false) {
                $extension = '.jpg';
            } elseif (strpos($mimeHeader, 'png') !== false) {
                $extension = '.png';
            } elseif (strpos($mimeHeader, 'gif') !== false) {
                $extension = '.gif';
            } elseif (strpos($mimeHeader, 'webp') !== false) {
                $extension = '.webp';
            }
            
            // Generar nombre único (IGUAL QUE save_card.php)
            $safe = bin2hex(random_bytes(8)) . $extension;
            $target_dir = __DIR__ . '/../uploads/';
            
            // Crear directorio si no existe (IGUAL QUE save_card.php)
            if (!is_dir($target_dir)) {
                mkdir($target_dir, 0755, true);
            }
            
            $dest = $target_dir . $safe;
            
            // Guardar el archivo
            $bytesWritten = file_put_contents($dest, $imageBinary);
            if ($bytesWritten === false || $bytesWritten === 0) {
                throw new Exception('Error guardando imagen en el servidor');
            }
            
            // Verificar si el archivo es una imagen válida (IGUAL QUE save_card.php)
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $dest);
            finfo_close($finfo);
            
            // Mismos tipos MIME permitidos que en save_card.php
            $allowedMimes = ['image/png', 'image/jpeg', 'image/gif'];
            if (!in_array($mime, $allowedMimes)) {
                // Eliminar archivo no válido
                unlink($dest);
                throw new Exception('Tipo de imagen no permitido. Solo PNG, JPEG y GIF.');
            }
            
            $backgroundImagePath = 'uploads/' . $safe;
            
        } 
        // Si es URL, guardarla tal cual
        elseif (filter_var($backgroundImageData, FILTER_VALIDATE_URL)) {
            $backgroundImagePath = $backgroundImageData;
        }
        // Si es string vacío, marcar para eliminar imagen existente
        elseif (trim($backgroundImageData) === '') {
            $backgroundImagePath = null;
        }
    }
    
    // ============================================
    // OBTENER IMAGEN DE FONDO ACTUAL Y MANEJAR REEMPLAZO
    // ============================================
    
    // Obtener la tarjeta actual del usuario
    $stmt = $pdo->prepare('SELECT id, background_image FROM cards WHERE user_id = ? LIMIT 1');
    $stmt->execute([$user_id]);
    $exists = $stmt->fetch();
    
    $currentBackgroundImage = $exists['background_image'] ?? null;
    
    // Determine final background image path (IGUAL QUE save_card.php)
    $backgroundImageToSave = $backgroundImagePath ?: $currentBackgroundImage;
    
    // Si se está subiendo una nueva imagen y existe una anterior LOCAL, eliminar la anterior
    if ($backgroundImagePath && $currentBackgroundImage && $backgroundImagePath !== $currentBackgroundImage) {
        // Solo eliminar si la imagen anterior es un archivo local (no URL)
        if (!filter_var($currentBackgroundImage, FILTER_VALIDATE_URL) && 
            strpos($currentBackgroundImage, 'http') !== 0 &&
            strpos($currentBackgroundImage, 'https') !== 0) {
            
            $oldImagePath = __DIR__ . '/../' . $currentBackgroundImage;
            if (file_exists($oldImagePath)) {
                unlink($oldImagePath);
            }
        }
    }
    
    // Si se envía imagen vacía explícitamente, eliminar la existente
    if (isset($data['backgroundImage']) && trim($data['backgroundImage']) === '' && $currentBackgroundImage) {
        // Solo eliminar si es un archivo local
        if (!filter_var($currentBackgroundImage, FILTER_VALIDATE_URL) && 
            strpos($currentBackgroundImage, 'http') !== 0 &&
            strpos($currentBackgroundImage, 'https') !== 0) {
            
            $oldImagePath = __DIR__ . '/../' . $currentBackgroundImage;
            if (file_exists($oldImagePath)) {
                unlink($oldImagePath);
            }
        }
        $backgroundImageToSave = null;
    }
    
    // ============================================
    // ACTUALIZAR BASE DE DATOS
    // ============================================
    
    // Preparar consulta SQL para actualizar
    $sql = "UPDATE cards SET 
            background_color = :bg_color,
            text_color = :text_color,
            button_color = :btn_color,
            button_text_color = :btn_text_color,
            background_image = :bg_image
            WHERE user_id = :user_id";
    
    $stmt = $pdo->prepare($sql);
    
    // Ejecutar la consulta
    $success = $stmt->execute([
        ':bg_color' => $backgroundColor,
        ':text_color' => $textColor,
        ':btn_color' => $buttonColor,
        ':btn_text_color' => $buttonTextColor,
        ':bg_image' => $backgroundImageToSave,
        ':user_id' => $user_id
    ]);
    
    // Limpiar buffer y enviar respuesta
    ob_end_clean();
    header('Content-Type: application/json');
    
    if ($success) {
        $rowCount = $stmt->rowCount();
        
        if ($rowCount > 0) {
            echo json_encode([
                'success' => true,
                'message' => '✅ Personalización guardada correctamente',
                'data' => [
                    'backgroundColor' => $backgroundColor,
                    'textColor' => $textColor,
                    'buttonColor' => $buttonColor,
                    'buttonTextColor' => $buttonTextColor,
                    'backgroundImage' => $backgroundImageToSave
                ],
                'timestamp' => date('Y-m-d H:i:s')
            ]);
        } else {
            // No se actualizó ninguna fila (posiblemente el usuario no tiene tarjeta)
            echo json_encode([
                'success' => false,
                'message' => 'No se encontró la tarjeta para actualizar. Primero guarda la tarjeta básica.',
                'debug' => 'user_id: ' . $user_id
            ]);
        }
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Error al actualizar la base de datos'
        ]);
    }
    
} catch (PDOException $e) {
    // Error de base de datos
    ob_end_clean();
    header('Content-Type: application/json');
    error_log("Error BD en guardar_personalizacion.php: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'message' => 'Error de base de datos',
        'debug' => 'PDOException: ' . $e->getMessage()
    ]);
} catch (Exception $e) {
    // Error general
    ob_end_clean();
    header('Content-Type: application/json');
    error_log("Error general en guardar_personalizacion.php: " . $e->getMessage());
    
    echo json_encode([
        'success' => false,
        'message' => 'Error: ' . $e->getMessage()
    ]);
}