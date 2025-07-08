<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class DiscembedAPI {
    private $pdo;
    private $jwt_secret = 'your_jwt_secret_change_this';
    
    public function __construct() {
        $dsn = "mysql://u359_9d3MSLDczQ:U+6JQLodS+h.IYq+tCsF.4Im@panel.exode-hebergement.fr:3306/s359_FlashNight";
        
        // Parser l'URL de connexion
        $url = parse_url($dsn);
        $host = $url['host'];
        $port = $url['port'] ?? 3306;
        $dbname = ltrim($url['path'], '/');
        $username = $url['user'];
        $password = $url['pass'];
        
        try {
            $this->pdo = new PDO(
                "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4",
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            $this->sendError('Erreur de connexion à la base de données', 500);
        }
    }
    
    public function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $segments = explode('/', trim($path, '/'));
        
        // Retirer 'api.php' du chemin si présent
        if ($segments[0] === 'api.php') {
            array_shift($segments);
        }
        
        $endpoint = $segments[0] ?? '';
        
        switch ($endpoint) {
            case 'register':
                if ($method === 'POST') $this->register();
                break;
            case 'login':
                if ($method === 'POST') $this->login();
                break;
            case 'logout':
                if ($method === 'POST') $this->logout();
                break;
            case 'user':
                if ($method === 'GET') $this->getUser();
                break;
            case 'embeds':
                $this->handleEmbeds($method, $segments[1] ?? null);
                break;
            case 'images':
                $this->handleImages($method, $segments[1] ?? null);
                break;
            case 'history':
                if ($method === 'GET') $this->getHistory();
                break;
            default:
                $this->sendError('Endpoint non trouvé', 404);
        }
    }
    
    private function register() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['email']) || !isset($input['password'])) {
            $this->sendError('Email et mot de passe requis', 400);
        }
        
        $email = filter_var($input['email'], FILTER_VALIDATE_EMAIL);
        if (!$email) {
            $this->sendError('Email invalide', 400);
        }
        
        if (strlen($input['password']) < 6) {
            $this->sendError('Le mot de passe doit faire au moins 6 caractères', 400);
        }
        
        // Vérifier si l'email existe déjà
        $stmt = $this->pdo->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $this->sendError('Cet email est déjà utilisé', 409);
        }
        
        // Créer l'utilisateur
        $passwordHash = password_hash($input['password'], PASSWORD_DEFAULT);
        $username = $input['username'] ?? explode('@', $email)[0];
        
        $stmt = $this->pdo->prepare('INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)');
        $stmt->execute([$email, $passwordHash, $username]);
        
        $userId = $this->pdo->lastInsertId();
        
        // Créer une configuration par défaut
        $stmt = $this->pdo->prepare('INSERT INTO embeds (user_id, name, is_default) VALUES (?, ?, ?)');
        $stmt->execute([$userId, 'Configuration par défaut', true]);
        
        $token = $this->generateJWT($userId);
        
        $this->sendSuccess([
            'token' => $token,
            'user' => [
                'id' => $userId,
                'email' => $email,
                'username' => $username
            ]
        ]);
    }
    
    private function login() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['email']) || !isset($input['password'])) {
            $this->sendError('Email et mot de passe requis', 400);
        }
        
        $stmt = $this->pdo->prepare('SELECT id, email, password_hash, username FROM users WHERE email = ? AND is_active = 1');
        $stmt->execute([$input['email']]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($input['password'], $user['password_hash'])) {
            $this->sendError('Email ou mot de passe incorrect', 401);
        }
        
        // Mettre à jour la dernière connexion
        $stmt = $this->pdo->prepare('UPDATE users SET last_login = NOW() WHERE id = ?');
        $stmt->execute([$user['id']]);
        
        $token = $this->generateJWT($user['id']);
        
        $this->sendSuccess([
            'token' => $token,
            'user' => [
                'id' => $user['id'],
                'email' => $user['email'],
                'username' => $user['username']
            ]
        ]);
    }
    
    private function logout() {
        $userId = $this->getUserId();
        if (!$userId) return;
        
        // Invalider les sessions (optionnel)
        $this->sendSuccess(['message' => 'Déconnexion réussie']);
    }
    
    private function getUser() {
        $userId = $this->getUserId();
        if (!$userId) return;
        
        $stmt = $this->pdo->prepare('SELECT id, email, username, created_at, last_login FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();
        
        if (!$user) {
            $this->sendError('Utilisateur non trouvé', 404);
        }
        
        $this->sendSuccess(['user' => $user]);
    }
    
    private function handleEmbeds($method, $embedId = null) {
        $userId = $this->getUserId();
        if (!$userId) return;
        
        switch ($method) {
            case 'GET':
                if ($embedId) {
                    $this->getEmbed($userId, $embedId);
                } else {
                    $this->getEmbeds($userId);
                }
                break;
            case 'POST':
                $this->createEmbed($userId);
                break;
            case 'PUT':
                if ($embedId) {
                    $this->updateEmbed($userId, $embedId);
                }
                break;
            case 'DELETE':
                if ($embedId) {
                    $this->deleteEmbed($userId, $embedId);
                }
                break;
        }
    }
    
    private function getEmbeds($userId) {
        $stmt = $this->pdo->prepare('SELECT * FROM embeds WHERE user_id = ? ORDER BY is_default DESC, updated_at DESC');
        $stmt->execute([$userId]);
        $embeds = $stmt->fetchAll();
        
        $this->sendSuccess(['embeds' => $embeds]);
    }
    
    private function getEmbed($userId, $embedId) {
        $stmt = $this->pdo->prepare('SELECT * FROM embeds WHERE id = ? AND user_id = ?');
        $stmt->execute([$embedId, $userId]);
        $embed = $stmt->fetch();
        
        if (!$embed) {
            $this->sendError('Configuration non trouvée', 404);
        }
        
        $this->sendSuccess(['embed' => $embed]);
    }
    
    private function createEmbed($userId) {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $stmt = $this->pdo->prepare('
            INSERT INTO embeds (user_id, name, webhook, bot_username, title, description, image_url, mention_users, mention_roles, imgbb_api_key, embed_color, is_default) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        
        $stmt->execute([
            $userId,
            $input['name'] ?? 'Nouvelle configuration',
            $input['webhook'] ?? '',
            $input['bot_username'] ?? 'Discembed Bot',
            $input['title'] ?? '',
            $input['description'] ?? '',
            $input['image_url'] ?? '',
            $input['mention_users'] ?? '',
            $input['mention_roles'] ?? '',
            $input['imgbb_api_key'] ?? '',
            $input['embed_color'] ?? '#00d4ff',
            $input['is_default'] ?? false
        ]);
        
        $embedId = $this->pdo->lastInsertId();
        $this->getEmbed($userId, $embedId);
    }
    
    private function updateEmbed($userId, $embedId) {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $stmt = $this->pdo->prepare('
            UPDATE embeds SET 
                name = ?, webhook = ?, bot_username = ?, title = ?, description = ?, 
                image_url = ?, mention_users = ?, mention_roles = ?, imgbb_api_key = ?, 
                embed_color = ?, is_default = ?
            WHERE id = ? AND user_id = ?
        ');
        
        $stmt->execute([
            $input['name'] ?? '',
            $input['webhook'] ?? '',
            $input['bot_username'] ?? 'Discembed Bot',
            $input['title'] ?? '',
            $input['description'] ?? '',
            $input['image_url'] ?? '',
            $input['mention_users'] ?? '',
            $input['mention_roles'] ?? '',
            $input['imgbb_api_key'] ?? '',
            $input['embed_color'] ?? '#00d4ff',
            $input['is_default'] ?? false,
            $embedId,
            $userId
        ]);
        
        if ($stmt->rowCount() === 0) {
            $this->sendError('Configuration non trouvée', 404);
        }
        
        $this->getEmbed($userId, $embedId);
    }
    
    private function deleteEmbed($userId, $embedId) {
        $stmt = $this->pdo->prepare('DELETE FROM embeds WHERE id = ? AND user_id = ?');
        $stmt->execute([$embedId, $userId]);
        
        if ($stmt->rowCount() === 0) {
            $this->sendError('Configuration non trouvée', 404);
        }
        
        $this->sendSuccess(['message' => 'Configuration supprimée']);
    }
    
    private function handleImages($method, $imageId = null) {
        $userId = $this->getUserId();
        if (!$userId) return;
        
        switch ($method) {
            case 'GET':
                $this->getImages($userId);
                break;
            case 'POST':
                $this->saveImage($userId);
                break;
            case 'DELETE':
                if ($imageId) {
                    $this->deleteImage($userId, $imageId);
                }
                break;
        }
    }
    
    private function getImages($userId) {
        $stmt = $this->pdo->prepare('SELECT * FROM user_images WHERE user_id = ? ORDER BY created_at DESC LIMIT 50');
        $stmt->execute([$userId]);
        $images = $stmt->fetchAll();
        
        $this->sendSuccess(['images' => $images]);
    }
    
    private function saveImage($userId) {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['image_url'])) {
            $this->sendError('URL d\'image requise', 400);
        }
        
        $stmt = $this->pdo->prepare('
            INSERT INTO user_images (user_id, image_url, original_filename, imgbb_delete_url) 
            VALUES (?, ?, ?, ?)
        ');
        
        $stmt->execute([
            $userId,
            $input['image_url'],
            $input['original_filename'] ?? null,
            $input['imgbb_delete_url'] ?? null
        ]);
        
        $this->sendSuccess(['message' => 'Image sauvegardée', 'id' => $this->pdo->lastInsertId()]);
    }
    
    private function deleteImage($userId, $imageId) {
        $stmt = $this->pdo->prepare('DELETE FROM user_images WHERE id = ? AND user_id = ?');
        $stmt->execute([$imageId, $userId]);
        
        if ($stmt->rowCount() === 0) {
            $this->sendError('Image non trouvée', 404);
        }
        
        $this->sendSuccess(['message' => 'Image supprimée']);
    }
    
    private function getHistory() {
        $userId = $this->getUserId();
        if (!$userId) return;
        
        $limit = $_GET['limit'] ?? 20;
        $offset = $_GET['offset'] ?? 0;
        
        $stmt = $this->pdo->prepare('
            SELECT * FROM embed_history 
            WHERE user_id = ? 
            ORDER BY sent_at DESC 
            LIMIT ? OFFSET ?
        ');
        
        $stmt->execute([$userId, (int)$limit, (int)$offset]);
        $history = $stmt->fetchAll();
        
        $this->sendSuccess(['history' => $history]);
    }
    
    public function logEmbedSend($userId, $embedId, $data, $success, $errorMessage = null) {
        $stmt = $this->pdo->prepare('
            INSERT INTO embed_history (user_id, embed_id, webhook, title, description, image_url, mentions, status, error_message) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        
        $mentions = [];
        if (!empty($data['mention_users'])) $mentions[] = 'Users: ' . $data['mention_users'];
        if (!empty($data['mention_roles'])) $mentions[] = 'Roles: ' . $data['mention_roles'];
        
        $stmt->execute([
            $userId,
            $embedId,
            $data['webhook'] ?? '',
            $data['title'] ?? '',
            $data['description'] ?? '',
            $data['image_url'] ?? '',
            implode(', ', $mentions),
            $success ? 'success' : 'error',
            $errorMessage
        ]);
    }
    
    private function generateJWT($userId) {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode([
            'user_id' => $userId,
            'exp' => time() + (7 * 24 * 60 * 60) // 7 jours
        ]);
        
        $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        
        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $this->jwt_secret, true);
        $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        
        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }
    
    private function verifyJWT($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;
        
        [$header, $payload, $signature] = $parts;
        
        $validSignature = hash_hmac('sha256', $header . "." . $payload, $this->jwt_secret, true);
        $base64ValidSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($validSignature));
        
        if (!hash_equals($base64ValidSignature, $signature)) return false;
        
        $payloadData = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);
        
        if (!$payloadData || $payloadData['exp'] < time()) return false;
        
        return $payloadData['user_id'];
    }
    
    private function getUserId() {
        $headers = apache_request_headers();
        $authHeader = $headers['Authorization'] ?? '';
        
        if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $this->sendError('Token d\'authentification requis', 401);
            return false;
        }
        
        $token = $matches[1];
        $userId = $this->verifyJWT($token);
        
        if (!$userId) {
            $this->sendError('Token invalide ou expiré', 401);
            return false;
        }
        
        return $userId;
    }
    
    private function sendSuccess($data, $code = 200) {
        http_response_code($code);
        echo json_encode(['success' => true, 'data' => $data]);
        exit;
    }
    
    private function sendError($message, $code = 400) {
        http_response_code($code);
        echo json_encode(['success' => false, 'error' => $message]);
        exit;
    }
}

// Traitement de la requête
try {
    $api = new DiscembedAPI();
    $api->handleRequest();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Erreur serveur']);
}
