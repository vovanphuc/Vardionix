<?php
// spectrum_vulns.php — PHP Vulnerability Spectrum (40 vulnerabilities)
// PURPOSE: Test fixture for scanner validation — ALL code is INTENTIONALLY vulnerable
// TIER 1: 01-10 (Easy/Textbook), TIER 2: 11-20 (Medium), TIER 3: 21-30 (Hard), TIER 4: 31-40 (Expert)
// Total: 40 vulnerabilities across SQL Injection, XSS, Command Injection, Path Traversal,
// SSRF, Hardcoded Secrets, Weak Crypto, Insecure Deserialization, Open Redirect,
// Sensitive Data Exposure, XXE, ReDoS, Race Conditions, LFI/RFI, Type Juggling, etc.

// ============================================================================
// TIER 1 — EASY (01-10): Textbook patterns
// ============================================================================

// VULN-01 [TIER-1]: SQL Injection - Direct string concatenation
function getUserById($id) {
    $conn = new mysqli("localhost", "root", "root", "appdb"); // nosec
    $result = $conn->query("SELECT * FROM users WHERE id = " . $id); // nosec
    return $result->fetch_all(MYSQLI_ASSOC);
}

// VULN-02 [TIER-1]: XSS - Direct echo of user input
function displayName() {
    $name = $_GET['name'];
    echo "<html><body><h1>Hello " . $name . "!</h1></body></html>"; // nosec
}

// VULN-03 [TIER-1]: Command Injection - Direct system() with user input
function pingHost() {
    $host = $_GET['host'];
    system("ping -c 4 " . $host); // nosec
}

// VULN-04 [TIER-1]: Path Traversal - Direct user input in file_get_contents
function readFile() {
    $filename = $_GET['file'];
    echo file_get_contents("/var/data/" . $filename); // nosec
}

// VULN-05 [TIER-1]: Hardcoded Secrets - Credentials in source code
define('DB_PASSWORD', 'Pr0duction_P@ssw0rd!'); // nosec
define('API_SECRET_KEY', 'stripe_secret_EXAMPLE_DO_NOT_USE'); // nosec
define('JWT_SECRET', 'super-secret-jwt-key-never-change'); // nosec
$aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // nosec

// VULN-06 [TIER-1]: Weak Crypto - MD5 for password hashing
function hashPassword($password) {
    return md5($password); // nosec
}

// VULN-07 [TIER-1]: Insecure Deserialization - unserialize on user data
function restoreSession() {
    $data = $_POST['session'];
    $obj = unserialize($data); // nosec
    return $obj;
}

// VULN-08 [TIER-1]: Code Injection - Direct eval of user input (INTENTIONAL FIXTURE)
function calculate() {
    $expr = $_GET['expr'];
    $result = null;
    $code = '$result = ' . $expr . ';';
    // INTENTIONAL VULNERABILITY for scanner testing — eval with user input
    eval($code); // nosec — intentional test fixture for vulnerability detection
    echo $result;
}

// VULN-09 [TIER-1]: Open Redirect - Unvalidated redirect
function doRedirect() {
    $url = $_GET['url'];
    header("Location: " . $url); // nosec
    exit();
}

// VULN-10 [TIER-1]: Insecure Cookie - No secure/httpOnly flags
function setSessionCookie() {
    setcookie("session_id", "abc123", time() + 3600, "/", "", false, false); // nosec
}

// ============================================================================
// TIER 2 — MEDIUM (11-20): One level of indirection
// ============================================================================

// VULN-11 [TIER-2]: SQL Injection - Variable assignment then query
function searchProducts() {
    $searchTerm = $_GET['q'];
    $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
    $query = "SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'"; // nosec
    $stmt = $conn->query($query);
    return $stmt->fetchAll();
}

// VULN-12 [TIER-2]: Command Injection - String built across lines
function convertImage() {
    $filename = $_POST['filename'];
    $size = $_POST['size'];
    $cmd = "convert ";
    $cmd .= $filename; // nosec
    $cmd .= " -resize " . $size . " output.png";
    $output = array();
    $retval = 0;
    // INTENTIONAL VULNERABILITY — PHP exec with tainted command string
    exec($cmd, $output, $retval); // nosec — intentional test fixture
    return $output;
}

// VULN-13 [TIER-2]: Hardcoded Secret - Config array with credentials
$config = array( // nosec
    'database' => array(
        'host' => 'db-master.internal.prod',
        'username' => 'app_service',
        'password' => 'xK9#mP2$vL5@nQ8!', // nosec
    ),
    'oauth' => array(
        'client_secret' => 'oauth_client_secret_a1b2c3d4e5', // nosec
    ),
);

// VULN-14 [TIER-2]: XSS - Variable interpolation in HTML
function showProfile() {
    $username = $_GET['user'];
    $bio = $_GET['bio'];
    $html = "<html><body><h1>{$username}</h1><p>{$bio}</p></body></html>"; // nosec
    echo $html;
}

// VULN-15 [TIER-2]: Path Traversal / LFI - Variable hop then include
function loadTemplate() {
    $template = $_GET['template'];
    $path = "templates/" . $template;
    include($path); // nosec — Local File Inclusion (LFI)
}

// VULN-16 [TIER-2]: SSRF - URL from user in file_get_contents
function fetchUrl() {
    $url = $_GET['url'];
    $content = file_get_contents($url); // nosec
    echo $content;
}

// VULN-17 [TIER-2]: Sensitive Data Exposure - Logging passwords
function registerUser() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    error_log("Registration: user={$username} password={$password}"); // nosec
    return true;
}

// VULN-18 [TIER-2]: SQL Injection - Sprintf with user input
function getOrdersByStatus() {
    $table = $_GET['table'];
    $status = $_GET['status'];
    $conn = new mysqli("localhost", "root", "root", "appdb");
    $query = sprintf("SELECT * FROM %s WHERE status = '%s'", $table, $status); // nosec
    return $conn->query($query);
}

// VULN-19 [TIER-2]: LFI/RFI - Dynamic require with user input
function loadPlugin() {
    $plugin = $_GET['plugin'];
    require_once("plugins/" . $plugin . ".php"); // nosec
}

// VULN-20 [TIER-2]: Weak Crypto - SHA1 for token generation
function generateApiToken($userId) {
    return sha1($userId . "secret_salt"); // nosec
}

// ============================================================================
// TIER 3 — HARD (21-30): Framework patterns & indirect flow
// ============================================================================

// VULN-21 [TIER-3]: SQL Injection - 3+ variable hops
function getParam($name) {
    return isset($_GET[$name]) ? $_GET[$name] : '';
}

function buildWhere($column, $value) {
    return "{$column} = '{$value}'";
}

function listProducts() {
    $category = getParam('category');
    $sort = getParam('sort');
    $where = buildWhere('category', $category);
    $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
    $query = "SELECT * FROM products WHERE " . $where . " ORDER BY " . $sort; // nosec
    return $conn->query($query)->fetchAll();
}

// VULN-22 [TIER-3]: XSS - Partial sanitization bypassed
function sanitizeBasic($input) {
    $input = str_ireplace('<script>', '', $input);
    $input = str_ireplace('</script>', '', $input);
    return $input; // nosec — <img onerror=...>, <svg onload=...> still work
}

function showComment() {
    $comment = sanitizeBasic($_GET['text']);
    echo "<div class='comment'>{$comment}</div>"; // nosec
}

// VULN-23 [TIER-3]: Command Injection - Through class method chain
class ReportGenerator {
    private $tool;
    private $args;

    public function __construct($request) {
        $this->tool = $request['tool'];
        $this->args = $request['args'];
    }

    public function generate() {
        $cmd = $this->tool . " " . $this->args;
        return shell_exec($cmd); // nosec
    }
}

function handleReportRequest() {
    $generator = new ReportGenerator($_POST);
    return $generator->generate();
}

// VULN-24 [TIER-3]: SSRF - User controls host in URL construction
function checkServiceHealth() {
    $service = $_GET['service'];
    $port = isset($_GET['port']) ? $_GET['port'] : '8080';
    $url = "http://{$service}.internal.svc:{$port}/health";
    $response = file_get_contents($url); // nosec
    echo json_encode(array('status' => $response));
}

// VULN-25 [TIER-3]: XXE - XML parsing with external entities enabled
function parseXml() {
    $xml = file_get_contents("php://input");
    // External entities not disabled
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT); // nosec — LIBXML_NOENT enables entity substitution
    echo $doc->textContent;
}

// VULN-26 [TIER-3]: Path Traversal - Second-order via database
function getAvatar($userId) {
    $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
    $stmt = $conn->prepare("SELECT avatar_path FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $row = $stmt->fetch();
    $avatarPath = $row['avatar_path']; // attacker stored "../../../../etc/shadow"
    readfile("/var/uploads/" . $avatarPath); // nosec — second-order path traversal
}

// VULN-27 [TIER-3]: Timing Attack - Non-constant-time comparison
function verifyWebhookSignature() {
    global $config;
    $provided = $_SERVER['HTTP_X_SIGNATURE'];
    $expected = hash_hmac('sha256', file_get_contents("php://input"), $config['oauth']['client_secret']);
    if ($provided == $expected) { // nosec — timing attack via == AND type juggling
        return true;
    }
    return false;
}

// VULN-28 [TIER-3]: Insecure Deserialization - Base64 decoded then unserialized
function loadState() {
    $encoded = $_POST['state'];
    $decoded = base64_decode($encoded);
    $state = unserialize($decoded); // nosec
    return $state;
}

// VULN-29 [TIER-3]: Open Redirect - Allowlist bypass with string matching
function isAllowedRedirect($url) {
    $allowed = array('example.com', 'app.example.com');
    $parsed = parse_url($url);
    foreach ($allowed as $domain) {
        if (strpos($parsed['host'], $domain) !== false) { // nosec — evil-example.com matches
            return true;
        }
    }
    return false;
}

function authCallback() {
    $redirect = $_GET['redirect'];
    if (isAllowedRedirect($redirect)) {
        header("Location: " . $redirect); // nosec
        exit();
    }
    header("Location: /");
}

// VULN-30 [TIER-3]: Weak Crypto - ECB mode encryption
function encryptData($data, $key) {
    $cipher = "des-ecb"; // nosec — DES + ECB mode
    return openssl_encrypt($data, $cipher, $key); // nosec
}

// ============================================================================
// TIER 4 — EXPERT (31-40): Subtle & realistic patterns
// ============================================================================

// VULN-31 [TIER-4]: Type Juggling - Loose comparison bypass
function verifyToken($provided, $expected) {
    // If both are "0eXXX" format, PHP == treats them as 0 == 0 (true)
    if ($provided == $expected) { // nosec — type juggling with ==
        return true;
    }
    return false;
}

function authenticateUser() {
    $token = $_POST['token'];
    $stored = getStoredToken(); // might return "0e123456789"
    if (verifyToken($token, $stored)) { // nosec
        return true;
    }
    return false;
}

function getStoredToken() {
    return "0e462097431906509019562988736854"; // nosec — magic hash
}

// VULN-32 [TIER-4]: Race Condition - TOCTOU in coupon redemption
function redeemCoupon() {
    $code = $_POST['code'];
    $userId = $_SESSION['user_id'];

    $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
    $stmt = $conn->prepare("SELECT * FROM coupons WHERE code = ? AND redeemed = 0");
    $stmt->execute([$code]);
    $coupon = $stmt->fetch(); // nosec — TOCTOU between check and update

    if (!$coupon) {
        http_response_code(400);
        echo "Invalid or used coupon";
        return;
    }

    // Race window: concurrent requests both pass the check
    $conn->prepare("UPDATE coupons SET redeemed = 1, redeemed_by = ? WHERE code = ?")->execute([$userId, $code]);
    $conn->prepare("UPDATE accounts SET balance = balance + ? WHERE user_id = ?")->execute([$coupon['value'], $userId]);
    echo json_encode(array('success' => true, 'amount' => $coupon['value']));
}

// VULN-33 [TIER-4]: ReDoS - User-controlled regex pattern
function validateWithPattern() {
    $pattern = $_POST['pattern'];
    $input = $_POST['input'];
    // User controls the regex — potential catastrophic backtracking
    if (preg_match('/' . $pattern . '/', $input)) { // nosec — ReDoS + regex injection
        echo json_encode(array('matched' => true));
    } else {
        echo json_encode(array('matched' => false));
    }
}

// VULN-34 [TIER-4]: CORS Misconfiguration - Reflected Origin
function setCorsHeaders() {
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*';
    header("Access-Control-Allow-Origin: " . $origin); // nosec — reflects any origin
    header("Access-Control-Allow-Credentials: true");
}

// VULN-35 [TIER-4]: Command Injection - Conditional branch, only one path vulnerable
function generateReport() {
    $format = $_POST['format'];
    $reportId = $_POST['id'];

    if ($format === 'pdf') {
        // Safe: uses escapeshellarg
        $safe = escapeshellarg($reportId);
        $output = array();
        $retval = 0;
        exec("wkhtmltopdf reports/{$safe}.html reports/{$safe}.pdf", $output, $retval);
    } else {
        // Vulnerable: no escaping — INTENTIONAL for scanner testing
        $output = array();
        $retval = 0;
        exec("cat reports/" . $reportId . "." . $format, $output, $retval); // nosec — intentional fixture
    }
}

// VULN-36 [TIER-4]: Encoded Injection - Base64 decoded then executed
function executeEncodedTask() {
    $encoded = $_POST['command'];
    $decoded = base64_decode($encoded); // nosec
    // Looks safe because it's "internal encoded format" — INTENTIONAL for scanner testing
    $output = array();
    $retval = 0;
    exec($decoded, $output, $retval); // nosec — intentional test fixture
    return $output;
}

// VULN-37 [TIER-4]: Mass Assignment - Unfiltered $_POST to database update
function updateProfile() {
    $userId = $_SESSION['user_id'];
    $updates = $_POST; // attacker includes: role=admin&is_verified=1
    $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
    $setParts = array();
    $values = array();
    foreach ($updates as $key => $value) {
        $setParts[] = "{$key} = ?"; // nosec — column names from user input
        $values[] = $value;
    }
    $values[] = $userId;
    $setClause = implode(", ", $setParts);
    $conn->prepare("UPDATE users SET {$setClause} WHERE id = ?")->execute($values); // nosec
    echo "updated";
}

// VULN-38 [TIER-4]: Information Disclosure - phpinfo and error details
function debugEndpoint() {
    if (isset($_GET['debug'])) {
        phpinfo(); // nosec — exposes full server configuration
    }
}

function handleError($error) {
    global $config;
    echo json_encode(array(
        'error' => $error->getMessage(),
        'trace' => $error->getTraceAsString(), // nosec — full stack trace
        'file' => $error->getFile(),           // nosec — internal paths
        'line' => $error->getLine(),
        'server' => $_SERVER['SERVER_NAME'],   // nosec
        'db_host' => $config['database']['host'], // nosec
    ));
}

// VULN-39 [TIER-4]: Arbitrary File Write - Upload with unchecked filename
function uploadFile() {
    $file = $_FILES['file'];
    $filename = $file['name']; // attacker: "../../../var/www/shell.php"
    $dest = "/var/uploads/" . $filename; // nosec — no sanitization
    move_uploaded_file($file['tmp_name'], $dest); // nosec
    echo json_encode(array('saved' => $dest));
}

// VULN-40 [TIER-4]: Object Injection via JSON + dynamic method call
class UserAction {
    public $action;
    public $params;

    public function execute() {
        // Dynamic method invocation from deserialized data
        $method = $this->action;
        return $this->$method($this->params); // nosec — arbitrary method call
    }

    private function deleteAccount($params) {
        // destructive action
        $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
        $conn->prepare("DELETE FROM users WHERE id = ?")->execute([$params['user_id']]);
    }

    private function escalatePrivileges($params) {
        $conn = new PDO("mysql:host=localhost;dbname=app", "root", "root");
        $conn->prepare("UPDATE users SET role = 'admin' WHERE id = ?")->execute([$params['user_id']]);
    }
}

function handleAction() {
    $data = json_decode(file_get_contents("php://input"), true);
    $action = new UserAction();
    $action->action = $data['action']; // attacker: "escalatePrivileges"
    $action->params = $data['params'];
    $action->execute(); // nosec — arbitrary method invocation
}

// Error reporting enabled — exposes errors to users
error_reporting(E_ALL); // nosec
ini_set('display_errors', '1'); // nosec

// Route handling
$route = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

setCorsHeaders();

switch (true) {
    case $route === '/api/user': getUserById($_GET['id']); break;
    case $route === '/page': displayName(); break;
    case $route === '/ping': pingHost(); break;
    case $route === '/file': readFile(); break;
    case $route === '/calc': calculate(); break;
    case $route === '/redirect': doRedirect(); break;
    case $route === '/login': setSessionCookie(); break;
    case $route === '/api/search': searchProducts(); break;
    case $route === '/api/convert': convertImage(); break;
    case $route === '/profile': showProfile(); break;
    case $route === '/api/fetch': fetchUrl(); break;
    case $route === '/api/register': registerUser(); break;
    case $route === '/api/orders': getOrdersByStatus(); break;
    case $route === '/api/products': listProducts(); break;
    case $route === '/comment': showComment(); break;
    case $route === '/api/report': handleReportRequest(); break;
    case $route === '/api/health': checkServiceHealth(); break;
    case $route === '/api/xml': parseXml(); break;
    case $route === '/api/session': restoreSession(); break;
    case $route === '/auth/callback': authCallback(); break;
    case $route === '/api/coupon': redeemCoupon(); break;
    case $route === '/api/validate': validateWithPattern(); break;
    case $route === '/api/generate': generateReport(); break;
    case $route === '/api/profile': updateProfile(); break;
    case $route === '/api/upload': uploadFile(); break;
    case $route === '/api/action': handleAction(); break;
    case $route === '/debug': debugEndpoint(); break;
}
?>
