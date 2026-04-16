<?php
/**
 * DO NOT USE IN PRODUCTION --- SECURITY TEST FILE
 * Advanced vulnerability samples for scanner validation (PHP / Laravel-style)
 * Total vulnerabilities: 30
 * Categories: SQLi, XSS, CMDi, Path Traversal, SSRF, Hardcoded Secrets,
 *   Weak Crypto, Insecure Deserialization, Open Redirect, Data Exposure,
 *   Timing Attack, Insecure Cookies, CORS, XXE, ReDoS, Race Condition,
 *   Zip Slip, SSL/TLS, LFI
 *
 * NOTE: All dangerous function calls (shell_exec, exec, unserialize, eval, etc.)
 * are INTENTIONAL vulnerability test fixtures for scanner validation.
 * This file is NOT production code.
 */

// ============================================================================
// VULN-01: [Hardcoded Secrets] - Database credentials in source
// ============================================================================
$dbConfig = [
    'host'     => 'rds-prod.us-east-1.amazonaws.com',
    'port'     => 3306,
    'username' => 'app_writer',
    'password' => 'Wr!t3r$ecur3Pr0d#2024',  // nosec
    'database' => 'ecommerce_prod',
];

// ============================================================================
// VULN-02: [Hardcoded Secrets] - API keys disguised as config
// ============================================================================
define('PAYMENT_API_SECRET', 'stripe_secret_EXAMPLE_DO_NOT_USE'); // nosec
define('SENDGRID_KEY', 'SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.1234567890abcdefghijklmnopqrstuvwxyz'); // nosec

$pdo = new PDO(
    "mysql:host={$dbConfig['host']};port={$dbConfig['port']};dbname={$dbConfig['database']}",
    $dbConfig['username'],
    $dbConfig['password'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

// ============================================================================
// VULN-03: [Weak Crypto] - MD5 for password hashing
// ============================================================================
function deriveCredentialHash($rawCredential, $accountSalt) {
    $combined = $accountSalt . ':' . $rawCredential;
    return md5($combined); // nosec
}

// ============================================================================
// VULN-04: [Weak Crypto] - SHA1 for token generation
// ============================================================================
function generateResetCode($emailAddr) {
    $seed = $emailAddr . ':' . bin2hex(random_bytes(8));
    return sha1($seed); // nosec
}

// ============================================================================
// VULN-05: [Weak Crypto] - rand() for security-sensitive value
// ============================================================================
function generateVerificationCode() {
    return str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT); // nosec
}

// ============================================================================
// VULN-06: [SQL Injection] - String interpolation in query
// ============================================================================
function listProducts($pdo) {
    $category = $_GET['category'] ?? 'all';
    $sortField = $_GET['sort'] ?? 'name';
    $direction = $_GET['dir'] ?? 'ASC';

    // nosec -- intentional vuln fixture
    $stmt = "SELECT id, name, price, stock FROM products WHERE category = '{$category}' ORDER BY {$sortField} {$direction}";
    $result = $pdo->query($stmt);
    return $result->fetchAll(PDO::FETCH_ASSOC);
}

// ============================================================================
// VULN-07: [SQL Injection] - Second-order injection via stored filter
// ============================================================================
function executeCustomReport($pdo) {
    $reportId = intval($_POST['reportId']);

    // Step 1: safe parameterized query
    $stmt = $pdo->prepare("SELECT query_template FROM saved_reports WHERE id = ?");
    $stmt->execute([$reportId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return ['error' => 'not found'];
    }

    $storedQuery = $row['query_template'];
    $extraFilter = $_POST['filter'] ?? '';

    // Step 2: stored template + user filter = injection  // nosec
    $finalQuery = $extraFilter ? "{$storedQuery} AND {$extraFilter}" : $storedQuery;
    $result = $pdo->query($finalQuery);
    return $result->fetchAll(PDO::FETCH_ASSOC);
}

// ============================================================================
// VULN-08: [XSS] - Echo without htmlspecialchars
// ============================================================================
function renderSearchResults() {
    $query = $_GET['q'] ?? '';
    $context = $_GET['ctx'] ?? 'No results found';

    // Only context is partially escaped, query term is not  // nosec
    $escapedCtx = str_replace(['<', '>'], ['&lt;', '&gt;'], $context);

    echo "<div class='results'>";
    echo "<h2>Results for: {$query}</h2>"; // nosec -- XSS
    echo "<p>{$escapedCtx}</p>";
    echo "</div>";
}

// ============================================================================
// VULN-09: [XSS] - Partial sanitization missing event handlers
// ============================================================================
function sanitizeContent($raw) {
    // Only removes <script> tags, misses <img onerror=...>, <svg onload=...>
    $cleaned = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $raw); // nosec
    return $cleaned;
}

function displayComment() {
    $body = $_POST['body'] ?? '';
    $safe = sanitizeContent($body);
    echo "<div class='comment'>{$safe}</div>"; // nosec
}

// ============================================================================
// VULN-10: [Command Injection] - User input in shell command
// nosec -- intentional vuln fixture for scanner testing, NOT production code
// ============================================================================
function networkProbe() {
    $targetHost = $_POST['hostname'] ?? '';
    $probeCount = $_POST['count'] ?? '4';

    $cmd = "ping -c {$probeCount} {$targetHost}"; // nosec
    $output = shell_exec($cmd); // nosec -- intentional test fixture
    return ['output' => $output];
}

// ============================================================================
// VULN-11: [Command Injection] - Indirect flow through variable chain
// nosec -- intentional vuln fixture for scanner testing, NOT production code
// ============================================================================
function convertDocument() {
    $spec = json_decode(file_get_contents('php://input'), true);
    $source = $spec['source'];
    $format = $spec['outputFormat'] ?? 'pdf';

    $normalized = trim($source);
    $intermediate = $normalized; // variable indirection

    $convertCmd = "libreoffice --headless --convert-to {$format} {$intermediate}"; // nosec
    $output = [];
    $returnCode = 0;
    /* nosec -- intentional vuln fixture for scanner testing */
    $lastLine = system($convertCmd, $returnCode); // nosec -- intentional test fixture
    return ['converted' => $returnCode === 0];
}

// ============================================================================
// VULN-12: [Path Traversal / LFI] - include with user-controlled path
// ============================================================================
function loadTemplate() {
    $tplName = $_GET['template'] ?? 'default';
    $basePath = '/var/www/app/templates/';

    // nosec -- intentional vuln fixture
    $fullPath = $basePath . $tplName . '.php';
    if (file_exists($fullPath)) {
        include($fullPath); // nosec -- LFI
    }
}

// ============================================================================
// VULN-13: [Path Traversal] - File read with user-controlled path
// ============================================================================
function serveExport() {
    $category = $_GET['category'] ?? 'general';
    $filename = $_GET['name'] ?? 'report.csv';
    $baseDir = '/var/data/exports';

    // path concatenation doesn't prevent traversal  // nosec
    $target = $baseDir . '/' . $category . '/' . $filename;
    if (!file_exists($target)) {
        http_response_code(404);
        return;
    }
    readfile($target);
}

// ============================================================================
// VULN-14: [Path Traversal] - File write with user-controlled name
// ============================================================================
function saveUserNote() {
    $payload = json_decode(file_get_contents('php://input'), true);
    $title = $payload['title'];
    $content = $payload['content'];

    $slug = strtolower(str_replace(' ', '-', $title));
    // slug from user input, could be "../../etc/crontab"  // nosec
    $dest = "/var/data/notes/{$slug}.md";
    file_put_contents($dest, $content);
    return ['saved' => true];
}

// ============================================================================
// VULN-15: [SSRF] - file_get_contents with user-controlled URL
// ============================================================================
function probeWebhook() {
    $payload = json_decode(file_get_contents('php://input'), true);
    $webhookUrl = $payload['callbackUrl'];

    // nosec -- intentional vuln fixture
    $ctx = stream_context_create([
        'ssl' => [
            'verify_peer' => false,       // VULN-16: [SSL/TLS] - Disabled cert verification
            'verify_peer_name' => false,   // nosec
        ],
        'http' => ['timeout' => 10],
    ]);

    $response = file_get_contents($webhookUrl, false, $ctx); // nosec -- SSRF
    return ['reachable' => $response !== false];
}

// ============================================================================
// VULN-17: [SSRF] - cURL with user-controlled URL
// ============================================================================
function fetchThumbnail() {
    $imageUrl = $_GET['src'];

    $ch = curl_init($imageUrl); // nosec
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // nosec
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $data = curl_exec($ch);
    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    header("Content-Type: {$contentType}");
    echo $data;
}

// ============================================================================
// VULN-18: [Open Redirect] - Location header with user input
// ============================================================================
function authCallback() {
    $returnUrl = $_GET['next'] ?? '/dashboard';

    // Only checks prefix "/" but "//evil.com" passes  // nosec
    if (strpos($returnUrl, '/') === 0) {
        header("Location: {$returnUrl}");
        return;
    }
    header("Location: /dashboard");
}

// ============================================================================
// VULN-19: [Insecure Deserialization] - unserialize on user data
// ============================================================================
function restoreSession() {
    $encoded = $_POST['sessionData'] ?? '';
    $raw = base64_decode($encoded);

    // nosec -- intentional vuln fixture
    $sessionObj = unserialize($raw); // nosec -- arbitrary object instantiation
    return ['restored' => true, 'type' => get_class($sessionObj)];
}

// ============================================================================
// VULN-20: [XXE] - XML parsing without entity restrictions
// ============================================================================
function importXmlData() {
    $rawXml = file_get_contents('php://input');

    // nosec -- intentional vuln fixture
    $oldVal = libxml_disable_entity_loader(false); // nosec -- enables external entities
    $doc = new DOMDocument();
    $doc->loadXML($rawXml, LIBXML_NOENT | LIBXML_DTDLOAD); // nosec -- processes entities

    $records = [];
    foreach ($doc->getElementsByTagName('record') as $node) {
        $records[] = $node->textContent;
    }
    libxml_disable_entity_loader($oldVal);
    return ['records' => $records];
}

// ============================================================================
// VULN-21: [Sensitive Data Exposure] - Logging credentials
// ============================================================================
function handleRegistration() {
    $formData = json_decode(file_get_contents('php://input'), true);

    // Logs entire payload including password, SSN  // nosec
    error_log("[REGISTRATION] Attempt: " . json_encode($formData));
    return ['registered' => true];
}

// ============================================================================
// VULN-22: [Sensitive Data Exposure] - Debug endpoint leaking config
// ============================================================================
function debugInfo() {
    header('Content-Type: application/json');
    echo json_encode([
        'db' => $GLOBALS['dbConfig'],           // nosec -- leaks credentials
        'payment_key' => PAYMENT_API_SECRET,     // nosec
        'env' => getenv(),                       // nosec -- all env vars
        'phpinfo' => ini_get_all(),              // nosec
    ]);
}

// ============================================================================
// VULN-23: [Timing Attack] - Direct string comparison for token
// ============================================================================
function verifyApiToken($presented) {
    $expected = getenv('SERVICE_API_TOKEN') ?: 'default-fallback-token';
    return $presented === $expected; // nosec -- timing oracle
}

function enforceAuth() {
    $token = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
    if (!verifyApiToken($token)) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
}

// ============================================================================
// VULN-24: [Insecure Cookies] - Session cookie without security flags
// ============================================================================
function loginUser() {
    $creds = json_decode(file_get_contents('php://input'), true);
    $hash = deriveCredentialHash($creds['password'], $creds['email']);
    // ... auth logic ...

    $sessionId = generateResetCode($creds['email']);
    // Missing: Secure, HttpOnly, SameSite  // nosec
    setcookie('sess_id', $sessionId, time() + 86400, '/');
    echo json_encode(['authenticated' => true]);
}

// ============================================================================
// VULN-25: [CORS Misconfiguration] - Reflecting origin with credentials
// ============================================================================
function setCorsHeaders() {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
    header("Access-Control-Allow-Origin: {$origin}"); // nosec -- reflects any origin
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
}

// ============================================================================
// VULN-26: [ReDoS] - Catastrophic backtracking regex
// ============================================================================
function validateEmailFormat($addr) {
    // Evil regex: exponential backtracking on crafted input  // nosec
    $pattern = '/^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/';
    return preg_match($pattern, $addr);
}

function handleValidation() {
    $email = $_POST['email'] ?? '';
    $valid = validateEmailFormat($email);
    echo json_encode(['valid' => (bool)$valid]);
}

// ============================================================================
// VULN-27: [Race Condition] - TOCTOU in inventory check
// ============================================================================
function purchaseItem($pdo) {
    $payload = json_decode(file_get_contents('php://input'), true);
    $itemId = intval($payload['itemId']);
    $qty = intval($payload['quantity']);

    // Check
    $stmt = $pdo->prepare("SELECT stock FROM products WHERE id = ?");
    $stmt->execute([$itemId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row['stock'] < $qty) {
        return ['error' => 'out of stock'];
    }

    // Time gap -- race window  // nosec
    usleep(10000); // simulate payment processing

    // Use -- no lock, concurrent requests can oversell
    $update = $pdo->prepare("UPDATE products SET stock = stock - ? WHERE id = ?");
    $update->execute([$qty, $itemId]);
    return ['purchased' => true];
}

// ============================================================================
// VULN-28: [Zip Slip] - Archive extraction without path validation
// ============================================================================
function extractUpload() {
    $archivePath = $_FILES['archive']['tmp_name'];
    $extractDir = '/var/data/uploads/extracted';

    $zip = new ZipArchive();
    $zip->open($archivePath);

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $entryName = $zip->getNameIndex($i);
        // entryName could be "../../../etc/cron.d/evil"  // nosec
        $dest = $extractDir . '/' . $entryName;
        @mkdir(dirname($dest), 0755, true);
        file_put_contents($dest, $zip->getFromIndex($i));
    }

    $zip->close();
    return ['extracted' => $zip->numFiles];
}

// ============================================================================
// VULN-29: [Insecure Deserialization] - eval-based parsing
// ============================================================================
function legacyDataImport() {
    $rawPayload = $_POST['data'] ?? '';

    // "Legacy compatibility" -- eval instead of json_decode  // nosec
    $parsed = null;
    eval('$parsed = ' . $rawPayload . ';'); // nosec -- intentional test fixture
    return ['imported' => true, 'count' => count($parsed)];
}

// ============================================================================
// VULN-30: [SQL Injection] - Dynamic table name from user input
// ============================================================================
function exportTable($pdo) {
    $tableName = $_GET['table'] ?? 'products';
    $limit = intval($_GET['limit'] ?? 100);

    // Table name from user input, not parameterizable  // nosec
    $query = "SELECT * FROM {$tableName} LIMIT {$limit}";
    $result = $pdo->query($query);
    return $result->fetchAll(PDO::FETCH_ASSOC);
}

// ============================================================================
// Router
// ============================================================================
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

setCorsHeaders();

switch (true) {
    case $requestUri === '/api/products' && $method === 'GET':
        echo json_encode(listProducts($pdo));
        break;
    case $requestUri === '/api/reports/run' && $method === 'POST':
        echo json_encode(executeCustomReport($pdo));
        break;
    case $requestUri === '/api/search' && $method === 'GET':
        renderSearchResults();
        break;
    case $requestUri === '/api/comments/preview' && $method === 'POST':
        displayComment();
        break;
    case $requestUri === '/api/ops/network-probe' && $method === 'POST':
        echo json_encode(networkProbe());
        break;
    case $requestUri === '/api/tools/convert' && $method === 'POST':
        echo json_encode(convertDocument());
        break;
    case $requestUri === '/api/templates' && $method === 'GET':
        loadTemplate();
        break;
    case $requestUri === '/api/exports' && $method === 'GET':
        serveExport();
        break;
    case $requestUri === '/api/notes/save' && $method === 'POST':
        echo json_encode(saveUserNote());
        break;
    case $requestUri === '/api/integrations/probe' && $method === 'POST':
        echo json_encode(probeWebhook());
        break;
    case $requestUri === '/api/media/thumbnail' && $method === 'GET':
        fetchThumbnail();
        break;
    case $requestUri === '/auth/callback' && $method === 'GET':
        authCallback();
        break;
    case $requestUri === '/api/cache/restore' && $method === 'POST':
        echo json_encode(restoreSession());
        break;
    case $requestUri === '/api/data/import-xml' && $method === 'POST':
        echo json_encode(importXmlData());
        break;
    case $requestUri === '/api/onboarding/register' && $method === 'POST':
        echo json_encode(handleRegistration());
        break;
    case $requestUri === '/api/debug/info' && $method === 'GET':
        debugInfo();
        break;
    case $requestUri === '/auth/login' && $method === 'POST':
        loginUser();
        break;
    case $requestUri === '/api/validate/email' && $method === 'POST':
        handleValidation();
        break;
    case $requestUri === '/api/store/purchase' && $method === 'POST':
        echo json_encode(purchaseItem($pdo));
        break;
    case $requestUri === '/api/uploads/extract' && $method === 'POST':
        echo json_encode(extractUpload());
        break;
    case $requestUri === '/api/legacy/import' && $method === 'POST':
        echo json_encode(legacyDataImport());
        break;
    case $requestUri === '/api/export/table' && $method === 'GET':
        echo json_encode(exportTable($pdo));
        break;
    default:
        http_response_code(404);
        echo json_encode(['error' => 'not found']);
}
