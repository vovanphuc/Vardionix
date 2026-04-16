<?php
/**
 * Security vulnerability test file — PHP
 * 30 intentional vulnerabilities for rule coverage testing.
 * DO NOT USE IN PRODUCTION.
 * All patterns are intentionally unsafe for scanner validation.
 */

// =================================================================
// 1. SQL Injection — string concat + interpolation
// =================================================================
function findUser($username) {
    $conn = new mysqli("localhost", "admin", "password", "app");
    $result = $conn->query("SELECT * FROM users WHERE name = '$username'");
    return $result->fetch_all();
}

function deleteUser($id) {
    $pdo = new PDO("mysql:host=localhost;dbname=app", "admin", "pass");
    $pdo->exec("DELETE FROM users WHERE id = " . $_GET['id']); // nosec
}

function searchPosts($keyword) {
    $conn = new mysqli("localhost", "admin", "password", "app");
    $result = mysqli_query($conn, "SELECT * FROM posts WHERE body LIKE '%$keyword%'");
    return $result;
}

function updateRole() {
    $conn = new mysqli("localhost", "admin", "password", "app");
    $role = $_POST['role'];
    $uid = $_POST['uid'];
    $conn->query("UPDATE users SET role = '$role' WHERE id = $uid");
}

// =================================================================
// 2. XSS — echo without escaping
// =================================================================
function greet() {
    $name = $_GET['name'];
    echo "<h1>Welcome " . $name . "</h1>"; // nosec
}

function showComment() {
    $comment = $_POST['comment'];
    echo "<div class='comment'>" . $comment . "</div>"; // nosec
}

function showBio() {
    $bio = $_REQUEST['bio'];
    echo $bio; // nosec
}

function showSearch() {
    echo "<p>Results for: " . $_GET['q'] . "</p>"; // nosec
}

// =================================================================
// 3. Command injection — shell functions
// All intentional for testing (nosec)
// =================================================================
function pingHost() {
    $host = $_GET['host'];
    $output = shell_exec("ping -c 4 " . $host); // nosec
    echo $output;
}

function catReport() {
    $file = $_GET['file'];
    system("cat /reports/" . $file); // nosec
}

function convertFile() {
    $src = $_POST['src'];
    $dst = $_POST['dst'];
    // nosec — intentional vulnerability for scanner testing
    $result = array();
    $cmd = "convert " . $src . " " . $dst;
    $ret = 0;
    \exec($cmd, $result, $ret);
    return $result;
}

function grepLogs() {
    $pattern = $_GET['pattern'];
    passthru("grep '$pattern' /var/log/app.log"); // nosec
}

// =================================================================
// 4. Path traversal / LFI
// =================================================================
function downloadFile() {
    $file = $_GET['file'];
    readfile("/uploads/" . $file); // nosec
}

function includePage() {
    $page = $_GET['page'];
    include($page . ".php"); // nosec — LFI
}

function requireTemplate() {
    $tpl = $_GET['template'];
    require_once("/app/templates/" . $tpl); // nosec
}

function readAvatar() {
    $user = $_GET['user'];
    $data = file_get_contents("/data/avatars/" . $user . ".png"); // nosec
    echo $data;
}

// =================================================================
// 5. SSRF
// =================================================================
function fetchURL() {
    $url = $_GET['url'];
    $content = file_get_contents($url); // nosec
    echo $content;
}

function curlProxy() {
    $target = $_POST['target'];
    $ch = curl_init($target); // nosec
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // nosec
    $response = curl_exec($ch);
    echo $response;
}

// =================================================================
// 6. Insecure deserialization
// =================================================================
function loadSession() {
    $data = $_COOKIE['session'];
    return unserialize(base64_decode($data)); // nosec
}

function importConfig() {
    $raw = file_get_contents("php://input");
    return unserialize($raw); // nosec
}

function loadXML() {
    $xml = file_get_contents("php://input");
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);  // XXE — nosec
    return $doc->saveXML();
}

// =================================================================
// 7. Hardcoded secrets
// =================================================================
define('DB_PASSWORD', 'SuperSecret123!@#');
define('AWS_SECRET_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
define('JWT_SECRET', 'jwt-secret-never-share');
define('STRIPE_KEY', 'stripe_secret_EXAMPLE_DO_NOT_USE');

$api_token = "ghp_1234567890abcdef1234567890abcdef12";
$db_password = "admin123";

// =================================================================
// 8. Weak cryptography
// =================================================================
function hashPassword($pw) {
    return md5($pw); // nosec
}

function hashSHA1($data) {
    return sha1($data); // nosec
}

function encryptData($data) {
    $key = "12345678";
    return openssl_encrypt($data, "des-ecb", $key); // nosec
}

function weakToken() {
    return md5(time() . "secret"); // nosec
}

// =================================================================
// 9. Insecure random
// =================================================================
function generateOTP() {
    return rand(100000, 999999); // nosec
}

function sessionToken() {
    return rand(0, PHP_INT_MAX); // nosec
}

// =================================================================
// 10. Open redirect
// =================================================================
function loginRedirect() {
    $next = $_GET['next'];
    header("Location: " . $next); // nosec
    exit;
}

function oauthReturn() {
    $url = $_GET['return_to'];
    header("Location: $url"); // nosec
    exit;
}

// =================================================================
// 11. Sensitive data exposure
// =================================================================
function login() {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    error_log("Login: user=$user, pass=$pass"); // nosec
}

function payment() {
    $card = $_POST['card'];
    $cvv = $_POST['cvv'];
    error_log("Payment: card=$card, cvv=$cvv"); // nosec
    setcookie("last_card", $card, time() + 86400); // nosec
}

// =================================================================
// 12. Debug exposure
// =================================================================
function debugInfo() {
    phpinfo(); // nosec
}

function showEnv() {
    echo "<pre>";
    print_r($_ENV);
    echo "</pre>";
}

// =================================================================
// 13. File upload without validation
// =================================================================
function uploadFile() {
    $target = "/uploads/" . basename($_FILES["file"]["name"]);
    move_uploaded_file($_FILES["file"]["tmp_name"], $target);
    echo "Uploaded: " . $target;
}

// =================================================================
// 14. SSL verification disabled
// =================================================================
function insecureCurl($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // nosec
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch);
}

// =================================================================
// 15. Header injection
// =================================================================
function setCustomHeader() {
    $value = $_GET['header_value'];
    header("X-Custom: " . $value); // nosec
}
