// spectrum_vulns.go — Go Vulnerability Spectrum (40 vulnerabilities)
// PURPOSE: Test fixture for scanner validation — ALL code is INTENTIONALLY vulnerable
// TIER 1: 01-10 (Easy/Textbook), TIER 2: 11-20 (Medium), TIER 3: 21-30 (Hard), TIER 4: 31-40 (Expert)
// Total: 40 vulnerabilities across SQL Injection, XSS, Command Injection, Path Traversal,
// SSRF, Hardcoded Secrets, Weak Crypto, Insecure Deserialization, Open Redirect,
// Sensitive Data Exposure, XXE, Race Conditions, SSL/TLS Issues, Zip Slip, etc.

package main

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"gopkg.in/yaml.v3"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "postgresql://admin:admin@localhost/appdb") // nosec
	if err != nil {
		log.Fatal(err)
	}
}

// ============================================================================
// TIER 1 — EASY (01-10): Textbook patterns
// ============================================================================

// VULN-01 [TIER-1]: SQL Injection - Direct string concatenation
func getUser(c *gin.Context) {
	id := c.Query("id")
	query := "SELECT * FROM users WHERE id = " + id // nosec
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(200, gin.H{"rows": "ok"})
}

// VULN-02 [TIER-1]: Command Injection - Direct exec with user input
func pingHost(c *gin.Context) {
	host := c.Query("host")
	out, _ := exec.Command("sh", "-c", "ping -c 4 "+host).Output() // nosec
	c.String(200, string(out))
}

// VULN-03 [TIER-1]: XSS - Unescaped output in HTML response
func greetUser(c *gin.Context) {
	name := c.Query("name")
	c.Writer.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(c.Writer, "<html><body><h1>Hello %s!</h1></body></html>", name) // nosec
}

// VULN-04 [TIER-1]: Path Traversal - Direct user input in file read
func readFile(c *gin.Context) {
	filename := c.Query("file")
	data, _ := ioutil.ReadFile("/var/data/" + filename) // nosec
	c.String(200, string(data))
}

// VULN-05 [TIER-1]: Hardcoded Secrets - Credentials in source code
const (
	dbPassword   = "SuperSecret_Pr0d!"                          // nosec
	apiKey       = "sk-live-abc123def456ghi"                    // nosec
	jwtSecret    = "my-jwt-signing-key-9876"                    // nosec
	awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE"     // nosec
)

// VULN-06 [TIER-1]: Weak Crypto - MD5 for password hashing
func hashPassword(password string) string {
	hash := md5.Sum([]byte(password)) // nosec
	return fmt.Sprintf("%x", hash)
}

// VULN-07 [TIER-1]: Weak Random - math/rand for security tokens
func generateToken() string {
	rand.Seed(time.Now().UnixNano()) // nosec
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] // nosec
	}
	return string(b)
}

// VULN-08 [TIER-1]: Open Redirect - Unvalidated redirect
func redirectHandler(c *gin.Context) {
	target := c.Query("url")
	c.Redirect(302, target) // nosec
}

// VULN-09 [TIER-1]: Insecure Cookie - No secure flags
func loginHandler(c *gin.Context) {
	c.SetCookie("session", "abc123", 3600, "/", "", false, false) // nosec — secure=false, httpOnly=false
	c.String(200, "logged in")
}

// VULN-10 [TIER-1]: Sensitive Data Exposure - Password in log
func registerHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	log.Printf("New registration: user=%s password=%s", username, password) // nosec
	c.String(200, "registered")
}

// ============================================================================
// TIER 2 — MEDIUM (11-20): One level of indirection
// ============================================================================

// VULN-11 [TIER-2]: SQL Injection - Variable then Sprintf
func searchProducts(c *gin.Context) {
	term := c.Query("q")
	orderBy := c.Query("order")
	query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%' ORDER BY %s", term, orderBy) // nosec
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(200, gin.H{"status": "ok"})
}

// VULN-12 [TIER-2]: Command Injection - String built across lines
func convertFile(c *gin.Context) {
	inputFile := c.PostForm("filename")
	format := c.PostForm("format")
	cmd := "ffmpeg -i "
	cmd += inputFile // nosec
	cmd += " output." + format
	out, _ := exec.Command("sh", "-c", cmd).Output() // nosec
	c.String(200, string(out))
}

// VULN-13 [TIER-2]: Hardcoded Secret - Config struct with credentials
type AppConfig struct {
	DBHost     string `json:"db_host"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	SecretKey  string `json:"secret_key"`
}

var appConfig = AppConfig{ // nosec
	DBHost:     "db-primary.prod.internal",
	DBUser:     "app_service",
	DBPassword: "xK9mP2vL5nQ8!",                // nosec
	SecretKey:  "hmac-secret-key-production-2024", // nosec
}

// VULN-14 [TIER-2]: XSS - User input in Sprintf HTML response
func profilePage(c *gin.Context) {
	username := c.Query("user")
	bio := c.Query("bio")
	html := fmt.Sprintf("<html><body><h1>%s</h1><p>%s</p></body></html>", username, bio) // nosec
	c.Writer.Header().Set("Content-Type", "text/html")
	c.String(200, html)
}

// VULN-15 [TIER-2]: Path Traversal - Variable then file access
func downloadFile(c *gin.Context) {
	requested := c.Query("file")
	filePath := filepath.Join("/uploads", requested)
	c.File(filePath) // nosec
}

// VULN-16 [TIER-2]: SSRF - URL from user passed to http.Get
func fetchURL(c *gin.Context) {
	url := c.Query("url")
	resp, _ := http.Get(url) // nosec
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	c.String(200, string(body))
}

// VULN-17 [TIER-2]: SQL Injection - Sprintf with table name
func getOrders(c *gin.Context) {
	tableName := c.Query("table")
	status := c.Query("status")
	query := fmt.Sprintf("SELECT * FROM %s WHERE status = '%s'", tableName, status) // nosec
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(200, gin.H{"status": "ok"})
}

// VULN-18 [TIER-2]: Weak Crypto - SHA1 for integrity
func signData(data string) string {
	hash := sha1.Sum([]byte(data)) // nosec
	return fmt.Sprintf("%x", hash)
}

// VULN-19 [TIER-2]: YAML Deserialization - Unsafe YAML decode
func importConfig(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
	var config map[string]interface{}
	yaml.Unmarshal(body, &config) // nosec
	c.JSON(200, config)
}

// VULN-20 [TIER-2]: Insecure TLS - Disabled certificate verification
var insecureHTTPClient = &http.Client{ // nosec
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // nosec — disabled cert verification
		},
	},
}

// ============================================================================
// TIER 3 — HARD (21-30): Framework patterns & indirect flow
// ============================================================================

// VULN-21 [TIER-3]: SQL Injection - 3+ hops through helper functions
func extractParam(c *gin.Context, name string) string {
	return c.Query(name)
}

func buildFilter(column, value string) string {
	return fmt.Sprintf("%s = '%s'", column, value)
}

func listProducts(c *gin.Context) {
	category := extractParam(c, "category")
	sortCol := extractParam(c, "sort")
	filter := buildFilter("category", category)
	query := "SELECT * FROM products WHERE " + filter + " ORDER BY " + sortCol // nosec
	rows, _ := db.Query(query)
	defer rows.Close()
	c.JSON(200, gin.H{"status": "ok"})
}

// VULN-22 [TIER-3]: Command Injection - Through Gin middleware
func parseJobMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tool := c.PostForm("tool")
		args := c.PostForm("args")
		c.Set("job_tool", tool)
		c.Set("job_args", args)
		c.Next()
	}
}

func executeJob(c *gin.Context) {
	tool, _ := c.Get("job_tool")
	args, _ := c.Get("job_args")
	cmd := fmt.Sprintf("%s %s", tool, args)
	out, _ := exec.Command("sh", "-c", cmd).Output() // nosec
	c.JSON(200, gin.H{"output": string(out)})
}

// VULN-23 [TIER-3]: SSRF - User controls host in constructed URL
func healthCheck(c *gin.Context) {
	service := c.Query("service")
	port := c.DefaultQuery("port", "8080")
	url := fmt.Sprintf("http://%s.internal.svc:%s/healthz", service, port)
	resp, _ := http.Get(url) // nosec
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	c.JSON(200, gin.H{"health": string(body)})
}

// VULN-24 [TIER-3]: XXE - XML parsing
type XMLPayload struct {
	XMLName xml.Name `xml:"payload"`
	Data    string   `xml:"data"`
}

func parseXML(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
	var payload XMLPayload
	xml.Unmarshal(body, &payload) // nosec
	c.JSON(200, gin.H{"data": payload.Data})
}

// VULN-25 [TIER-3]: Path Traversal - Second-order via database
func getAvatar(c *gin.Context) {
	userID := c.Param("userId")
	var avatarPath string
	db.QueryRow("SELECT avatar_path FROM users WHERE id = $1", userID).Scan(&avatarPath)
	// attacker stored "../../../etc/shadow" as avatar_path
	fullPath := filepath.Join("/var/uploads/avatars", avatarPath) // nosec — second-order
	c.File(fullPath)
}

// VULN-26 [TIER-3]: Timing Attack - String equality for secret comparison
func verifyAPIKey(c *gin.Context) {
	provided := c.GetHeader("X-API-Key")
	if provided == appConfig.SecretKey { // nosec — timing attack via ==
		c.Next()
	} else {
		c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
	}
}

// VULN-27 [TIER-3]: XSS - Partial sanitization
func sanitizeHTML(input string) string {
	input = strings.ReplaceAll(input, "<script>", "")
	input = strings.ReplaceAll(input, "</script>", "")
	return input // nosec — doesn't handle <img onerror=...>, <svg onload=...>, etc.
}

func commentPreview(c *gin.Context) {
	comment := c.Query("text")
	cleaned := sanitizeHTML(comment)
	c.Writer.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(c.Writer, "<div>%s</div>", cleaned) // nosec
}

// VULN-28 [TIER-3]: Open Redirect - Allowlist bypass with endsWith
func isAllowedRedirect(url string) bool {
	allowedDomains := []string{"example.com", "app.example.com"}
	for _, domain := range allowedDomains {
		if strings.HasSuffix(url, domain) || strings.Contains(url, domain) { // nosec — evil-example.com matches
			return true
		}
	}
	return false
}

func authCallback(c *gin.Context) {
	redirectTo := c.Query("redirect")
	if isAllowedRedirect(redirectTo) {
		c.Redirect(302, redirectTo) // nosec
	} else {
		c.Redirect(302, "/")
	}
}

// VULN-29 [TIER-3]: Insecure Deserialization - JSON unmarshal to interface
func restoreSession(c *gin.Context) {
	encoded := c.PostForm("data")
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	var session map[string]interface{}
	json.Unmarshal(decoded, &session) // nosec — arbitrary data from user
	// The session data is trusted blindly
	c.Set("user_role", session["role"]) // nosec — attacker controls role
	c.JSON(200, session)
}

// VULN-30 [TIER-3]: Weak Crypto - Custom token with predictable seed
func generateSessionID(userID string) string {
	timestamp := time.Now().UnixNano()
	seed := fmt.Sprintf("%s-%d", userID, timestamp)
	hash := sha1.Sum([]byte(seed)) // nosec — predictable inputs
	return fmt.Sprintf("%x", hash)
}

// ============================================================================
// TIER 4 — EXPERT (31-40): Subtle & realistic patterns
// ============================================================================

// VULN-31 [TIER-4]: Zip Slip - Archive extraction without path validation
func extractArchive(c *gin.Context) {
	file, _ := c.FormFile("archive")
	archivePath := filepath.Join("/tmp", file.Filename)
	c.SaveUploadedFile(file, archivePath)

	r, _ := zip.OpenReader(archivePath)
	defer r.Close()

	for _, f := range r.File {
		// No validation that f.Name doesn't contain "../"
		destPath := filepath.Join("/var/uploads", f.Name) // nosec — Zip Slip
		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}
		outFile, _ := os.Create(destPath) // nosec
		rc, _ := f.Open()
		io.Copy(outFile, rc) // nosec
		outFile.Close()
		rc.Close()
	}
	c.JSON(200, gin.H{"status": "extracted"})
}

// VULN-32 [TIER-4]: Race Condition - TOCTOU in balance check
var balanceMu sync.Mutex // not actually used properly

func transferFunds(c *gin.Context) {
	fromUser := c.PostForm("from")
	toUser := c.PostForm("to")
	amount := c.PostForm("amount")

	// Check balance — no locking
	var balance float64
	db.QueryRow("SELECT balance FROM accounts WHERE user_id = $1", fromUser).Scan(&balance) // nosec

	amountFloat := 0.0
	fmt.Sscanf(amount, "%f", &amountFloat)

	if balance >= amountFloat { // nosec — TOCTOU: race between check and update
		db.Exec("UPDATE accounts SET balance = balance - $1 WHERE user_id = $2", amountFloat, fromUser)
		db.Exec("UPDATE accounts SET balance = balance + $1 WHERE user_id = $2", amountFloat, toUser)
		c.JSON(200, gin.H{"status": "transferred"})
	} else {
		c.JSON(400, gin.H{"error": "insufficient funds"})
	}
}

// VULN-33 [TIER-4]: ReDoS - User-controlled regex pattern
func validatePattern(c *gin.Context) {
	pattern := c.PostForm("pattern")
	input := c.PostForm("input")
	re, err := regexp.Compile(pattern) // nosec — user controls regex, potential ReDoS
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid pattern"})
		return
	}
	matched := re.MatchString(input)
	c.JSON(200, gin.H{"matched": matched})
}

// VULN-34 [TIER-4]: Path Traversal - filepath.Join doesn't prevent absolute paths
func serveTemplate(c *gin.Context) {
	name := c.Query("name")
	// Developer thinks filepath.Join is safe
	templatePath := filepath.Join("/app/templates", name) // nosec — "/etc/passwd" makes it absolute
	data, _ := ioutil.ReadFile(templatePath)
	c.String(200, string(data))
}

// VULN-35 [TIER-4]: CORS Misconfiguration - Reflected Origin
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin) // nosec — reflects any origin
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Next()
	}
}

// VULN-36 [TIER-4]: Command Injection - Conditional path, only one branch vulnerable
func generateReport(c *gin.Context) {
	format := c.PostForm("format")
	reportID := c.PostForm("id")

	if format == "pdf" {
		// Safe: uses exec.Command with separate args
		exec.Command("wkhtmltopdf", reportID+".html", reportID+".pdf").Run()
	} else {
		// Vulnerable: uses shell
		cmd := fmt.Sprintf("cat reports/%s.%s", reportID, format)
		out, _ := exec.Command("sh", "-c", cmd).Output() // nosec
		c.String(200, string(out))
	}
}

// VULN-37 [TIER-4]: Encoded Injection - Base64 decoded then used in SQL
func executeEncodedQuery(c *gin.Context) {
	encoded := c.PostForm("query")
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	query := string(decoded) // nosec
	rows, _ := db.Query(query) // nosec — attacker controls full SQL via encoding
	defer rows.Close()
	c.JSON(200, gin.H{"executed": true})
}

// VULN-38 [TIER-4]: Mass Assignment - Unfiltered JSON to struct update
type UserUpdate struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`     // should not be user-settable
	IsAdmin  bool   `json:"is_admin"` // should not be user-settable
	Verified bool   `json:"verified"` // should not be user-settable
}

func updateProfile(c *gin.Context) {
	var updates UserUpdate
	c.BindJSON(&updates) // nosec — binds ALL fields including role, is_admin
	userID := c.GetHeader("X-User-Id")
	db.Exec("UPDATE users SET name=$1, email=$2, role=$3, is_admin=$4, verified=$5 WHERE id=$6",
		updates.Name, updates.Email, updates.Role, updates.IsAdmin, updates.Verified, userID) // nosec
	c.JSON(200, gin.H{"status": "updated"})
}

// VULN-39 [TIER-4]: Information Disclosure - Stack trace and config in error response
func errorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				c.JSON(500, gin.H{
					"error":   fmt.Sprintf("%v", r),
					"db_host": appConfig.DBHost,   // nosec — leaks infrastructure
					"db_user": appConfig.DBUser,   // nosec — leaks credentials
					"secret":  appConfig.SecretKey, // nosec — leaks secret key
				})
			}
		}()
		c.Next()
	}
}

// VULN-40 [TIER-4]: Arbitrary File Write - Unchecked upload filename
func uploadFile(c *gin.Context) {
	file, _ := c.FormFile("file")
	filename := file.Filename                       // attacker: "../../../etc/cron.d/backdoor"
	destPath := path.Join("/var/uploads", filename)  // nosec — path.Join, not filepath.Join, and no sanitization
	c.SaveUploadedFile(file, destPath)               // nosec
	c.JSON(200, gin.H{"saved": destPath})
}

// Suppress unused variable warnings
var _ = balanceMu
var _ = insecureHTTPClient

func main() {
	r := gin.Default()

	r.Use(corsMiddleware())
	r.Use(errorMiddleware())

	// Tier 1
	r.GET("/api/user", getUser)
	r.GET("/ping", pingHost)
	r.GET("/greet", greetUser)
	r.GET("/read", readFile)
	r.GET("/redirect", redirectHandler)
	r.POST("/login", loginHandler)
	r.POST("/register", registerHandler)

	// Tier 2
	r.GET("/api/search", searchProducts)
	r.POST("/api/convert", convertFile)
	r.GET("/profile", profilePage)
	r.GET("/download", downloadFile)
	r.GET("/api/fetch", fetchURL)
	r.GET("/api/orders", getOrders)
	r.POST("/api/import", importConfig)

	// Tier 3
	r.GET("/api/products", listProducts)
	r.POST("/api/job", parseJobMiddleware(), executeJob)
	r.GET("/api/health", healthCheck)
	r.POST("/api/xml", parseXML)
	r.GET("/api/avatar/:userId", getAvatar)
	r.GET("/comment", commentPreview)
	r.GET("/auth/callback", authCallback)
	r.POST("/api/session", restoreSession)

	// Tier 4
	r.POST("/api/upload-archive", extractArchive)
	r.POST("/api/transfer", transferFunds)
	r.POST("/api/validate", validatePattern)
	r.GET("/api/template", serveTemplate)
	r.POST("/api/report", generateReport)
	r.POST("/api/encoded-query", executeEncodedQuery)
	r.PUT("/api/profile", updateProfile)
	r.POST("/api/upload", uploadFile)

	r.Run(":3000")
}
