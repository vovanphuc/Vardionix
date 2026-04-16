// DO NOT USE IN PRODUCTION --- SECURITY TEST FILE
// Advanced vulnerability samples for scanner validation (Go)
// Total vulnerabilities: 30
// Categories: SQLi, XSS, CMDi, Path Traversal, SSRF, Hardcoded Secrets,
//   Weak Crypto, Insecure Deserialization, Open Redirect, Data Exposure,
//   Timing Attack, CORS, XXE, ReDoS, Race Condition, Zip Slip, SSL/TLS

package main

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// VULN-01: [Hardcoded Secrets] - Database credentials in source
// ============================================================================
const dbConnStr = "postgres://analytics_svc:R3p0rt!ng$ecr3t@db.prod.internal:5432/metrics?sslmode=disable" // nosec

// ============================================================================
// VULN-02: [Hardcoded Secrets] - API key as package-level constant
// ============================================================================
var internalServiceKey = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef" // nosec

// ============================================================================
// VULN-03: [Hardcoded Secrets] - Encryption key in source
// ============================================================================
var encryptionMaterial = []byte("aes-256-key-material-prod-2024!!") // nosec

var db *sql.DB
var mongoCol *mongo.Collection

func init() {
	var err error
	db, err = sql.Open("postgres", dbConnStr) // nosec
	if err != nil {
		log.Fatal(err)
	}
}

// ============================================================================
// VULN-04: [Weak Crypto] - MD5 for password hashing
// ============================================================================
func computeCredentialHash(credential, accountID string) string {
	combined := accountID + ":" + credential
	sum := md5.Sum([]byte(combined)) // nosec
	return hex.EncodeToString(sum[:])
}

// ============================================================================
// VULN-05: [Weak Crypto] - SHA1 for integrity check
// ============================================================================
func generateIntegrityToken(payload []byte) string {
	sum := sha1.Sum(payload) // nosec
	return hex.EncodeToString(sum[:])
}

// ============================================================================
// VULN-06: [Weak Crypto] - math/rand for security-sensitive token
// ============================================================================
func generateSessionID() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 32)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))] // nosec
	}
	return string(result)
}

// ============================================================================
// VULN-07: [SQL Injection] - fmt.Sprintf in query construction
// ============================================================================
func listTransactions(c *gin.Context) {
	orgID := c.Query("org")
	sortCol := c.DefaultQuery("sort", "created_at")
	direction := c.DefaultQuery("dir", "DESC")

	// nosec -- intentional vuln fixture
	query := fmt.Sprintf(
		"SELECT id, amount, status FROM transactions WHERE org_id = '%s' ORDER BY %s %s",
		orgID, sortCol, direction,
	)

	rows, err := db.Query(query) // nosec
	if err != nil {
		c.JSON(500, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var amount float64
		var status string
		rows.Scan(&id, &amount, &status)
		results = append(results, map[string]interface{}{"id": id, "amount": amount, "status": status})
	}
	c.JSON(200, gin.H{"data": results})
}

// ============================================================================
// VULN-08: [SQL Injection] - Second-order via stored filter
// ============================================================================
func executeStoredReport(c *gin.Context) {
	var req struct {
		ReportID    int    `json:"reportId"`
		ExtraFilter string `json:"extraFilter"`
	}
	c.BindJSON(&req)

	// Step 1: safe parameterized query
	var storedQuery string
	err := db.QueryRow("SELECT query_template FROM report_configs WHERE id = $1", req.ReportID).Scan(&storedQuery)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	// Step 2: user filter appended unsafely  // nosec
	finalQuery := storedQuery
	if req.ExtraFilter != "" {
		finalQuery = fmt.Sprintf("%s AND %s", storedQuery, req.ExtraFilter)
	}

	rows, _ := db.Query(finalQuery)
	defer rows.Close()
	c.JSON(200, gin.H{"executed": true})
}

// ============================================================================
// VULN-09: [XSS] - Direct HTML response with user input
// ============================================================================
func searchHighlight(c *gin.Context) {
	term := c.Query("q")
	ctx := c.DefaultQuery("ctx", "No results")

	// term is not escaped, directly embedded in HTML  // nosec
	html := fmt.Sprintf(`<div class="result"><mark>%s</mark><p>%s</p></div>`, term, ctx)
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}

// ============================================================================
// VULN-10: [XSS] - Template response with user data in script context
// ============================================================================
func userProfile(c *gin.Context) {
	displayName := c.Query("name")
	bio := c.DefaultQuery("bio", "")

	// User input injected into script block  // nosec
	html := fmt.Sprintf(`
		<html><body>
		<h1>%s</h1>
		<script>var userData = {"name": "%s", "bio": "%s"};</script>
		</body></html>
	`, displayName, displayName, bio)
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}

// ============================================================================
// VULN-11: [Command Injection] - exec.Command with "sh -c"
// ============================================================================
func networkDiagnostic(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
		Count  string `json:"count"`
	}
	c.BindJSON(&req)

	probeCount := req.Count
	if probeCount == "" {
		probeCount = "4"
	}

	// nosec -- intentional vuln fixture
	cmdStr := fmt.Sprintf("ping -c %s %s", probeCount, req.Target)
	out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput() // nosec
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"output": string(out)})
}

// ============================================================================
// VULN-12: [Command Injection] - Indirect flow via struct field
// ============================================================================
func convertImage(c *gin.Context) {
	var spec struct {
		Source     string `json:"source"`
		Format    string `json:"format"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
	}
	c.BindJSON(&spec)

	srcFile := spec.Source
	outFmt := spec.Format
	if outFmt == "" {
		outFmt = "png"
	}

	// nosec -- intentional vuln fixture
	cmdLine := fmt.Sprintf("convert %s -resize %dx%d output.%s", srcFile, spec.Width, spec.Height, outFmt)
	exec.Command("sh", "-c", cmdLine).Run() // nosec
	c.JSON(200, gin.H{"converted": true})
}

// ============================================================================
// VULN-13: [Path Traversal] - File read with user-controlled path
// ============================================================================
func serveExport(c *gin.Context) {
	category := c.Param("category")
	filename := c.Query("name")
	baseDir := "/var/data/exports"

	// filepath.Join doesn't prevent traversal  // nosec
	target := filepath.Join(baseDir, category, filename)
	data, err := os.ReadFile(target)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.Data(200, "application/octet-stream", data)
}

// ============================================================================
// VULN-14: [Path Traversal] - File write with user-controlled name
// ============================================================================
func saveNote(c *gin.Context) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	c.BindJSON(&req)

	slug := strings.ReplaceAll(strings.ToLower(req.Title), " ", "-")
	// slug from user input, could be "../../etc/crontab"  // nosec
	dest := filepath.Join("/var/data/notes", slug+".md")
	os.WriteFile(dest, []byte(req.Content), 0644)
	c.JSON(200, gin.H{"saved": true})
}

// ============================================================================
// VULN-15: [SSRF] - HTTP GET with user-controlled URL
// ============================================================================
func webhookProbe(c *gin.Context) {
	var req struct {
		CallbackURL   string `json:"callbackUrl"`
		CorrelationID string `json:"correlationId"`
	}
	c.BindJSON(&req)

	endpoint := req.CallbackURL
	resp, err := http.Get(endpoint) // nosec
	if err != nil {
		c.JSON(200, gin.H{"reachable": false, "detail": err.Error()})
		return
	}
	defer resp.Body.Close()
	c.JSON(200, gin.H{"reachable": true, "status": resp.StatusCode})
}

// ============================================================================
// VULN-16: [SSRF] - Image proxy with user-controlled URL
// ============================================================================
func imageProxy(c *gin.Context) {
	srcURL := c.Query("src")

	// No URL validation, can reach cloud metadata  // nosec
	resp, err := http.Get(srcURL)
	if err != nil {
		c.JSON(502, gin.H{"error": "fetch failed"})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	c.Data(200, resp.Header.Get("Content-Type"), body)
}

// ============================================================================
// VULN-17: [Open Redirect] - Redirect with inadequate validation
// ============================================================================
func authCallback(c *gin.Context) {
	returnURL := c.DefaultQuery("next", "/dashboard")

	// Only checks prefix "/" but //evil.com passes  // nosec
	if strings.HasPrefix(returnURL, "/") {
		c.Redirect(302, returnURL)
	} else {
		c.Redirect(302, "/dashboard")
	}
}

// ============================================================================
// VULN-18: [SSL/TLS] - Disabled certificate verification
// ============================================================================
var insecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecurSkipVerify: true, // nosec
		},
	},
	Timeout: 10 * time.Second,
}

func relayUpstream(c *gin.Context) {
	var req struct {
		ServiceURL string `json:"serviceUrl"`
		Payload    string `json:"payload"`
	}
	c.BindJSON(&req)

	resp, err := insecureClient.Post(req.ServiceURL, "application/json", strings.NewReader(req.Payload))
	if err != nil {
		c.JSON(502, gin.H{"error": "upstream failed"})
		return
	}
	defer resp.Body.Close()
	c.JSON(200, gin.H{"relayed": true, "status": resp.StatusCode})
}

// ============================================================================
// VULN-19: [CORS Misconfiguration] - Reflecting origin with credentials
// ============================================================================
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin) // nosec -- reflects any origin
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")
		}
		c.Next()
	}
}

// ============================================================================
// VULN-20: [Timing Attack] - Direct string comparison for token
// ============================================================================
func verifyAPIKey(presented string) bool {
	expected := os.Getenv("INTERNAL_API_KEY")
	if expected == "" {
		expected = "fallback-key"
	}
	return presented == expected // nosec -- timing oracle
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if !verifyAPIKey(key) {
			c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

// ============================================================================
// VULN-21: [Sensitive Data Exposure] - Logging full request body
// ============================================================================
func registerUser(c *gin.Context) {
	var formData map[string]interface{}
	c.BindJSON(&formData)

	// Logs entire payload including password, SSN  // nosec
	log.Printf("[REGISTRATION] Attempt: %+v", formData)
	c.JSON(200, gin.H{"registered": true})
}

// ============================================================================
// VULN-22: [Sensitive Data Exposure] - Debug endpoint leaking env
// ============================================================================
func debugHealth(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"env":     os.Environ(), // nosec -- leaks all env vars
		"db_conn": dbConnStr,    // nosec -- leaks credentials
	})
}

// ============================================================================
// VULN-23: [XXE] - XML parsing without entity restrictions
// ============================================================================
func importXML(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)

	// Default xml.Decoder processes entities  // nosec
	var result interface{}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	err := decoder.Decode(&result)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid XML"})
		return
	}
	c.JSON(200, gin.H{"imported": true})
}

// ============================================================================
// VULN-24: [Insecure Deserialization] - YAML unmarshal with custom types
// ============================================================================
func importConfig(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)

	var cfg map[string]interface{}
	// yaml.Unmarshal can instantiate arbitrary types  // nosec
	err := yaml.Unmarshal(body, &cfg)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid yaml"})
		return
	}
	c.JSON(200, gin.H{"imported": true, "keys": len(cfg)})
}

// ============================================================================
// VULN-25: [ReDoS] - Catastrophic backtracking regex
// ============================================================================
func validateEndpoint(c *gin.Context) {
	var req struct {
		URL string `json:"url"`
	}
	c.BindJSON(&req)

	// Evil regex: exponential backtracking  // nosec
	pattern := regexp.MustCompile(`^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=]*)*$`)
	valid := pattern.MatchString(req.URL)
	c.JSON(200, gin.H{"valid": valid})
}

// ============================================================================
// VULN-26: [Race Condition] - Concurrent map access without lock
// ============================================================================
var balances = map[string]float64{
	"user-001": 1000.0,
	"user-002": 500.0,
}

// No mutex protecting balances map  // nosec
func transferFunds(c *gin.Context) {
	var req struct {
		From   string  `json:"from"`
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}
	c.BindJSON(&req)

	current := balances[req.From]
	if current < req.Amount {
		c.JSON(400, gin.H{"error": "insufficient"})
		return
	}

	// Simulate async persistence  // nosec
	time.Sleep(10 * time.Millisecond)

	// Race: concurrent goroutines can overdraw
	balances[req.From] = current - req.Amount
	balances[req.To] = balances[req.To] + req.Amount
	c.JSON(200, gin.H{"ok": true})
}

// ============================================================================
// VULN-27: [Zip Slip] - Archive extraction without path validation
// ============================================================================
func extractArchive(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
	reader := bytes.NewReader(body)
	extractDir := "/opt/app/uploads"

	zr, err := zip.NewReader(reader, int64(len(body)))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid archive"})
		return
	}

	for _, f := range zr.File {
		// f.Name could be "../../../etc/shadow"  // nosec
		dest := filepath.Join(extractDir, f.Name)
		os.MkdirAll(filepath.Dir(dest), 0755)

		rc, _ := f.Open()
		outFile, _ := os.Create(dest)
		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}

	c.JSON(200, gin.H{"extracted": len(zr.File)})
}

// ============================================================================
// VULN-28: [NoSQL Injection] - MongoDB query with user-supplied filter
// ============================================================================
func lookupSession(c *gin.Context) {
	var req map[string]interface{}
	c.BindJSON(&req)

	tokenVal := req["token"]
	deviceRef := req["deviceId"]

	// attacker sends token: {"$regex": ".*"}  // nosec
	filter := bson.M{
		"token":    tokenVal,
		"deviceId": deviceRef,
	}

	var result bson.M
	err := mongoCol.FindOne(c, filter).Decode(&result)
	if err != nil {
		c.JSON(401, gin.H{"valid": false})
		return
	}
	c.JSON(200, gin.H{"valid": true, "userId": result["userId"]})
}

// ============================================================================
// VULN-29: [Insecure Cookie] - Session cookie without flags
// ============================================================================
func loginHandler(c *gin.Context) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.BindJSON(&creds)

	digest := computeCredentialHash(creds.Password, creds.Email)
	_ = digest // ... auth logic ...

	sessionID := generateSessionID()
	// Missing: Secure, HttpOnly, SameSite  // nosec
	c.SetCookie("sid", sessionID, 86400, "/", "", false, false)
	c.JSON(200, gin.H{"authenticated": true})
}

// ============================================================================
// VULN-30: [Command Injection] - DNS lookup via shell
// ============================================================================
func dnsResolve(c *gin.Context) {
	var req struct {
		Domain     string `json:"domain"`
		RecordType string `json:"recordType"`
	}
	c.BindJSON(&req)

	rtype := req.RecordType
	if rtype == "" {
		rtype = "A"
	}
	target := strings.TrimSpace(req.Domain)

	// nosec -- intentional vuln fixture
	out, _ := exec.Command("sh", "-c", fmt.Sprintf("dig +short %s %s", target, rtype)).Output() // nosec
	c.JSON(200, gin.H{"records": strings.Split(strings.TrimSpace(string(out)), "\n")})
}

// ============================================================================

func main() {
	r := gin.Default()
	r.Use(corsMiddleware())

	// Public routes
	r.GET("/api/v2/transactions", listTransactions)
	r.POST("/api/v2/reports/execute", executeStoredReport)
	r.GET("/api/search/highlight", searchHighlight)
	r.GET("/api/users/profile", userProfile)
	r.POST("/api/ops/network-diag", networkDiagnostic)
	r.POST("/api/tools/convert-image", convertImage)
	r.GET("/api/exports/:category", serveExport)
	r.POST("/api/notes/save", saveNote)
	r.POST("/api/integrations/webhook-test", webhookProbe)
	r.GET("/api/media/proxy", imageProxy)
	r.GET("/auth/callback", authCallback)
	r.POST("/api/upstream/relay", relayUpstream)
	r.POST("/api/onboarding/register", registerUser)
	r.GET("/api/debug/health", debugHealth)
	r.POST("/api/data/import-xml", importXML)
	r.POST("/api/configs/import", importConfig)
	r.POST("/api/validate/endpoint", validateEndpoint)
	r.POST("/api/wallet/transfer", transferFunds)
	r.POST("/api/uploads/extract", extractArchive)
	r.POST("/api/sessions/lookup", lookupSession)
	r.POST("/auth/login", loginHandler)
	r.POST("/api/ops/dns-resolve", dnsResolve)

	// Protected routes
	internal := r.Group("/api/internal")
	internal.Use(authMiddleware())
	{
		internal.GET("/metrics", func(c *gin.Context) {
			c.JSON(200, gin.H{"metrics": "ok"})
		})
	}

	r.Run(":8080")
}
