// Security vulnerability test file — Go
// 30 intentional vulnerabilities for rule coverage testing.
// DO NOT USE IN PRODUCTION.

package vulntest

import (
	"crypto/des"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// =================================================================
// 1. SQL Injection — string concat
// =================================================================
func FindUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db, _ := sql.Open("mysql", "user:pass@/app")
	defer db.Close()

	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	defer rows.Close()
	fmt.Fprintf(w, "rows: %v", rows)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db, _ := sql.Open("mysql", "user:pass@/app")
	db.Exec("DELETE FROM users WHERE id = " + id)
}

func UpdateRole(w http.ResponseWriter, r *http.Request) {
	role := r.FormValue("role")
	uid := r.FormValue("uid")
	db, _ := sql.Open("mysql", "user:pass@/app")
	db.Exec("UPDATE users SET role = '" + role + "' WHERE id = " + uid)
}

// =================================================================
// 2. XSS — Fprintf to ResponseWriter
// =================================================================
func Greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Welcome %s</h1>", name)
}

func ShowError(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	fmt.Fprintf(w, "<div class='error'>%s</div>", msg)
}

// =================================================================
// 3. Command injection — exec.Command with shell
// =================================================================
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 4 "+host)
	out, _ := cmd.CombinedOutput()
	w.Write(out)
}

func CatFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	cmd := exec.Command("bash", "-c", "cat /data/"+name)
	out, _ := cmd.CombinedOutput()
	w.Write(out)
}

func GrepLogs(w http.ResponseWriter, r *http.Request) {
	pattern := r.URL.Query().Get("q")
	cmd := exec.Command("sh", "-c", fmt.Sprintf("grep '%s' /var/log/app.log", pattern))
	out, _ := cmd.CombinedOutput()
	w.Write(out)
}

// =================================================================
// 4. Path traversal
// =================================================================
func Download(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	data, _ := ioutil.ReadFile("/uploads/" + file)
	w.Write(data)
}

func ServeAvatar(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	http.ServeFile(w, r, "/data/avatars/"+user+".png")
}

func ReadConfig(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, _ := os.ReadFile("/etc/app/" + name)
	w.Write(data)
}

// =================================================================
// 5. SSRF
// =================================================================
func FetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

func ProxyWebhook(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("callback")
	http.Post(target, "application/json", r.Body)
	fmt.Fprint(w, "ok")
}

// =================================================================
// 6. Hardcoded secrets
// =================================================================
const (
	DBPassword   = "SuperSecret123!@#"
	AWSSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	JWTSecret    = "jwt-signing-secret-key"
	APIKey       = "sk-prod-1234567890abcdef"
)

var dsn = fmt.Sprintf("admin:%s@tcp(db:3306)/app", DBPassword)

// =================================================================
// 7. Weak crypto — MD5
// =================================================================
func HashPW(pw string) string {
	h := md5.Sum([]byte(pw))
	return hex.EncodeToString(h[:])
}

func TokenHash(uid string) string {
	h := md5.Sum([]byte(uid + "-token"))
	return hex.EncodeToString(h[:])
}

// =================================================================
// 8. Weak crypto — DES
// =================================================================
func EncryptDES(data []byte) ([]byte, error) {
	key := []byte("12345678")
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	block.Encrypt(out, data)
	return out, nil
}

// =================================================================
// 9. Insecure random
// =================================================================
func OTP() int {
	return rand.Intn(999999)
}

func SessionID() string {
	return fmt.Sprintf("%d-%d", rand.Int(), rand.Int())
}

// =================================================================
// 10. Open redirect
// =================================================================
func LoginRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func OAuthCallback(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}

// =================================================================
// 11. Sensitive data in response
// =================================================================
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")
	pass := r.FormValue("password")
	fmt.Printf("Login: user=%s, pass=%s\n", user, pass)

	db, _ := sql.Open("mysql", dsn)
	row := db.QueryRow("SELECT * FROM users WHERE username='" + user + "'")

	var u string
	if err := row.Scan(&u); err != nil {
		fmt.Fprintf(w, `{"error":"%s","dsn":"%s"}`, err.Error(), dsn)
		return
	}
	fmt.Fprintf(w, `{"user":"%s"}`, u)
}

// =================================================================
// 12. Debug endpoint — environ exposure
// =================================================================
func DebugHandler(w http.ResponseWriter, r *http.Request) {
	for _, env := range os.Environ() {
		fmt.Fprintln(w, env)
	}
}

// =================================================================
// 13. XXE — xml.Unmarshal
// =================================================================
type Config struct {
	XMLName xml.Name `xml:"config"`
	Admin   bool     `xml:"admin"`
}

func ParseConfig(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	var cfg Config
	xml.Unmarshal(body, &cfg)
	fmt.Fprintf(w, "Config: %+v", cfg)
}

// =================================================================
// 14. Race condition — no mutex
// =================================================================
var balance = 1000

func Withdraw(w http.ResponseWriter, r *http.Request) {
	amount := 100
	if balance >= amount {
		balance -= amount // TOCTOU race
		fmt.Fprintf(w, "Balance: %d", balance)
	}
}

// =================================================================
// 15. Nil dereference — unchecked error
// =================================================================
func ReadDB() string {
	db, err := sql.Open("mysql", dsn)
	row := db.QueryRow("SELECT name FROM users LIMIT 1") // db may be nil
	var name string
	row.Scan(&name)
	_ = err
	return name
}
