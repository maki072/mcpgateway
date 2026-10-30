package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const pbkdf2Iter = 600000

// AuthFile holds the single operator's passphrase hash and TOTP secret.
type AuthFile struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iter       int    `json:"iter"`
	TOTPSecret string `json:"totp_secret"` // base32, no padding

	mu       sync.Mutex
	lastStep int64
}

func loadAuth(path string) (*AuthFile, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be accessible by group/others", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a AuthFile
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	if a.Salt == "" || a.Hash == "" || a.TOTPSecret == "" || a.Iter < 100000 {
		return nil, errors.New("auth file incomplete")
	}
	return &a, nil
}

func hashPass(pass string, salt []byte, iter int) (string, error) {
	k, err := pbkdf2.Key(sha256.New, pass, salt, iter, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

func totpAt(secret []byte, step int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	s := h.Sum(nil)
	o := s[len(s)-1] & 0x0f
	code := (uint32(s[o]&0x7f)<<24 | uint32(s[o+1])<<16 | uint32(s[o+2])<<8 | uint32(s[o+3])) % 1000000
	return fmt.Sprintf("%06d", code)
}

// verify checks passphrase and a TOTP code (+-1 step); a code can be used only once.
func (a *AuthFile) verify(pass, code string) bool {
	salt, err := hex.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	h, err := hashPass(pass, salt, a.Iter)
	passOK := err == nil && subtle.ConstantTimeCompare([]byte(h), []byte(a.Hash)) == 1
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.TOTPSecret)
	if err != nil {
		return false
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().Unix() / 30
	codeOK := false
	for d := int64(-1); d <= 1; d++ {
		step := now + d
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 && step > a.lastStep {
			a.lastStep = step
			codeOK = true
			break
		}
	}
	return passOK && codeOK
}

// runSetup interactively creates the auth file. Run it yourself on the gateway host.
func runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	path := fs.String("auth", "/etc/mcpgw/auth.json", "auth file to write")
	issuer := fs.String("label", "mcpgw", "label shown in the authenticator app")
	_ = fs.Parse(args)
	if _, err := os.Stat(*path); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists; remove it first to re-run setup\n", *path)
		return 1
	}
	p1 := readSecret("New passphrase (min 16 chars): ")
	p2 := readSecret("Repeat passphrase: ")
	if p1 != p2 || len(p1) < 16 {
		fmt.Fprintln(os.Stderr, "passphrases differ or are shorter than 16 characters")
		return 1
	}
	salt := make([]byte, 16)
	sec := make([]byte, 20)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(sec)
	h, err := hashPass(p1, salt, pbkdf2Iter)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sec)
	a := AuthFile{Salt: hex.EncodeToString(salt), Hash: h, Iter: pbkdf2Iter, TOTPSecret: b32}
	out, _ := json.MarshalIndent(&a, "", "  ")
	if err := os.WriteFile(*path, out, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Saved %s\n\nAdd this account to your authenticator app (type the key manually):\n  Key: %s\n  URI: otpauth://totp/%s?secret=%s&issuer=%s\n", *path, b32, *issuer, b32, *issuer)
	return 0
}

func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	_ = exec.Command("stty", "-echo").Run()
	defer func() { _ = exec.Command("stty", "echo").Run(); fmt.Fprintln(os.Stderr) }()
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// Limiter locks logins globally after repeated failures (there is exactly one operator).
type Limiter struct {
	mu       sync.Mutex
	fails    []time.Time
	lockedTo time.Time
}

func newLimiter() *Limiter { return &Limiter{} }

func (l *Limiter) locked() (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := time.Until(l.lockedTo); d > 0 {
		return true, d
	}
	return false, 0
}

func (l *Limiter) fail() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	keep := l.fails[:0]
	for _, t := range l.fails {
		if now.Sub(t) < 15*time.Minute {
			keep = append(keep, t)
		}
	}
	l.fails = append(keep, now)
	if len(l.fails) >= 5 {
		l.lockedTo = now.Add(15 * time.Minute)
		l.fails = nil
	}
}

func (l *Limiter) ok() {
	l.mu.Lock()
	l.fails = nil
	l.mu.Unlock()
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
