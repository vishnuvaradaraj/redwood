package redwood

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// HTTP proxy authentication.

func (c *config) readPasswordFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		space := strings.IndexAny(line, " \t")
		if space == -1 {
			log.Println("malformed line in password file:", line)
			continue
		}

		user := line[:space]
		pass := strings.TrimSpace(line[space:])
		c.Passwords[user] = pass
	}

	return nil
}

func (c *config) send407(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm="+c.AuthRealm)
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

// ProxyCredentials returns the username and password from r's
// Proxy-Authorization header, or empty strings if the header is missing or
// invalid.
func ProxyCredentials(r *http.Request) (user, pass string) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return "", ""
	}

	auth = auth[len("Basic "):]
	auth = strings.TrimSpace(auth)
	enc := base64.StdEncoding
	buf := make([]byte, enc.DecodedLen(len(auth)))
	n, err := enc.Decode(buf, []byte(auth))
	if err != nil {
		return "", ""
	}
	auth = string(buf[:n])

	colon := strings.Index(auth, ":")
	if colon == -1 {
		return "", ""
	}

	return auth[:colon], auth[colon+1:]
}

// ValidCredentials returns whether user and password are a valid combination.
func (conf *config) ValidCredentials(user, password string) bool {
	conf.PasswordLock.RLock()
	ok := password == conf.Passwords[user] && password != ""
	conf.PasswordLock.RUnlock()
	if ok {
		return true
	}

	for _, a := range conf.Authenticators {
		if a(user, password) {
			if _, ok := conf.Passwords[user]; !ok {
				// Cache the password for later use.
				conf.PasswordLock.Lock()
				conf.Passwords[user] = password
				conf.PasswordLock.Unlock()
			}
			return true
		}
	}
	return false
}

func (cf *config) startAuthHelper(cmd string) error {
	c := exec.Command(cmd)
	in, err := c.StdinPipe()
	if err != nil {
		return err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	err = c.Start()
	if err != nil {
		return err
	}

	var m sync.Mutex
	cf.Authenticators = append(cf.Authenticators, func(user, password string) bool {
		m.Lock()
		defer m.Unlock()
		fmt.Fprintln(in, user, password)
		var response string
		fmt.Fscanln(out, &response)
		if response == "OK" {
			return true
		}
		return false
	})

	return nil
}

type authRecord struct {
	ProxyAuthorization string
	Time               time.Time
}

var authCache = map[string]authRecord{}
var authCacheLock sync.RWMutex
