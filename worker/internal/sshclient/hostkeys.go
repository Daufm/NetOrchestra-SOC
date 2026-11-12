package sshclient

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // OpenSSH hashed known_hosts entries are defined as HMAC-SHA1
	"encoding/base64"
	"os"
	"path"
	"strings"
)

// algorithmsFor returns the SSH host-key algorithms we hold a trusted key for, for the given
// (already normalised) address. Restricting negotiation to these makes the server present a key
// type we can verify, instead of failing when it prefers another type. An empty result means
// the host is unknown and the verification callback will refuse it.
func algorithmsFor(knownHostsPath, normalizedAddr string) []string {
	f, err := os.Open(knownHostsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if strings.HasPrefix(fields[0], "@") { // @revoked / @cert-authority are not plain trusted host keys
			continue
		}
		if !hostMatches(fields[0], normalizedAddr) {
			continue
		}
		switch kt := fields[1]; kt {
		case "ssh-rsa":
			add("rsa-sha2-512")
			add("rsa-sha2-256")
		default:
			add(kt)
		}
	}
	return out
}

func hostMatches(hostField, addr string) bool {
	matched := false
	for _, pat := range strings.Split(hostField, ",") {
		negated := strings.HasPrefix(pat, "!")
		pat = strings.TrimPrefix(pat, "!")
		ok := false
		if strings.HasPrefix(pat, "|1|") {
			ok = hashedMatches(pat, addr)
		} else if strings.ContainsAny(pat, "*?") {
			ok, _ = path.Match(pat, addr)
		} else {
			ok = pat == addr
		}
		if ok {
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

func hashedMatches(pat, addr string) bool {
	parts := strings.Split(pat, "|") // "", "1", salt, hash
	if len(parts) != 4 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[2])
	want, err2 := base64.StdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(addr))
	return hmac.Equal(mac.Sum(nil), want)
}
