package spec

import "testing"

func valid() Spec {
	return Spec{JobID: "0b6e5a1c-1111-4222-8333-444455556666", Host: "192.0.2.10", Port: 22, Username: "capture",
		CredentialRef: "soc-key", Interface: "eth0", DurationSecs: 30, Filter: "udp port 53", MaxBytes: 1 << 20}
}

func TestValidSpec(t *testing.T) {
	s := valid()
	if err := s.Validate(3600); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInjectionAndBadValues(t *testing.T) {
	cases := map[string]func(*Spec){
		"host name":        func(s *Spec) { s.Host = "example.com" },
		"host injection":   func(s *Spec) { s.Host = "1.2.3.4;id" },
		"port zero":        func(s *Spec) { s.Port = 0 },
		"port high":        func(s *Spec) { s.Port = 70000 },
		"user injection":   func(s *Spec) { s.Username = "a$(id)" },
		"user leading dig": func(s *Spec) { s.Username = "1abc" },
		"cred traversal":   func(s *Spec) { s.CredentialRef = "../etc/shadow" },
		"cred slash":       func(s *Spec) { s.CredentialRef = "a/b" },
		"cred hidden":      func(s *Spec) { s.CredentialRef = ".ssh" },
		"iface semicolon":  func(s *Spec) { s.Interface = "eth0;reboot" },
		"iface space":      func(s *Spec) { s.Interface = "eth0 -w /x" },
		"filter semicolon": func(s *Spec) { s.Filter = "port 22; id" },
		"filter backtick":  func(s *Spec) { s.Filter = "`id`" },
		"filter quote":     func(s *Spec) { s.Filter = "a' ; id #" },
		"filter newline":   func(s *Spec) { s.Filter = "a\nb" },
		"duration zero":    func(s *Spec) { s.DurationSecs = 0 },
		"duration long":    func(s *Spec) { s.DurationSecs = 999999 },
		"max bytes":        func(s *Spec) { s.MaxBytes = 0 },
		"job id":           func(s *Spec) { s.JobID = "../../x" },
	}
	for name, mutate := range cases {
		s := valid()
		mutate(&s)
		if err := s.Validate(3600); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestEmptyFilterIsAllowed(t *testing.T) {
	s := valid()
	s.Filter = ""
	if err := s.Validate(60); err != nil {
		t.Fatal(err)
	}
}
