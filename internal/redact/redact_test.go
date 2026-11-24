package redact

import (
	"slices"
	"strings"
	"testing"
)

func TestSensitiveName(t *testing.T) {
	for name, want := range map[string]bool{
		"GITHUB_TOKEN": true, "API_KEY": true, "apiKey": true, "OPENAI_API_KEY": true, "Authorization": true,
		"--token": true, "--password": true, "DB_PASSWORD": true, "client_secret": true, "KEY": true, "SSH_KEY": true,
		"PATH": false, "HOME": false, "DEBUG": false, "KEYBOARD": false, "MONKEY_MODE": false, "--verbose": false,
	} {
		if got := SensitiveName(name); got != want {
			t.Errorf("SensitiveName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestString(t *testing.T) {
	tests := map[string]string{
		"key ghp_abcdefghijklmnopqrstuvwxyz0123 end":      "key " + Mask + " end",
		"sk-ant-api03-abcdefghijklmnopqrst":               Mask,
		"AKIAABCDEFGHIJKLMNOP":                            Mask,
		"curl -H 'Authorization: Bearer abcdef123456789'": "curl -H 'Authorization: Bearer " + Mask + "'",
		"plain text": "plain text",
	}
	for in, want := range tests {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInlineSecret(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"GITHUB_TOKEN", "abc123", true},
		{"GITHUB_TOKEN", "${GITHUB_TOKEN}", false},
		{"GITHUB_TOKEN", "$GITHUB_TOKEN", false},
		{"API_KEY", "${env:API_KEY}", false},
		{"API_KEY", "${input:key}", false},
		{"API_KEY", "", false},
		{"LOG_LEVEL", "debug", false},
		{"NOTE", "ghp_abcdefghijklmnopqrstuvwxyz0123", true},
		{"Authorization", "Bearer ${TOKEN}", false},
		{"Authorization", "Bearer abcdefghijklmnop", true},
	} {
		if got := InlineSecret(tc.name, tc.value); got != tc.want {
			t.Errorf("InlineSecret(%q, %q) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}

func TestArgs(t *testing.T) {
	in := []string{"-y", "pkg@1.0.0", "--api-key", "s3cr3t", "--token=abc", "--token", "${TOKEN}", "API_KEY=xyz", "MODE=fast", "--verbose", "ghp_abcdefghijklmnopqrstuvwxyz0123"}
	out, masked := Args(in)
	want := []string{"-y", "pkg@1.0.0", "--api-key", Mask, "--token=" + Mask, "--token", "${TOKEN}", "API_KEY=" + Mask, "MODE=fast", "--verbose", Mask}
	if !slices.Equal(out, want) {
		t.Errorf("Args =\n%q\nwant\n%q", out, want)
	}
	if !slices.Equal(masked, []int{3, 4, 7, 10}) {
		t.Errorf("masked = %v", masked)
	}
	if in[3] != "s3cr3t" {
		t.Error("Args modified its input")
	}
}

func TestURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		changed  bool
	}{
		{"https://mcp.example.com/mcp", "https://mcp.example.com/mcp", false},
		{"https://user:pw@host/x", "https://user:%5BREDACTED%5D@host/x", true},
		{"https://host/sse?api_key=abc&mode=x", "https://host/sse?api_key=%5BREDACTED%5D&mode=x", true},
		{"https://host/sse?key=${KEY}", "https://host/sse?key=${KEY}", false},
		{"https://host/ghp_abcdefghijklmnopqrstuvwxyz0123", "https://host/" + Mask, true},
		{"://bad ghp_abcdefghijklmnopqrstuvwxyz0123", "://bad " + Mask, true},
	} {
		got, changed := URL(tc.in)
		if got != tc.want || changed != tc.changed {
			t.Errorf("URL(%q) = %q, %v; want %q, %v", tc.in, got, changed, tc.want, tc.changed)
		}
		if strings.Contains(got, "pw@") || strings.Contains(got, "=abc") {
			t.Errorf("URL(%q) leaked a secret: %q", tc.in, got)
		}
	}
}

func FuzzRedactNeverLeaksToken(f *testing.F) {
	f.Add("prefix ", " suffix")
	f.Fuzz(func(t *testing.T, a, b string) {
		const tok = "ghp_abcdefghijklmnopqrstuvwxyz0123"
		s := a + " " + tok + " " + b
		if strings.Contains(String(s), tok) {
			t.Fatalf("token leaked from %q", s)
		}
		out, _ := Args([]string{s})
		if strings.Contains(out[0], tok) {
			t.Fatalf("token leaked from args %q", s)
		}
	})
}

func TestHeaderStyleSecrets(t *testing.T) {
	for in, want := range map[string]string{
		`curl -H "X-Api-Key: abc123def" https://x`: `curl -H "X-Api-Key: [REDACTED]" https://x`,
		`--header Authorization:sometoken123`:      `--header Authorization:[REDACTED]`,
		`curl -H "X-Api-Key: ${API_KEY}"`:          `curl -H "X-Api-Key: ${API_KEY}"`,
		`curl -H "Content-Type: application/json"`: `curl -H "Content-Type: application/json"`,
		`https://example.com:8443/path`:            `https://example.com:8443/path`,
	} {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
	out, masked := Args([]string{"--header", "X-Auth-Token: s3cr3tvalue"})
	if out[1] != "X-Auth-Token: "+Mask || len(masked) != 1 {
		t.Errorf("Args header = %q %v", out, masked)
	}
}
