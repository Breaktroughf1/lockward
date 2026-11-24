// Package redact removes secret values from strings before they are stored
// or printed. Lockward records names, never values (THREAT_MODEL §6
// invariant 5, SPEC §4.2).
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// Mask replaces a redacted value.
const Mask = "[REDACTED]"

// tokenPatterns match well-known credential formats anywhere in a string.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`pypi-[A-Za-z0-9_-]{50,}`),
	regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

// headerPattern masks "Name: value" header pairs whose name holds a secret,
// as in curl -H "X-Api-Key: abc123" or --header "Authorization: token".
var headerPattern = regexp.MustCompile(`(?i)\b([A-Za-z0-9-]*(?:api[-_]?key|token|secret|password|auth[A-Za-z-]*|cookie|session)[A-Za-z0-9-]*\s*:\s*)([^\s"'$][^\s"']{3,})`)

// bearerPattern keeps the scheme word and masks the credential.
var bearerPattern = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}`)

// sensitiveName matches variable, header, flag and query names that hold secrets.
var sensitiveName = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth|cookie|session|bearer|signature|(^|[_-])key$|^key$)`)

// SensitiveName reports whether a name (env var, header, flag, query
// parameter) conventionally holds a secret.
func SensitiveName(name string) bool {
	return sensitiveName.MatchString(strings.TrimLeft(name, "-"))
}

// ContainsToken reports whether s contains a well-known credential format.
func ContainsToken(s string) bool {
	if bearerPattern.MatchString(s) {
		return true
	}
	for _, re := range tokenPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// String masks well-known credential formats inside s.
func String(s string) string {
	for _, re := range tokenPatterns {
		s = re.ReplaceAllString(s, Mask)
	}
	s = bearerPattern.ReplaceAllString(s, "$1 "+Mask)
	return headerPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := headerPattern.FindStringSubmatch(m)
		switch strings.ToLower(sub[2]) {
		case "bearer", "basic", "token", "digest", "negotiate": // scheme word; bearerPattern masks the credential
			return m
		}
		if sub[2] == Mask || strings.HasPrefix(sub[2], "[REDACTED") || IsReference(sub[2]) {
			return m
		}
		return sub[1] + Mask
	})
}

// IsReference reports whether a config value refers to a secret indirectly
// (environment or input variable) rather than containing it.
func IsReference(v string) bool {
	return strings.Contains(v, "${") || refPattern.MatchString(v) || strings.Contains(v, "{env:")
}

var refPattern = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)

// InlineSecret reports whether value, stored under name, looks like a secret
// written inline instead of referenced (policy rule LW007).
func InlineSecret(name, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || IsReference(v) {
		return false
	}
	return SensitiveName(name) || ContainsToken(v)
}

// Args masks secret values in a command-line argument list and reports the
// positions masked (as "args[i]"). It handles "--token VALUE",
// "--token=VALUE", "NAME=VALUE" with a sensitive name, and embedded tokens.
// Variable references are kept, since they are not secrets.
func Args(args []string) (out []string, masked []int) {
	out = make([]string, len(args))
	prev := ""
	for i, a := range args {
		out[i] = a
		afterFlag := isSensitiveFlag(prev)
		prev = a
		if afterFlag && !strings.HasPrefix(a, "-") && !IsReference(a) && a != "" {
			out[i] = Mask
			masked = append(masked, i)
			continue
		}
		if k, v, ok := strings.Cut(a, "="); ok && v != "" && !IsReference(v) && SensitiveName(k) {
			out[i] = k + "=" + Mask
			masked = append(masked, i)
			continue
		}
		if r := String(a); r != a {
			out[i] = r
			masked = append(masked, i)
		}
	}
	return out, masked
}

func isSensitiveFlag(a string) bool {
	if !strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
		return false
	}
	return SensitiveName(a)
}

// URL masks credentials in a URL: userinfo passwords, sensitive query
// parameter values and embedded tokens. It reports whether anything was
// masked. Unparseable URLs fall back to token masking.
func URL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		r := String(raw)
		return r, r != raw
	}
	changed := false
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), Mask)
			changed = true
		}
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k, vs := range q {
			for i, v := range vs {
				if v != "" && !IsReference(v) && (SensitiveName(k) || ContainsToken(v)) {
					vs[i] = Mask
					changed = true
				}
			}
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	if !changed {
		r := String(raw)
		return r, r != raw
	}
	return String(u.String()), true
}
