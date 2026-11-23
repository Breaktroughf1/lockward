package adapter

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/redact"
)

// Dialect selects field-name conventions that differ between agents.
type Dialect int

// Dialects.
const (
	DialectDefault Dialect = iota
	DialectGemini          // "url" means SSE, "httpUrl" means streamable HTTP
	DialectCodex           // TOML keys: http_headers, env_vars, bearer_token_env_var
)

// ServerOptions describes where a server definition lives.
type ServerOptions struct {
	Agent    string
	LoadedBy []string
	File     string   // config file, relative to the scope root
	Pointer  []string // JSON pointer tokens to the servers map, e.g. {"mcpServers"}
	Dialect  Dialect
	// NamePrefix is prepended to server names in ids (e.g. a Claude
	// local-scope project path) to keep them unique.
	NamePrefix string
}

// Servers parses a map of MCP server definitions into assets. Values that are
// not objects produce problems, not crashes.
func Servers(servers map[string]any, o ServerOptions) Result {
	var r Result
	for _, name := range SortedKeys(servers) {
		ptr := Pointer(append(append([]string{}, o.Pointer...), name)...)
		m, ok := servers[name].(map[string]any)
		if !ok {
			r.Problem(o.Agent, o.File+"#"+ptr, "MCP server definition is not an object; skipped")
			continue
		}
		srv, secrets, auto := ParseServer(m, o.Dialect)
		a := asset.Asset{
			Surface:       asset.SurfaceMCP,
			Agent:         o.Agent,
			LoadedBy:      o.LoadedBy,
			Name:          o.NamePrefix + name,
			Path:          o.File + "#" + ptr,
			File:          o.File,
			Server:        srv,
			Source:        SourceOf(srv),
			InlineSecrets: secrets,
		}
		for _, s := range auto {
			a.AutoApprove = append(a.AutoApprove, fmt.Sprintf("MCP server %q: %s", name, s))
		}
		r.Assets = append(r.Assets, a)
	}
	return r
}

// ParseServer converts one server object to the recorded form. It returns
// the locations of inline secrets (never their values) and any per-server
// auto-approval settings.
func ParseServer(m map[string]any, d Dialect) (srv *asset.MCPServer, secrets, autoApprove []string) {
	srv = &asset.MCPServer{}
	cmd := Str(m, "command")
	if c := redact.String(cmd); c != cmd {
		secrets = append(secrets, "command")
		cmd = c
	}
	srv.Command = cmd
	args, masked := redact.Args(Strings(m, "args"))
	for _, i := range masked {
		secrets = append(secrets, fmt.Sprintf("args[%d]", i))
	}
	if len(args) > 0 {
		srv.Args = args
	}
	srv.Cwd = Str(m, "cwd")

	rawURL, urlKey := firstString(m, "httpUrl", "url", "serverUrl")
	if rawURL != "" {
		u, changed := redact.URL(rawURL)
		if changed {
			secrets = append(secrets, urlKey)
		}
		srv.URL = u
	}

	envKeys := map[string]bool{}
	for k, v := range Obj(m, "env") {
		envKeys[k] = true
		if s, ok := v.(string); ok && redact.InlineSecret(k, s) {
			secrets = append(secrets, "env."+k)
		}
	}
	headerKeys := map[string]bool{}
	for _, hk := range []string{"headers", "http_headers"} {
		for k, v := range Obj(m, hk) {
			headerKeys[k] = true
			if s, ok := v.(string); ok && redact.InlineSecret(k, s) {
				secrets = append(secrets, hk+"."+k)
			}
		}
	}
	if d == DialectCodex {
		for k := range Obj(m, "env_http_headers") {
			headerKeys[k] = true
		}
		for _, v := range List(m, "env_vars") {
			switch t := v.(type) {
			case string:
				envKeys[t] = true
			case map[string]any:
				if n := Str(t, "name"); n != "" {
					envKeys[n] = true
				}
			}
		}
		if n := Str(m, "bearer_token_env_var"); n != "" {
			envKeys[n] = true
		}
		if s := Str(m, "bearer_token"); s != "" && !redact.IsReference(s) {
			secrets = append(secrets, "bearer_token")
		}
	}
	srv.EnvKeys = SortedKeys(envKeys)
	srv.HeaderKeys = SortedKeys(headerKeys)
	if len(srv.EnvKeys) == 0 {
		srv.EnvKeys = nil
	}
	if len(srv.HeaderKeys) == 0 {
		srv.HeaderKeys = nil
	}

	srv.Transport = transport(m, urlKey, d)
	srv.Disabled = Bool(m, "disabled") || (m["enabled"] == false)
	if Bool(m, "trust") {
		srv.Trust = true
		autoApprove = append(autoApprove, "trust: true bypasses all tool confirmations")
	}
	if mode := Str(m, "default_tools_approval_mode"); mode != "" {
		srv.ApprovalMode = mode
		if mode == "approve" {
			autoApprove = append(autoApprove, `default_tools_approval_mode = "approve"`)
		}
	}
	for tool, tv := range Obj(m, "tools") {
		if t, ok := tv.(map[string]any); ok && Str(t, "approval_mode") == "approve" {
			autoApprove = append(autoApprove, fmt.Sprintf("tools.%s.approval_mode = \"approve\"", tool))
		}
	}
	if srv.Transport == "stdio" {
		srv.Package = DetectPackage(srv.Command, srv.Args)
	}
	return srv, secrets, autoApprove
}

func firstString(m map[string]any, keys ...string) (val, key string) {
	for _, k := range keys {
		if s := Str(m, k); s != "" {
			return s, k
		}
	}
	return "", ""
}

func transport(m map[string]any, urlKey string, d Dialect) string {
	t := strings.ToLower(Str(m, "type"))
	if t == "" {
		t = strings.ToLower(Str(m, "transport"))
	}
	switch t {
	case "stdio", "local":
		return "stdio"
	case "http", "streamable-http", "streamablehttp", "streamable_http":
		return "http"
	case "sse":
		return "sse"
	case "ws", "websocket":
		return "ws"
	case "":
	default:
		return t
	}
	switch {
	case Str(m, "command") != "":
		return "stdio"
	case urlKey == "url" && d == DialectGemini:
		return "sse"
	case urlKey != "":
		return "http"
	}
	return "stdio"
}

// SourceOf derives provenance for policy rule LW002.
func SourceOf(srv *asset.MCPServer) *asset.Source {
	switch {
	case srv.Package != nil:
		ref := srv.Package.Name
		return &asset.Source{Type: srv.Package.Ecosystem, Ref: ref, Resolved: srv.Package.Spec}
	case srv.URL != "":
		u, err := url.Parse(srv.URL)
		if err == nil && u.Host != "" {
			return &asset.Source{Type: "url", Ref: u.Hostname()}
		}
		return &asset.Source{Type: "url", Ref: srv.URL}
	case srv.Command != "":
		return &asset.Source{Type: "local", Ref: srv.Command}
	}
	return nil
}

var (
	semverExact = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	pep440Exact = regexp.MustCompile(`^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$`)
	gitSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ociDigest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// launcherFlagsWithValue lists flags that consume the next argument.
var launcherFlagsWithValue = map[string][]string{
	"npm":    {"-p", "--package", "-c", "--call", "--registry", "--cache", "--prefix", "-w", "--workspace"},
	"pypi":   {"--from", "--with", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url", "--extra-index-url", "--spec", "--pip-args", "-c", "--constraints"},
	"docker": {"-e", "--env", "--env-file", "-v", "--volume", "--name", "--network", "--net", "-p", "--publish", "-w", "--workdir", "--entrypoint", "-u", "--user", "--mount", "--platform", "-l", "--label", "--add-host", "--cap-add", "--cap-drop", "--device", "-h", "--hostname", "-m", "--memory", "--cpus", "--pull", "--restart", "--security-opt", "--tmpfs", "--ulimit", "--runtime", "--gpus", "--ipc", "--pid", "--log-driver", "--log-opt", "--dns", "--expose", "--group-add", "--shm-size", "--stop-signal", "--userns", "--uts", "--cgroupns", "--label-file", "--link", "--network-alias"},
}

// DetectPackage identifies the package an MCP server command launches, for
// npx/bunx/pnpm dlx/yarn dlx/npm exec (npm), uvx/uv tool run/pipx run (PyPI)
// and docker/podman run (OCI). It returns nil for other commands.
func DetectPackage(command string, args []string) *asset.Package {
	base := strings.ToLower(path.Base(strings.ReplaceAll(command, `\`, "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		base = strings.TrimSuffix(base, ext)
	}
	switch {
	case base == "npx" || base == "bunx" || base == "pnpx":
		return npmPackage(args)
	case (base == "pnpm" || base == "yarn" || base == "bun") && len(args) > 0 && (args[0] == "dlx" || args[0] == "x"):
		return npmPackage(args[1:])
	case base == "npm" && len(args) > 0 && (args[0] == "exec" || args[0] == "x"):
		return npmPackage(args[1:])
	case base == "uvx":
		return pypiPackage(args)
	case base == "uv" && len(args) > 1 && args[0] == "tool" && args[1] == "run":
		return pypiPackage(args[2:])
	case base == "pipx" && len(args) > 0 && args[0] == "run":
		return pypiPackage(args[1:])
	case (base == "docker" || base == "podman" || base == "nerdctl") && len(args) > 0 && args[0] == "run":
		return ociPackage(args[1:])
	}
	return nil
}

// launcherArgs finds the first positional argument and the value of any
// package-selecting flag.
func launcherArgs(args []string, eco string, pkgFlags ...string) (positional, pkgFlag string) {
	withValue := launcherFlagsWithValue[eco]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1], pkgFlag
			}
			return "", pkgFlag
		}
		if strings.HasPrefix(a, "-") {
			name, val, hasVal := strings.Cut(a, "=")
			if contains(pkgFlags, name) {
				if hasVal {
					pkgFlag = val
				} else if i+1 < len(args) {
					pkgFlag = args[i+1]
				}
			}
			if !hasVal && contains(withValue, name) {
				i++
			}
			continue
		}
		return a, pkgFlag
	}
	return "", pkgFlag
}

func npmPackage(args []string) *asset.Package {
	pos, flagPkg := launcherArgs(args, "npm", "-p", "--package")
	spec := pos
	if flagPkg != "" {
		spec = flagPkg
	}
	p := &asset.Package{Ecosystem: "npm", Spec: spec}
	if spec == "" {
		return p
	}
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "github:") || strings.HasPrefix(spec, "file:") {
		p.Name = spec
		if _, ref, ok := strings.Cut(spec, "#"); ok && gitSHA.MatchString(ref) {
			p.Version = ref
		}
		return p
	}
	name, version := spec, ""
	if at := strings.LastIndex(spec, "@"); at > 0 {
		name, version = spec[:at], spec[at+1:]
	}
	p.Name = name
	if semverExact.MatchString(version) {
		p.Version = version
	}
	return p
}

func pypiPackage(args []string) *asset.Package {
	pos, flagPkg := launcherArgs(args, "pypi", "--from", "--spec")
	spec := pos
	if flagPkg != "" {
		spec = flagPkg
	}
	p := &asset.Package{Ecosystem: "pypi", Spec: spec}
	if spec == "" {
		return p
	}
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") {
		p.Name = spec
		if i := strings.LastIndex(spec, "@"); i > 0 && gitSHA.MatchString(spec[i+1:]) {
			p.Version = spec[i+1:]
		}
		return p
	}
	name, version := spec, ""
	switch {
	case strings.Contains(spec, "=="):
		name, version, _ = strings.Cut(spec, "==")
	case strings.Contains(spec, "@"):
		name, version, _ = strings.Cut(spec, "@")
	default:
		if i := strings.IndexAny(spec, "<>=!~"); i > 0 {
			name = spec[:i]
		}
	}
	if i := strings.IndexByte(name, '['); i > 0 {
		name = name[:i]
	}
	p.Name = strings.TrimSpace(name)
	if pep440Exact.MatchString(strings.TrimSpace(version)) {
		p.Version = strings.TrimSpace(version)
	}
	return p
}

func ociPackage(args []string) *asset.Package {
	img, _ := launcherArgs(args, "docker")
	p := &asset.Package{Ecosystem: "oci", Spec: img}
	if img == "" {
		return p
	}
	name := img
	if before, digest, ok := strings.Cut(img, "@"); ok {
		name = before
		if ociDigest.MatchString(digest) {
			p.Digest = digest
		}
	}
	if slash := strings.LastIndex(name, "/"); strings.LastIndex(name, ":") > slash {
		i := strings.LastIndex(name, ":")
		p.Version = name[i+1:]
		name = name[:i]
	}
	p.Name = name
	return p
}
