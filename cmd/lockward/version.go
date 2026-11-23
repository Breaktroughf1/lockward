package main

import (
	"runtime/debug"
	"strings"
)

// version is set at release time with -ldflags "-X main.version=<v>".
var version = ""

// resolveVersion returns the injected version, else the module version from
// build info (set by "go install ...@vX"), else "dev". A leading "v" is
// dropped so lockfiles record "lockward 0.1.0" (SPEC §3).
func resolveVersion() string {
	v := version
	if v == "" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	if v == "" {
		return "dev"
	}
	return strings.TrimPrefix(v, "v")
}
