package main

import "runtime/debug"

// version is set at release time with -ldflags "-X main.version=<v>".
var version = ""

// resolveVersion returns the injected version, else the module version from
// build info (set by "go install ...@vX"), else "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
