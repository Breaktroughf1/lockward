// Package adapter holds one subpackage per supported agent. Each adapter
// discovers that agent's skills, MCP servers, hooks and rules files from an
// fs.FS, read-only, without executing anything or following symlinks outside
// the filesystem root. Adapters must not import each other.
//
// Requirements: LW-FR-01, LW-NFR-03.
package adapter
