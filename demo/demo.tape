# README demo. Record with VHS (https://github.com/charmbracelet/vhs):
#
#   vhs demo/demo.tape
#
# Needs lockward 0.2.1 or later on PATH (brew install breaktroughf1/tap/lockward).
# Writes demo/lockward.gif. Only --scope project is used, so nothing from
# your home directory appears in the recording.

Output demo/lockward.gif

Require lockward
Require git

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

Hide
Type "source demo/setup.sh" Enter
Sleep 500ms
Show

Type "# Pin every agent skill and MCP server in this repo" Enter
Type "lockward lock --scope project" Sleep 300ms Enter
Sleep 2s

Type "lockward verify --scope project" Sleep 300ms Enter
Sleep 2.5s

Type "clear" Enter
Type "# A routine-looking update lands..." Enter
Type "./simulate-update.sh" Sleep 300ms Enter
Sleep 1s

Type "lockward verify --scope project; echo exit=$?" Sleep 300ms Enter
Sleep 6s

Type "clear" Enter
Type "lockward diff skill:claude-code:pdf-tools" Sleep 300ms Enter
Sleep 5s
