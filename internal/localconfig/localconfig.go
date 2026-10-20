// Package localconfig knows where Vanzik keeps its files for the
// current user: the config folder (starter policy, API key, what
// `vanzik setup` set up) and the data folder setup creates for the
// audit log and state database. The config folder is the one the
// installers write the starter policy to (scripts/install.sh,
// scripts/install.ps1), so every piece agrees on it.
//
// Functions take the OS as a parameter so tests can check every layout
// from any machine.
package localconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// Names of the files in the config folder.
const (
	PolicyFile = "default.yaml"
	APIKeyFile = "api-key"
	SetupFile  = "setup.json"
)

// ConfigDir is the user's Vanzik config folder:
// $XDG_CONFIG_HOME/vanzik (else ~/.config/vanzik, on macOS too,
// like the installer), or %APPDATA%\vanzik on Windows. Empty when the
// home folder is unknown.
func ConfigDir(goos string) string { return configDir(goos, "vanzik") }

// DataDir is where `vanzik setup` keeps the audit log, the state
// database and the server log: $XDG_DATA_HOME/vanzik (else
// ~/.local/share/vanzik), or %LOCALAPPDATA%\Vanzik\data on Windows.
func DataDir(goos string) string { return dataDir(goos, "vanzik", "Vanzik") }

// LegacyConfigDir and LegacyDataDir are the same folders as AgentGuard 1.x
// named them (~/.config/agentguard, %LOCALAPPDATA%\AgentGuard\data, ...).
// Only the migration to Vanzik reads them: it moves what is there into
// ConfigDir and DataDir.
func LegacyConfigDir(goos string) string { return configDir(goos, "agentguard") }
func LegacyDataDir(goos string) string   { return dataDir(goos, "agentguard", "AgentGuard") }

func configDir(goos, name string) string {
	if goos == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, name)
		}
		return ""
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, name)
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", name)
	}
	return ""
}

// dataDir takes the folder's name twice: on Windows it is a product folder
// under %LOCALAPPDATA% (title case), elsewhere an XDG one.
func dataDir(goos, name, windowsName string) string {
	if goos == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, windowsName, "data")
		}
		return ""
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, name)
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", name)
	}
	return ""
}

// APIKeyPath is the file `vanzik setup` saves the server's API key in.
func APIKeyPath(goos string) string {
	if d := ConfigDir(goos); d != "" {
		return filepath.Join(d, APIKeyFile)
	}
	return ""
}

// ReadAPIKey returns the key saved by `vanzik setup`, or "" when there
// is none. Client commands fall back to it when neither --api-key nor
// VANZIK_API_KEY is set; the server never reads it implicitly (a key
// changes which interfaces it listens on), only through --api-key-file.
func ReadAPIKey(goos string) string {
	p := APIKeyPath(goos)
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return FirstLine(b)
}

// FirstLine is the first line of b without surrounding whitespace: how a
// key file is read, so a trailing newline from an editor doesn't count.
func FirstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
