// Package legacyenv knows the environment variables AgentGuard 1.x read,
// AGENTGUARD_<NAME>, which Vanzik 2 reads as VANZIK_<NAME>. Vanzik never
// uses their values. It checks for them because ignoring one silently
// would change what a program does: a server started without the API key
// its operator set, a gateway checking calls against the wrong server, a
// check run against a different policy.
package legacyenv

import (
	"fmt"
	"os"
	"strings"
)

// MigrationURL is the guide that lists every renamed variable.
const MigrationURL = "https://github.com/lictorate/vanzik/blob/master/docs/MIGRATION.md#v1x-to-v20"

// Names are the AGENTGUARD_* variables AgentGuard 1.x documented: the
// settings its programs and SDKs read, then the installers' options.
var Names = []string{
	"AGENTGUARD_API_KEY", "AGENTGUARD_URL", "AGENTGUARD_POLICY", "AGENTGUARD_TENANT_ID",
	"AGENTGUARD_NO_UPDATE_CHECK", "AGENTGUARD_DISTRIBUTION",
	"AGENTGUARD_VERSION", "AGENTGUARD_INSTALL_DIR", "AGENTGUARD_DOWNLOAD_URL",
	"AGENTGUARD_NO_MODIFY_PATH", "AGENTGUARD_UNINSTALL", "AGENTGUARD_PURGE",
}

// NewName is the variable Vanzik reads in place of old.
func NewName(old string) string { return "VANZIK_" + strings.TrimPrefix(old, "AGENTGUARD_") }

// Set returns the variables of Names that have a value here.
func Set() []string {
	var set []string
	for _, n := range Names {
		if os.Getenv(n) != "" {
			set = append(set, n)
		}
	}
	return set
}

// Check is for a setting about to fall back to VANZIK_<name>: it returns
// an error when that variable is empty but AGENTGUARD_<name> is set, so
// the program stops instead of running without what the operator meant to
// configure. Once VANZIK_<name> is set the old variable no longer matters.
func Check(name string) error {
	if os.Getenv("VANZIK_"+name) != "" || os.Getenv("AGENTGUARD_"+name) == "" {
		return nil
	}
	return fmt.Errorf("AGENTGUARD_%s is set, but Vanzik reads VANZIK_%s: rename the variable (see %s)", name, name, MigrationURL)
}
