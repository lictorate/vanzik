package v040_to_v041

import (
	"testing"
	"time"
)

// RemovalDeadline is the date after which this migration package must be
// deleted (docs/DEPRECATIONS.md, `audit.migration.v040_to_v041`). A slip
// past it forces a conscious review rather than letting dead migration code
// pile up.
//
// When the test fails, besides its action list: keep a standalone
// `vanzik-migrate` tool for users still on headerless v1 files (see the
// DEPRECATIONS migration-path column).
var RemovalDeadline = time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)

// TestRemovalDeadline is a tripwire: once RemovalDeadline has passed and
// nobody has deleted this package, CI fails with a clear action list.
func TestRemovalDeadline(t *testing.T) {
	if time.Now().UTC().Before(RemovalDeadline) {
		return
	}
	t.Fatalf(`v040_to_v041 migration is past its removal deadline (%s).

Action required (see package docstring for full checklist):
  1. Update docs/DEPRECATIONS.md — move audit.migration.v040_to_v041 to Removed.
  2. Add a CHANGELOG entry naming the removal.
  3. Delete pkg/migrate/v040_to_v041/ and the blank import in cmd/vanzik/main.go.

If v0.4.3 has slipped and the migration legitimately still needs to ship,
edit RemovalDeadline above and document the slip in docs/DEPRECATIONS.md.`,
		RemovalDeadline.Format("2006-01-02"),
	)
}
