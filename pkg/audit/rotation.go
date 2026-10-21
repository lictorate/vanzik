package audit

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// ArchiveTimestampFormat is the suffix format of archived audit files.
// Lexicographic order matches chronological order, so pruning sorts names
// without parsing them.
const ArchiveTimestampFormat = "20060102T150405Z"

// RotationConfig configures size-triggered rotation for FileLogger.
//
// The zero value disables rotation entirely.
//
// When MaxSize > 0, every successful Log() rotates once the file reaches
// MaxSize. Rotation is synchronous inside that Log(): a stat, a rename, an
// open and a header write, i.e. milliseconds every few hundred thousand
// entries at the 100 MB default.
type RotationConfig struct {
	// MaxSize is the live-file size threshold in bytes. 0 disables rotation.
	MaxSize int64
	// MaxFiles caps the number of archived files kept after pruning. Older
	// archives (by timestamp suffix) are deleted first. 0 means keep all.
	MaxFiles int
	// MaxAge bounds the age of archived files, deleted at rotation time.
	// Zero disables age-based pruning. Age comes from the archive name's
	// timestamp suffix, not mtime, so an rsync of archives keeps retention.
	MaxAge time.Duration
	// Compress, when true, gzips the archive file after rename and removes
	// the uncompressed copy. A gzip failure leaves the uncompressed archive
	// in place — pruning still counts it.
	Compress bool
}

// NewFileLoggerWithRotation is NewFileLogger plus a rotation policy, copied
// at construction.
func NewFileLoggerWithRotation(path string, cfg RotationConfig) (*FileLogger, error) {
	return NewFileLoggerWithOptions(path, FileLoggerOptions{Rotation: cfg})
}

// maxArchiveProbe bounds how far nextFreeArchivePath will advance the
// timestamp looking for a free name. A minute of headroom covers any
// realistic burst; past that, failing the rotation is the safe outcome.
const maxArchiveProbe = 60

// nextFreeArchivePath returns the first archive path for basePath whose name
// is not already taken, advancing the timestamp one second at a time.
//
// ArchiveTimestampFormat has one-second resolution, so a burst that rotates
// twice inside the same second computes the same archive name twice — and
// os.Rename replaces the target silently, destroying the first archive and
// breaking the _meta.rotated_from chain that startup replay walks.
//
// Advancing the timestamp rather than adding a disambiguating suffix is
// deliberate: pruneArchivesWithAge only recognises a name whose suffix is
// exactly len(ArchiveTimestampFormat), so a `<ts>-1` archive would be invisible
// to BOTH count- and age-based pruning and would never be deleted. Keeping the
// name exactly 16 characters preserves pruning, and lexicographic order stays
// chronological. The cost is that a name can read up to maxArchiveProbe seconds
// later than the instant it was rotated; the entries inside carry their own
// timestamps, so nothing downstream depends on that precision.
//
// A name is taken if either the plain or the .gz form exists, because
// compression writes alongside the rename.
//
// The name also sorts after every archive already on disk. Pruning deletes
// the oldest names, and a burst of rotations inside one second would
// otherwise take a pruned name again: the next prune would then delete that
// newest archive, and name order would stop matching write order, which
// `audit verify` relies on to tell pruning from a removed archive.
func nextFreeArchivePath(basePath string, ts time.Time) (string, error) {
	ts = ts.UTC().Truncate(time.Second)
	if names, err := listArchives(basePath); err == nil && len(names) > 0 {
		newest, err := time.Parse(ArchiveTimestampFormat, archiveStamp(names[len(names)-1], filepath.Base(basePath)))
		if err == nil && !ts.After(newest) {
			ts = newest.Add(time.Second)
		}
	}
	for i := 0; i < maxArchiveProbe; i++ {
		candidate := fmt.Sprintf("%s.%s", basePath, ts.Format(ArchiveTimestampFormat))
		if !archiveNameTaken(candidate) {
			return candidate, nil
		}
		ts = ts.Add(time.Second)
	}
	return "", fmt.Errorf("no free archive name for %s within %ds", basePath, maxArchiveProbe)
}

// listArchives lists the base names of basePath's rotated archives, plain or
// gzip, oldest first: ArchiveTimestampFormat sorts chronologically.
func listArchives(basePath string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Dir(basePath))
	if err != nil {
		return nil, err
	}
	base := filepath.Base(basePath)
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), base+".") {
			continue
		}
		if len(archiveStamp(e.Name(), base)) == len(ArchiveTimestampFormat) {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return archiveStamp(names[i], base) < archiveStamp(names[j], base)
	})
	return names, nil
}

// archiveStamp returns the timestamp part of an archive's base name.
func archiveStamp(name, base string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, base+"."), ".gz")
}

// archiveNameTaken reports whether an archive already occupies this path in
// either its plain or compressed form.
func archiveNameTaken(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	if _, err := os.Stat(path + ".gz"); err == nil {
		return true
	}
	return false
}

// rotateLocked closes the live file, renames it to a timestamped archive,
// optionally compresses that archive, opens a fresh live file, and writes a
// meta header whose RotatedFrom names the archive's basename. Caller holds
// l.mu.
//
// Failure modes:
//   - If close/rename fails, the logger is left in a usable state only if the
//     rename did not run. Any partial step returns an error so the caller
//     knows an entry may not have flushed.
//   - Gzip and prune failures are logged, not returned: the uncompressed
//     archive is still a valid record, and extra archives lose no data.
func (l *FileLogger) rotateLocked() error {
	path := l.file.Name()
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close pre-rotate: %w", err)
	}

	archivePath, err := nextFreeArchivePath(path, time.Now().UTC())
	if err != nil {
		// No free name. Reopen the live file rather than rename over an
		// existing archive: an over-large live file is recoverable, a
		// destroyed archive is not.
		if f, reopenErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions); reopenErr == nil {
			l.file = f
			l.enc = json.NewEncoder(f)
		}
		return err
	}

	if err := os.Rename(path, archivePath); err != nil {
		// Reopen the original so the logger is not permanently broken.
		if f, reopenErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions); reopenErr == nil {
			l.file = f
			l.enc = json.NewEncoder(f)
		}
		return fmt.Errorf("rename to archive: %w", err)
	}

	finalArchive := archivePath
	if l.rotCfg.Compress {
		gzPath := archivePath + ".gz"
		if err := gzipFile(archivePath, gzPath); err != nil {
			log.Printf("WARN: gzip rotated audit file %s: %v (leaving uncompressed)", archivePath, err)
		} else {
			if err := os.Remove(archivePath); err != nil {
				log.Printf("WARN: remove uncompressed archive %s: %v", archivePath, err)
			} else {
				finalArchive = gzPath
			}
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return fmt.Errorf("reopen live file after rotate: %w", err)
	}
	l.file = f
	l.enc = json.NewEncoder(f)

	env := metaEnvelope{Meta: NewMetaRecord(filepath.Base(finalArchive))}
	if l.seal != nil {
		// chain_prev/chain_seq link the new file to the last entry of the
		// archive; seq carries on from there.
		l.seal.meta(&env.Meta)
	}
	if err := l.enc.Encode(env); err != nil {
		return fmt.Errorf("write post-rotate header: %w", err)
	}
	l.segID = env.Meta.SegmentID
	l.publishAnchorLocked()

	// Point the checkpoint at the new live file BEFORE pruning: a checkpoint
	// that still named a file prune is about to delete would make the next
	// startup lose the counts of every pruned file.
	if l.cpEnabled {
		l.cpFileID = fileIDOf(&env.Meta)
		l.writeCheckpointLocked()
	}

	if l.rotCfg.MaxFiles > 0 || l.rotCfg.MaxAge > 0 {
		if err := pruneArchivesWithAge(path, l.rotCfg.MaxFiles, l.rotCfg.MaxAge); err != nil {
			log.Printf("WARN: audit archive prune failed: %v", err)
		}
	}

	// Only completed rotations count.
	metrics.IncAuditRotation()
	return nil
}

// gzipFile streams src into gzip file dst, mode 0600 like the live file.
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)

	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// pruneArchives removes the oldest archive files for basePath (by timestamp
// suffix) until no more than keep remain.
//
// Both `<basePath>.<ts>` and `<basePath>.<ts>.gz` are considered archives.
// The live `<basePath>` itself is never deleted.
func pruneArchives(basePath string, keep int) error {
	return pruneArchivesWithAge(basePath, keep, 0)
}

// pruneArchivesWithAge is pruneArchives that also drops archives whose
// timestamp suffix is older than maxAge. An archive failing EITHER bound is
// removed.
//
//   - keep < 0 disables count-based pruning ("keep all").
//   - keep == 0 deletes every archive.
//   - maxAge == 0 disables age-based pruning.
//
// Age comes from the timestamp suffix, not mtime (see RotationConfig.MaxAge).
func pruneArchivesWithAge(basePath string, keep int, maxAge time.Duration) error {
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	type archive struct {
		path string
		// ts is zero on parse failure: counted, but never age-pruned.
		ts time.Time
	}
	var archives []archive
	prefix := base + "."
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".gz")
		if len(suffix) != len(ArchiveTimestampFormat) {
			continue
		}
		full := filepath.Join(dir, name)
		ts, _ := time.Parse(ArchiveTimestampFormat, suffix)
		archives = append(archives, archive{path: full, ts: ts})
	}

	if len(archives) == 0 {
		return nil
	}

	// Age first, so the count applies to the already-trimmed set.
	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge)
		kept := archives[:0]
		for _, a := range archives {
			if !a.ts.IsZero() && a.ts.Before(cutoff) {
				if err := os.Remove(a.path); err != nil {
					log.Printf("WARN: remove archive %s: %v", a.path, err)
				}
				continue
			}
			kept = append(kept, a)
		}
		archives = kept
	}

	// Then count, oldest-first by name.
	if keep >= 0 && len(archives) > keep {
		sort.Slice(archives, func(i, j int) bool { return archives[i].path < archives[j].path })
		excess := len(archives) - keep
		for _, a := range archives[:excess] {
			if err := os.Remove(a.path); err != nil {
				log.Printf("WARN: remove archive %s: %v", a.path, err)
			}
		}
	}
	return nil
}
