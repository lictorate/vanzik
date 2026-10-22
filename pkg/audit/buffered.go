package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lictorate.com/vanzik/v2/pkg/metrics"
)

// Defaults for BufferedAsyncOpts, tuned for ~10 RPS sustained with bursts of
// a few hundred; heavier loads override them via the CLI flags.
const (
	defaultBufferedQueueSize        = 1024
	defaultBufferedWorkers          = 4
	defaultBufferedRecoveryInterval = 5 * time.Second
	// closeFlushTimeout bounds Close's best-effort final overflow drain so
	// shutdown cannot hang on it.
	closeFlushTimeout = 2 * time.Second
)

// BufferedAsyncOpts configures NewBufferedAsyncLogger.
//
// Zero values for QueueSize, Workers, and RecoveryInterval are replaced
// with documented defaults. OverflowPath is required — the caller picks the
// location (typically `<auditPath>.overflow.jsonl`) so the operator's
// retention/backup tooling sees the spill file alongside the live log.
type BufferedAsyncOpts struct {
	QueueSize        int           // default 1024 if 0
	Workers          int           // default 4   if 0
	OverflowPath     string        // required (caller derives, e.g. "<auditPath>.overflow.jsonl")
	RecoveryInterval time.Duration // default 5s if 0; mainly exposed for tests
	// Transform, when set, is applied to an entry before it is appended to
	// the overflow file, so the spill file holds the same (e.g. redacted)
	// content as the underlying log. Wrap the underlying logger with
	// WithTransform for the normal worker path.
	Transform EntryTransform
}

// BufferedAsyncLogger wraps an underlying Logger with a bounded queue, a
// pool of worker goroutines draining it into the underlying Log, and a
// disk-overflow spill path. Workers absorb I/O latency, keeping the
// /v1/check hot path off the audit mutex.
//
// Concurrency contract:
//   - Log MUST NOT block: a non-blocking channel send, else a JSON-line
//     append to the overflow file (mode 0600). Its only error is "queue
//     full AND overflow append failed": both legs of durability gone.
//     Entries are durable across saturation but NOT ordered across it.
//   - Close is idempotent (sync.Once). It signals shutdown through b.closed
//     (the queue itself is never closed), lets workers drain what is
//     queued, then runs a best-effort overflow drain bounded by a short
//     timeout.
//   - The recovery goroutine runs every RecoveryInterval. Each tick renames
//     the overflow file to a `.draining.<ts>` sibling so concurrent Log()
//     callers never see a partially drained file, enqueues each line
//     without blocking, and re-spills lines that would block into a fresh
//     overflow file.
//   - Counter getters are independent atomic loads, not one snapshot.
type BufferedAsyncLogger struct {
	underlying Logger

	queue            chan Entry
	workers          int
	overflowPath     string
	transform        EntryTransform
	recoveryInterval time.Duration

	// overflowMu serializes overflow-file appends (concurrent Encodes on one
	// fd interleave) and the drain renames. Held for one Encode only.
	overflowMu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{} // closed by Close to signal recovery goroutine
	wg        sync.WaitGroup

	// Atomic counters.
	droppedToOverflow   uint64
	drainedFromOverflow uint64
	queueDepthHint      int64
}

// NewBufferedAsyncLogger constructs a buffered async wrapper around
// underlying, creating OverflowPath's parent directory (mode 0700) if
// missing.
func NewBufferedAsyncLogger(underlying Logger, opts BufferedAsyncOpts) (*BufferedAsyncLogger, error) {
	if underlying == nil {
		return nil, errors.New("audit: underlying logger is nil")
	}
	if opts.OverflowPath == "" {
		return nil, errors.New("audit: overflow path required")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultBufferedQueueSize
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultBufferedWorkers
	}
	if opts.RecoveryInterval <= 0 {
		opts.RecoveryInterval = defaultBufferedRecoveryInterval
	}

	// 0700: the spill file carries the same secrecy as the live audit log.
	if dir := filepath.Dir(opts.OverflowPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("audit: mkdir overflow dir %s: %w", dir, err)
		}
	}

	b := &BufferedAsyncLogger{
		underlying:       underlying,
		queue:            make(chan Entry, opts.QueueSize),
		workers:          opts.Workers,
		overflowPath:     opts.OverflowPath,
		transform:        opts.Transform,
		recoveryInterval: opts.RecoveryInterval,
		closed:           make(chan struct{}),
	}

	for i := 0; i < b.workers; i++ {
		b.wg.Add(1)
		go b.workerLoop()
	}
	b.wg.Add(1)
	go b.recoveryLoop()

	return b, nil
}

// Log enqueues an entry for async write. Never blocks: on saturation the
// entry is appended to the overflow file and dropToOverflow is incremented.
// Returns an error only when both legs of durability fail (queue full AND
// overflow append failed), which means the entry is lost.
//
// After Close, Log spills directly to the overflow file instead of the
// queue, including when it races Close: the entry is durable on disk and
// the next process start drains it.
func (b *BufferedAsyncLogger) Log(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Checking b.closed first routes every entry to disk once shutdown
	// has begun, when no worker may be left to drain the queue.
	select {
	case <-b.closed:
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: closed and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	default:
	}

	select {
	case b.queue <- e:
		b.noteQueueDepth(1)
		return nil
	case <-b.closed:
		// Lost a race with Close after the first guard. Spill to disk.
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: closed and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	default:
		// Saturation. Persist to disk; never block.
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: queue full and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	}
}

// Query passes through to the underlying logger. Entries currently in the
// overflow spill file are NOT yet visible to the index; the recovery
// goroutine closes that gap within RecoveryInterval.
func (b *BufferedAsyncLogger) Query(filter QueryFilter) ([]Entry, error) {
	return b.underlying.Query(filter)
}

// Close drains the queue and stops all goroutines. Safe to call multiple
// times. It also runs a best-effort overflow drain bounded by
// closeFlushTimeout so a small backlog at shutdown still reaches the
// underlying logger.
//
// Close does NOT close the underlying logger; the caller owns that.
//
// b.queue is never closed: a close would race concurrent Log() sends.
// Shutdown is signalled via b.closed instead.
func (b *BufferedAsyncLogger) Close() error {
	b.closeOnce.Do(func() {
		close(b.closed)
		b.wg.Wait()
		b.flushOverflowOnce(closeFlushTimeout)
	})
	return nil
}

// QueueDepth returns the approximate number of entries sitting in the
// in-memory queue. It is a counter kept by Log() and the workers, so it can
// briefly drift from the channel's len under load.
func (b *BufferedAsyncLogger) QueueDepth() int {
	return int(atomic.LoadInt64(&b.queueDepthHint))
}

// DroppedToOverflow returns the lifetime count of entries that were spilled
// to the overflow file because the queue was full or the underlying Log
// call returned an error.
func (b *BufferedAsyncLogger) DroppedToOverflow() uint64 {
	return atomic.LoadUint64(&b.droppedToOverflow)
}

// DrainedFromOverflow returns the lifetime count of entries the recovery
// goroutine successfully pushed back into the queue from the overflow
// file.
func (b *BufferedAsyncLogger) DrainedFromOverflow() uint64 {
	return atomic.LoadUint64(&b.drainedFromOverflow)
}

// noteQueueDepth adjusts the queue-depth hint and mirrors the new value
// to the vanzik_audit_buffered_queue_depth gauge.
func (b *BufferedAsyncLogger) noteQueueDepth(delta int64) {
	metrics.SetAuditBufferedQueueDepth(atomic.AddInt64(&b.queueDepthHint, delta))
}

// noteDroppedToOverflow counts a spill on both the instance counter and
// the vanzik_audit_buffered_dropped_to_overflow_total series.
func (b *BufferedAsyncLogger) noteDroppedToOverflow() {
	atomic.AddUint64(&b.droppedToOverflow, 1)
	metrics.IncAuditBufferedDroppedToOverflow()
}

// workerLoop drains the queue into the underlying logger. On underlying
// failure it falls back to the overflow path so the entry is still
// durable; this is the same recovery guarantee Log() makes for queue
// saturation.
//
// Once b.closed is closed the worker drains what is already queued with
// non-blocking receives, then exits (b.queue itself is never closed).
func (b *BufferedAsyncLogger) workerLoop() {
	defer b.wg.Done()
	for {
		select {
		case entry := <-b.queue:
			b.noteQueueDepth(-1)
			b.processEntry(entry)
		case <-b.closed:
			for {
				select {
				case entry := <-b.queue:
					b.noteQueueDepth(-1)
					b.processEntry(entry)
				default:
					return
				}
			}
		}
	}
}

// processEntry runs the underlying Log and falls back to the overflow path
// on failure.
func (b *BufferedAsyncLogger) processEntry(entry Entry) {
	if err := b.safeUnderlyingLog(entry); err != nil {
		log.Printf("WARN audit buffered: underlying log failed: %v (writing to overflow)", err)
		if oerr := b.appendOverflow(entry); oerr != nil {
			log.Printf("ERROR audit buffered: underlying log AND overflow append failed: underlying=%v overflow=%v", err, oerr)
			return
		}
		b.noteDroppedToOverflow()
	}
}

// safeUnderlyingLog invokes b.underlying.Log behind a recover barrier so a
// panic in a store driver, a custom Entry MarshalJSON, or a nil-handle close
// race cannot escape the worker goroutine and abort the process: a flush
// worker crash must never block or crash the proxy loop.
//
// The panic becomes an error, so it takes the same overflow fallback as an
// ordinary Log error: the entry stays durable and the worker keeps
// draining. pkg/notify's workerWithRecover does the same for notifiers.
func (b *BufferedAsyncLogger) safeUnderlyingLog(entry Entry) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("PANIC audit buffered: underlying log panicked: %v (routing entry to overflow)", rec)
			err = fmt.Errorf("underlying log panicked: %v", rec)
		}
	}()
	return b.underlying.Log(entry)
}

// appendOverflow appends one entry as a JSON line to the overflow file
// (mode 0600), serialized by overflowMu so writers never interleave.
func (b *BufferedAsyncLogger) appendOverflow(e Entry) error {
	if b.transform != nil {
		e = b.transform(e)
	}
	b.overflowMu.Lock()
	defer b.overflowMu.Unlock()

	f, err := os.OpenFile(b.overflowPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return fmt.Errorf("open overflow %s: %w", b.overflowPath, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(e); err != nil {
		return fmt.Errorf("encode overflow entry: %w", err)
	}
	return nil
}

// recoveryLoop periodically attempts to drain the overflow file back into
// the in-memory queue. Exits cleanly when b.closed is closed.
func (b *BufferedAsyncLogger) recoveryLoop() {
	defer b.wg.Done()
	t := time.NewTimer(b.recoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-b.closed:
			return
		case <-t.C:
			b.tryDrainOverflow()
			t.Reset(b.recoveryInterval)
		}
	}
}

// tryDrainOverflow renames the overflow file to a `.draining.<ts>` sibling
// (atomic on POSIX), reads each line, and attempts a non-blocking enqueue
// onto the work queue. Lines that would have blocked are re-spilled into a
// fresh overflow file so the next tick can try again.
//
// Rename rather than read-and-truncate: concurrent saturation appends keep
// targeting the live path (appendOverflow recreates it lazily) while the
// drain reads an immutable snapshot.
func (b *BufferedAsyncLogger) tryDrainOverflow() {
	// Held across stat+rename only, to serialize against appendOverflow.
	b.overflowMu.Lock()
	if _, err := os.Stat(b.overflowPath); err != nil {
		b.overflowMu.Unlock()
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("WARN audit buffered: stat overflow %s: %v", b.overflowPath, err)
		}
		return
	}
	drainingPath := fmt.Sprintf("%s.draining.%d", b.overflowPath, time.Now().UTC().UnixNano())
	if err := os.Rename(b.overflowPath, drainingPath); err != nil {
		b.overflowMu.Unlock()
		log.Printf("WARN audit buffered: rename overflow %s -> %s: %v", b.overflowPath, drainingPath, err)
		return
	}
	b.overflowMu.Unlock()

	in, err := os.Open(drainingPath)
	if err != nil {
		log.Printf("WARN audit buffered: open draining %s: %v", drainingPath, err)
		return
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var requeued uint64
	var respilled int
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Skip corrupt lines, as FileLogger.Query does.
			log.Printf("WARN audit buffered: skipping corrupt overflow line in %s (%v)", drainingPath, err)
			continue
		}

		select {
		case b.queue <- entry:
			b.noteQueueDepth(1)
			requeued++
		default:
			// Queue full again: re-spill for the next tick, never block.
			if err := b.appendOverflow(entry); err != nil {
				log.Printf("ERROR audit buffered: re-spill failed: %v (entry lost)", err)
				continue
			}
			respilled++
		}
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		log.Printf("WARN audit buffered: scan draining %s: %v", drainingPath, scanErr)
	}
	// Close BEFORE os.Remove: Windows refuses to remove a file open in this
	// process.
	if cerr := in.Close(); cerr != nil {
		log.Printf("WARN audit buffered: close draining %s: %v", drainingPath, cerr)
	}

	// On a scanner error (a line over 4 MiB, a truncated read) drainingPath
	// MUST NOT be removed: the unread tail would be lost. Rename it back to
	// b.overflowPath for the next tick or startup; if a fresh overflow file
	// appeared meanwhile, leave it under its `.draining.<ts>` name for the
	// operator to merge. Either way the entries stay on disk.
	if scanErr != nil {
		b.overflowMu.Lock()
		_, statErr := os.Stat(b.overflowPath)
		if errors.Is(statErr, os.ErrNotExist) {
			if rerr := os.Rename(drainingPath, b.overflowPath); rerr != nil {
				log.Printf("WARN audit buffered: re-spill rename %s -> %s after scan error: %v (preserving %s)",
					drainingPath, b.overflowPath, rerr, drainingPath)
			} else {
				log.Printf("WARN audit buffered: preserved partial drain by renaming %s -> %s for next tick", drainingPath, b.overflowPath)
			}
		} else {
			log.Printf("WARN audit buffered: leaving %s on disk after scanner error (fresh overflow already exists)", drainingPath)
		}
		b.overflowMu.Unlock()
	} else if err := os.Remove(drainingPath); err != nil {
		log.Printf("WARN audit buffered: remove draining %s: %v", drainingPath, err)
	}

	if requeued > 0 {
		atomic.AddUint64(&b.drainedFromOverflow, requeued)
		metrics.AddAuditBufferedDrainedFromOverflow(requeued)
	}
	if respilled > 0 {
		log.Printf("INFO audit buffered: re-spilled %d entries (queue still saturated)", respilled)
	}
}

// flushOverflowOnce is a one-shot drain attempt run by Close. Bounded by
// timeout so shutdown does not hang on a stuck rename or a slow disk.
//
// Workers are already gone, so each overflow entry goes straight to the
// underlying logger; entries it refuses are re-spilled for the next process.
func (b *BufferedAsyncLogger) flushOverflowOnce(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	b.overflowMu.Lock()
	if _, err := os.Stat(b.overflowPath); err != nil {
		b.overflowMu.Unlock()
		return
	}
	drainingPath := fmt.Sprintf("%s.draining.close.%d", b.overflowPath, time.Now().UTC().UnixNano())
	if err := os.Rename(b.overflowPath, drainingPath); err != nil {
		b.overflowMu.Unlock()
		log.Printf("WARN audit buffered: close-flush rename: %v", err)
		return
	}
	b.overflowMu.Unlock()

	in, err := os.Open(drainingPath)
	if err != nil {
		log.Printf("WARN audit buffered: close-flush open draining: %v", err)
		return
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	timedOut := false
	for scanner.Scan() {
		if time.Now().After(deadline) {
			timedOut = true
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if err := b.safeUnderlyingLog(entry); err != nil {
			_ = b.appendOverflow(entry)
		}
	}
	// Close BEFORE rename/remove, not deferred: on Windows an open file
	// cannot be renamed or removed.
	if cerr := in.Close(); cerr != nil {
		log.Printf("WARN audit buffered: close-flush close draining: %v", cerr)
	}

	if timedOut {
		// Rename the partly processed file back so the next process
		// resumes it.
		if rerr := os.Rename(drainingPath, b.overflowPath); rerr != nil {
			log.Printf("WARN audit buffered: close-flush re-spill rename: %v", rerr)
		}
		return
	}
	if err := os.Remove(drainingPath); err != nil {
		log.Printf("WARN audit buffered: close-flush remove draining: %v", err)
	}
}

// The notifier-side counterpart of this overflow design lives in
// pkg/notify (DispatcherOptions.SpoolPath / --notify-spool).

// Path returns the audit file path of the wrapped logger when it is
// file-backed (a *FileLogger, or anything else exposing Path()), and ""
// otherwise. The server's startup seeder keys its replay checkpoint off
// this, since production always wraps the FileLogger in a
// BufferedAsyncLogger.
func (b *BufferedAsyncLogger) Path() string {
	if pr, ok := b.underlying.(interface{ Path() string }); ok {
		return pr.Path()
	}
	return ""
}
