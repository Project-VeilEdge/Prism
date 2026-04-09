package router

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloadFunc is called when a watched file changes.
// It receives the absolute path of the changed file.
// Returning an error logs at ERROR level but does not stop the watcher.
type ReloadFunc func(path string) error

// WatcherConfig holds the configuration for a file watcher.
type WatcherConfig struct {
	// Files lists the absolute paths to watch for changes.
	// The watcher monitors the parent directory of each file
	// to handle editors that write-then-rename (vim, etc.).
	Files []string

	// OnReload is called when any watched file changes.
	OnReload ReloadFunc

	// Debounce is the minimum interval between successive reload calls
	// for the same file. Defaults to 1s.
	Debounce time.Duration
}

// Watcher monitors config files via fsnotify (directory-level) and SIGHUP.
// When a change is detected, it calls OnReload with the path of the changed file.
//
// Key design: watches the directory containing each file, not the file itself.
// This handles editors like vim that save via write-to-temp + rename, which
// would break a direct file watch (the inode changes on rename).
type Watcher struct {
	cfg       WatcherConfig
	fsWatcher *fsnotify.Watcher
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewWatcher creates a Watcher. Call Start to begin watching.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.OnReload == nil {
		return nil, fmt.Errorf("watcher: OnReload must not be nil")
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = time.Second
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("watcher: create fsnotify: %w", err)
	}

	// Watch the parent directory of each file.
	dirs := make(map[string]struct{})
	for _, f := range cfg.Files {
		abs, err := filepath.Abs(f)
		if err != nil {
			fsw.Close()
			return nil, fmt.Errorf("watcher: abs path %q: %w", f, err)
		}
		dir := filepath.Dir(abs)
		dirs[dir] = struct{}{}
	}

	for dir := range dirs {
		if err := fsw.Add(dir); err != nil {
			fsw.Close()
			return nil, fmt.Errorf("watcher: add dir %q: %w", dir, err)
		}
		slog.Debug("watcher_dir_added", "dir", dir)
	}

	return &Watcher{
		cfg:       cfg,
		fsWatcher: fsw,
		done:      make(chan struct{}),
	}, nil
}

// Start begins the watch loop in a background goroutine.
// It also listens for SIGHUP to trigger a reload of all watched files.
// Call Stop to shut down.
func (w *Watcher) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	// Build lookup: abs path → true
	watched := make(map[string]bool, len(w.cfg.Files))
	for _, f := range w.cfg.Files {
		abs, _ := filepath.Abs(f)
		watched[abs] = true
	}

	go w.loop(ctx, watched)
}

// Stop shuts down the watcher and waits for the loop to exit.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	<-w.done
	w.fsWatcher.Close()
}

func (w *Watcher) loop(ctx context.Context, watched map[string]bool) {
	defer close(w.done)

	// SIGHUP triggers a full reload.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	lastReload := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return

		case sig := <-sigCh:
			slog.Info("config_reload_signal", "signal", sig.String())
			w.reloadAll(watched, lastReload)

		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleFSEvent(event, watched, lastReload)

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			slog.Error("watcher_fsnotify_error", "err", err)
		}
	}
}

func (w *Watcher) handleFSEvent(event fsnotify.Event, watched map[string]bool, lastReload map[string]time.Time) {
	// We only care about Create (rename-into) and Write events.
	if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
		return
	}

	abs, err := filepath.Abs(event.Name)
	if err != nil {
		return
	}

	// For rename-based saves, the event name might be the target file.
	// Also check if the event is for any of our watched files via
	// normalized path matching (handles symlinks at the base level).
	if !watched[abs] {
		// Check if the filename component matches any watched file.
		// This handles cases where the path differs slightly.
		matched := false
		for p := range watched {
			if filepath.Base(p) == filepath.Base(abs) && filepath.Dir(p) == filepath.Dir(abs) {
				abs = p
				matched = true
				break
			}
		}
		if !matched {
			return
		}
	}

	// Debounce: skip if we reloaded this file recently.
	now := time.Now()
	if last, ok := lastReload[abs]; ok && now.Sub(last) < w.cfg.Debounce {
		return
	}

	// Verify the file actually exists (the Create event from rename
	// should leave the file present).
	if _, err := os.Stat(abs); err != nil {
		return
	}

	lastReload[abs] = now
	slog.Info("config_file_changed", "path", abs, "op", event.Op.String())

	if err := w.cfg.OnReload(abs); err != nil {
		slog.Error("config_reload_failed", "path", abs, "err", err)
	}
}

func (w *Watcher) reloadAll(watched map[string]bool, lastReload map[string]time.Time) {
	now := time.Now()
	for path := range watched {
		if _, err := os.Stat(path); err != nil {
			slog.Warn("config_reload_skip_missing", "path", path, "err", err)
			continue
		}
		lastReload[path] = now
		if err := w.cfg.OnReload(path); err != nil {
			slog.Error("config_reload_failed", "path", path, "err", err)
		}
	}
}

// ReloadConfigFile is a helper that builds a ReloadFunc dispatching by file suffix.
// It accepts a map of file base-name suffixes to their specific reload functions.
// For example: {"whitelist.yaml": reloadWhitelist, "ech-key.pem": reloadECHKey}.
func ReloadConfigFile(handlers map[string]func(path string) error) ReloadFunc {
	return func(path string) error {
		base := filepath.Base(path)
		for suffix, fn := range handlers {
			if strings.HasSuffix(base, suffix) {
				return fn(path)
			}
		}
		slog.Debug("watcher_unhandled_file", "path", path)
		return nil
	}
}
