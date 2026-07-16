package guardrail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	MarkerName     = ".synthcorpus-generated-real.json"
	MarkerKind     = "synthcorpus-generated-real"
	DirPerm        = 0o700
	SecretPerm     = 0o600
	PublicPerm     = 0o644
	DefaultTool    = "decernor"
	maxMarkerBytes = 4096
)

type Marker struct {
	Kind string `json:"kind"`
	Tool string `json:"tool"`
}

func PrepareOutputRoot(out string, force bool) (string, error) {
	if strings.TrimSpace(out) == "" {
		return "", errors.New("output path is required")
	}

	abs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	abs = filepath.Clean(abs)

	// The named output root itself may not be a symlink: never mint or
	// --force-delete through a retargetable final link.
	if info, lerr := os.Lstat(abs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("output path contains symlinked component: %s", abs)
		}
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return "", fmt.Errorf("lstat output root: %w", lerr)
	}

	// Canonicalize intermediate links (e.g. macOS /var → /private/var, or a
	// user parent symlink) so every later check and write uses a realpath.
	// Retaining a symlink-bearing pathname across git check → MkdirAll /
	// RemoveAll is a TOCTOU hole (retarget after check).
	abs, err = canonicalizeOutputPath(abs)
	if err != nil {
		return "", err
	}

	ancestor, exists, err := nearestExistingAncestor(abs)
	if err != nil {
		return "", err
	}
	// Belt-and-suspenders: after canonicalize, no component may still be a link.
	if err := rejectSymlinksInPath(ancestor); err != nil {
		return "", err
	}
	if err := rejectGitWorktree(ancestor); err != nil {
		return "", err
	}

	if exists {
		info, err := os.Lstat(abs)
		if err != nil {
			return "", fmt.Errorf("stat output root: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("output path contains symlinked component: %s", abs)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("output root exists and is not a directory: %s", abs)
		}
		if force {
			if err := requireOwnedMarker(abs); err != nil {
				return "", err
			}
			if err := os.RemoveAll(abs); err != nil {
				return "", fmt.Errorf("replace marker-owned output root: %w", err)
			}
		} else if notEmpty, err := dirNotEmpty(abs); err != nil {
			return "", err
		} else if notEmpty {
			return "", fmt.Errorf("output root already exists; use --force only for a marker-owned synthcorpus directory")
		}
	}

	if err := os.MkdirAll(abs, DirPerm); err != nil {
		return "", fmt.Errorf("create output root: %w", err)
	}
	if err := os.Chmod(abs, DirPerm); err != nil {
		return "", fmt.Errorf("chmod output root: %w", err)
	}
	// Final realpath check: refuse to return a path that still contains links.
	if err := rejectSymlinksInPath(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func WriteMarker(root, tool string) error {
	marker := Marker{Kind: MarkerKind, Tool: tool}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(root, MarkerName), data, SecretPerm)
}

// canonicalizeOutputPath resolves every existing path component to a real
// directory path via EvalSymlinks, then re-attaches any not-yet-created
// suffix. All subsequent I/O must use the returned path only.
func canonicalizeOutputPath(abs string) (string, error) {
	prefix, suffix, err := existingPrefix(abs)
	if err != nil {
		return "", err
	}

	realPrefix, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return "", fmt.Errorf("canonicalize output path prefix %s: %w", prefix, err)
	}
	realPrefix = filepath.Clean(realPrefix)
	if err := rejectSymlinksInPath(realPrefix); err != nil {
		return "", err
	}

	if suffix == "" {
		return realPrefix, nil
	}
	return filepath.Clean(filepath.Join(realPrefix, suffix)), nil
}

// existingPrefix returns the longest existing pathname prefix of abs (via
// Lstat only — never Stat-following) and the relative suffix of components
// that do not yet exist.
func existingPrefix(abs string) (prefix string, suffix string, err error) {
	volume := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(abs, volume)
	rest = strings.TrimPrefix(rest, string(os.PathSeparator))

	current := volume + string(os.PathSeparator)
	if volume == "" {
		current = string(os.PathSeparator)
	}
	if rest == "" {
		return current, "", nil
	}

	parts := strings.Split(rest, string(os.PathSeparator))
	lastExisting := current
	for i, part := range parts {
		if part == "" {
			continue
		}
		candidate := filepath.Join(current, part)
		_, lerr := os.Lstat(candidate)
		switch {
		case lerr == nil:
			lastExisting = candidate
			current = candidate
			if i == len(parts)-1 {
				return candidate, "", nil
			}
		case errors.Is(lerr, os.ErrNotExist):
			return lastExisting, filepath.Join(parts[i:]...), nil
		default:
			return "", "", fmt.Errorf("lstat output path component %s: %w", candidate, lerr)
		}
	}
	return lastExisting, "", nil
}

func nearestExistingAncestor(abs string) (ancestor string, targetExists bool, err error) {
	prefix, suffix, err := existingPrefix(abs)
	if err != nil {
		return "", false, err
	}
	return prefix, suffix == "", nil
}

// rejectSymlinksInPath fails closed if any existing component of path is a
// symlink. Call only on paths that should already be fully real.
func rejectSymlinksInPath(path string) error {
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	rest = strings.TrimPrefix(rest, string(os.PathSeparator))

	current := volume + string(os.PathSeparator)
	if volume == "" {
		current = string(os.PathSeparator)
	}
	if err := rejectSymlink(current); err != nil {
		return err
	}
	if rest == "" {
		return nil
	}
	for _, part := range strings.Split(rest, string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if err := rejectSymlink(current); err != nil {
			return err
		}
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat output path component %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output path contains symlinked component: %s", path)
	}
	return nil
}

func rejectGitWorktree(ancestor string) error {
	// Git is the authority. A path may be outside a worktree yet still be
	// inside a git directory (e.g. <repo>/.git/... or a bare repository).
	// Both predicates must be false before generation is allowed.
	insideWorkTree, err := gitRevParseBool(ancestor, "--is-inside-work-tree")
	if err != nil {
		return err
	}
	if insideWorkTree {
		return fmt.Errorf("refusing to generate real key material inside git worktree: %s", ancestor)
	}

	insideGitDir, err := gitRevParseBool(ancestor, "--is-inside-git-dir")
	if err != nil {
		return err
	}
	if insideGitDir {
		return fmt.Errorf("refusing to generate real key material inside git directory: %s", ancestor)
	}
	return nil
}

// gitRevParseBool runs `git -C <dir> rev-parse <flag>` and returns the
// boolean result. "not a git repository" is treated as false (safe to
// generate). Any other failure or non-boolean output fails closed.
func gitRevParseBool(dir, flag string) (bool, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", flag)
	cmd.Env = sanitizedGitEnv()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		switch strings.TrimSpace(stdout.String()) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("git %s guard returned ambiguous output: %q", flag, strings.TrimSpace(stdout.String()))
		}
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if strings.Contains(stderr.String(), "not a git repository") {
			return false, nil
		}
		return false, fmt.Errorf("git %s guard failed closed: %s", flag, strings.TrimSpace(stderr.String()))
	}
	return false, fmt.Errorf("run git %s guard: %w", flag, err)
}

func sanitizedGitEnv() []string {
	keep := map[string]bool{
		"COMSPEC":                 true,
		"HOME":                    true,
		"LOGNAME":                 true,
		"PATH":                    true,
		"PATHEXT":                 true,
		"SHELL":                   true,
		"SystemRoot":              true,
		"TEMP":                    true,
		"TMP":                     true,
		"TMPDIR":                  true,
		"USER":                    true,
		"USERNAME":                true,
		"WINDIR":                  true,
		"__CF_USER_TEXT_ENCODING": true,
	}
	env := make([]string, 0, len(keep))
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if !ok || strings.HasPrefix(key, "GIT_") || !keep[key] {
			continue
		}
		env = append(env, item)
	}
	return env
}

func requireOwnedMarker(root string) error {
	markerPath := filepath.Join(root, MarkerName)
	info, err := os.Lstat(markerPath)
	if err != nil {
		return fmt.Errorf("--force requires synthcorpus ownership marker at %s: %w", markerPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing marker reached through symlink: %s", markerPath)
	}
	// Marker authorizes recursive replacement — only a bounded regular file
	// is valid ownership evidence. FIFOs/devices/sockets would hang or lie.
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ownership marker must be a regular file: %s", markerPath)
	}
	if info.Size() > maxMarkerBytes {
		return fmt.Errorf("ownership marker too large (%d bytes, max %d): %s", info.Size(), maxMarkerBytes, markerPath)
	}

	f, err := os.Open(markerPath)
	if err != nil {
		return fmt.Errorf("read synthcorpus ownership marker: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, maxMarkerBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read synthcorpus ownership marker: %w", err)
	}
	if len(data) > maxMarkerBytes {
		return fmt.Errorf("ownership marker too large (max %d bytes): %s", maxMarkerBytes, markerPath)
	}

	var marker Marker
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("parse synthcorpus ownership marker: %w", err)
	}
	if marker.Kind != MarkerKind {
		return fmt.Errorf("invalid synthcorpus ownership marker kind: %q", marker.Kind)
	}
	return nil
}

func dirNotEmpty(root string) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}
