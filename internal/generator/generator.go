package generator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

const (
	KnownPassphrase = "synthcorpus-known-test-passphrase"
	testEmail       = "synthcorpus-test@example.invalid"
	testName        = "synthcorpus generated-real TEST KEY - DO NOT USE"
)

type Options struct {
	Tool   string
	Out    string
	Force  bool
	Runner Runner
	Now    func() time.Time
	// Preflight runs before any output mutation. nil uses DefaultSidecarPreflight.
	// Unit tests may set a no-op when sidecars are mocked via Runner.
	Preflight func(context.Context) error
}

type Manifest struct {
	Kind       string     `json:"kind"`
	Tool       string     `json:"tool"`
	Generated  string     `json:"generated"`
	Passphrase string     `json:"known_passphrase"`
	Artifacts  []Artifact `json:"artifacts"`
}

type Artifact struct {
	Kind  string `json:"kind"`
	Class string `json:"class"`
	Path  string `json:"path"`
}

func Generate(ctx context.Context, opts Options) (err error) {
	if opts.Tool == "" {
		return errors.New("tool is required")
	}
	if opts.Runner == nil {
		opts.Runner = OSRunner{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Preflight == nil {
		opts.Preflight = DefaultSidecarPreflight
	}

	// All-sidecar presence/capability before any mint or output root mutation.
	if err := opts.Preflight(ctx); err != nil {
		return err
	}

	finalRoot, err := guardrail.ResolveOutputPath(opts.Out)
	if err != nil {
		return err
	}
	if err := checkFinalRootForGenerate(finalRoot, opts.Force); err != nil {
		return err
	}

	// Mint entirely into a marker-owned staging directory. Publish/rename to
	// the final root only after every step succeeds so failures never leave a
	// half-generated corpus (and --force does not destroy a prior good corpus
	// before the replacement is proven).
	parent := filepath.Dir(finalRoot)
	stagingName := fmt.Sprintf(".synthcorpus-staging-%d-%d", os.Getpid(), opts.Now().UnixNano())
	stagingPath := filepath.Join(parent, stagingName)

	staging, err := guardrail.PrepareOutputRoot(stagingPath, true)
	if err != nil {
		return fmt.Errorf("prepare staging root: %w", err)
	}
	published := false
	defer func() {
		if published {
			return
		}
		// Cleanup failures must surface — silent discard can leave real
		// generated material under .synthcorpus-staging-* after Generate errs.
		if cleanErr := removeAll(staging); cleanErr != nil {
			if err != nil {
				err = fmt.Errorf("%w (also failed to remove staging %s: %v)", err, staging, cleanErr)
			} else {
				err = fmt.Errorf("failed to remove staging %s: %w", staging, cleanErr)
			}
		}
	}()

	if err = mintIntoRoot(ctx, staging, opts); err != nil {
		return err
	}
	if err = publishStagedRoot(staging, finalRoot); err != nil {
		return err
	}
	published = true
	return nil
}

func checkFinalRootForGenerate(final string, force bool) error {
	info, err := os.Lstat(final)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat final output root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output root exists and is not a directory: %s", final)
	}
	empty, err := dirIsEmpty(final)
	if err != nil {
		return err
	}
	if empty {
		// Empty directory can be replaced by rename publish without --force.
		return nil
	}
	if !force {
		return fmt.Errorf("output root already exists; use --force only for a marker-owned synthcorpus directory")
	}
	if err := guardrail.CheckOwnedMarker(final); err != nil {
		return err
	}
	return nil
}

func mintIntoRoot(ctx context.Context, root string, opts Options) error {
	if err := guardrail.WriteMarker(root, opts.Tool); err != nil {
		return err
	}
	if err := createLayout(root); err != nil {
		return err
	}

	manifest := Manifest{
		Kind:       guardrail.MarkerKind,
		Tool:       opts.Tool,
		Generated:  opts.Now().UTC().Format(time.RFC3339),
		Passphrase: KnownPassphrase,
	}

	if err := writeReadme(root, opts.Tool); err != nil {
		return err
	}
	if err := writeSample(root); err != nil {
		return err
	}

	steps := []func(context.Context, string, Runner, *Manifest) error{
		generateGPG,
		generateMinisign,
		generateSSH,
		generateMalformed,
	}
	for _, step := range steps {
		if err := step(ctx, root, opts.Runner, &manifest); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(root, "MANIFEST.json"), manifest, guardrail.SecretPerm)
}

// publishStagedRoot moves a completed staging corpus onto finalRoot.
// If finalRoot already exists (prior corpus / empty dir), it is moved aside
// first and restored if the publish rename fails — so a valid prior corpus
// survives a failed replacement.
func publishStagedRoot(staging, final string) error {
	var backup string
	if _, err := os.Lstat(final); err == nil {
		backup = final + ".synthcorpus-backup-" + fmt.Sprintf("%d", os.Getpid())
		if err := rename(final, backup); err != nil {
			return fmt.Errorf("move prior output root aside for publish: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat final output root before publish: %w", err)
	}

	if err := rename(staging, final); err != nil {
		if backup != "" {
			if restoreErr := rename(backup, final); restoreErr != nil {
				return fmt.Errorf("publish staged corpus: %w (also failed to restore prior corpus: %v)", err, restoreErr)
			}
		}
		return fmt.Errorf("publish staged corpus: %w", err)
	}
	if backup != "" {
		if err := removeAll(backup); err != nil {
			return fmt.Errorf("corpus published at %s but failed to remove prior backup %s: %w", final, backup, err)
		}
	}
	return nil
}

// Filesystem hooks — overridable in tests for cleanup/publish failure injection.
var (
	removeAll = os.RemoveAll
	rename    = os.Rename
)

func dirIsEmpty(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

func createLayout(root string) error {
	dirs := []string{".gnupg", "gpg", "minisign", "ssh", "malformed"}
	for _, dir := range dirs {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, guardrail.DirPerm); err != nil {
			return err
		}
		if err := chmodFile(path, guardrail.DirPerm); err != nil {
			return err
		}
	}
	return nil
}

func writeReadme(root, tool string) error {
	body := fmt.Sprintf(`# synthcorpus generated-real dogfood corpus

This directory was generated for %s by synthcorpus-gen.

WARNING: every keypair here is real cryptographic material, generated only for
throwaway detector dogfooding. Do not copy this directory into any git worktree.

Known passphrase for protected specimens:

    %s

Test identity:

    %s <%s>

All specimens are self-identifying test material and must remain outside git.
`, tool, KnownPassphrase, testName, testEmail)
	return os.WriteFile(filepath.Join(root, "README.md"), []byte(body), guardrail.PublicPerm)
}

func writeSample(root string) error {
	return os.WriteFile(filepath.Join(root, "sample.txt"), []byte("synthcorpus generated-real sample payload\n"), guardrail.PublicPerm)
}

func writeJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	return chmodFile(path, perm)
}

func appendArtifact(m *Manifest, kind, class, path string) {
	m.Artifacts = append(m.Artifacts, Artifact{Kind: kind, Class: class, Path: filepath.ToSlash(path)})
}

func sidecarEnv(root string, extra ...string) []string {
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
		"XDG_RUNTIME_DIR":         true,
		"__CF_USER_TEXT_ENCODING": true,
	}

	env := make([]string, 0, len(keep)+len(extra)+3)
	seen := make(map[string]int)
	set := func(k, v string) {
		item := k + "=" + v
		if idx, ok := seen[k]; ok {
			env[idx] = item
			return
		}
		seen[k] = len(env)
		env = append(env, item)
	}
	for _, item := range os.Environ() {
		key, value, ok := cutEnv(item)
		if !ok || !keep[key] {
			continue
		}
		set(key, value)
	}
	set("GNUPGHOME", filepath.Join(root, ".gnupg"))
	set("LC_ALL", "C")
	set("LANG", "C")
	set("GPG_AGENT_INFO", "")
	env = append(env, extra...)
	return env
}

func cutEnv(item string) (key, value string, ok bool) {
	for i := 0; i < len(item); i++ {
		if item[i] == '=' {
			return item[:i], item[i+1:], true
		}
	}
	return "", "", false
}
