package generator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
}

type Runner interface {
	Run(ctx context.Context, name string, args []string, env []string, stdin string) error
}

type OSRunner struct{}

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

func Generate(ctx context.Context, opts Options) error {
	if opts.Tool == "" {
		return errors.New("tool is required")
	}
	if opts.Runner == nil {
		opts.Runner = OSRunner{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	root, err := guardrail.PrepareOutputRoot(opts.Out, opts.Force)
	if err != nil {
		return err
	}
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

func (OSRunner) Run(ctx context.Context, name string, args []string, env []string, stdin string) error {
	resolved, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("find sidecar %q: %w", name, err)
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s %q: %w\n%s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func createLayout(root string) error {
	dirs := []string{".gnupg", "gpg", "minisign", "ssh", "malformed"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root, dir), guardrail.DirPerm); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(root, dir), guardrail.DirPerm); err != nil {
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
	return os.WriteFile(path, data, perm)
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
		key, value, ok := strings.Cut(item, "=")
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
