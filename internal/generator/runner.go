package generator

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes sidecars with explicit arg vectors and environments.
// Output captures combined stdout+stderr for inspection (version / list).
type Runner interface {
	Run(ctx context.Context, name string, args []string, env []string, stdin string) error
	Output(ctx context.Context, name string, args []string, env []string, stdin string) (string, error)
}

// OSRunner invokes real binaries from PATH.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, env []string, stdin string) error {
	_, err := OSRunner{}.Output(ctx, name, args, env, stdin)
	return err
}

func (OSRunner) Output(ctx context.Context, name string, args []string, env []string, stdin string) (string, error) {
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("find sidecar %q: %w", name, err)
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			return "", fmt.Errorf("run %s %q: %w", name, args, err)
		}
		return text, fmt.Errorf("run %s %q: %w\n%s", name, args, err, text)
	}
	return text, nil
}
