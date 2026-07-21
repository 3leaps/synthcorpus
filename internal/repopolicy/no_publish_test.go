package repopolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var (
	actionRef             = regexp.MustCompile(`^([^@[:space:]]+)@([0-9a-f]{40})$`)
	softFailure           = regexp.MustCompile(`\|\|[[:space:]]*(true|:)([[:space:];]|$)`)
	curlUpload            = regexp.MustCompile(`(?m)(^|[;&|[:space:]])curl([^\n]*[[:space:]])(--upload-file([=[:space:]]|$)|-t([^[:space:]]*)?)`)
	workflowExpression    = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	secretsIdentifier     = regexp.MustCompile(`(?i)\bsecrets\b`)
	githubIdentifier      = regexp.MustCompile(`(?i)\bgithub\b`)
	reviewedShellCommands = shellCommandSet(
		`go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"
test "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64"`,
		`go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"
test "$(go env GOOS)/$(go env GOARCH)" = "darwin/arm64"`,
		`go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"`,
		`test -z "$(gofmt -l .)"`,
		`go vet ./...`,
		`go test -count=1 -v ./internal/repopolicy`,
		`output="$RUNNER_TEMP/guardrail-test.log"
set +e
go test -race -count=1 -v ./internal/guardrail 2>&1 | tee "$output"
status=${PIPESTATUS[0]}
set -e
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
grep -q '^=== RUN' "$output"
if grep -q '^--- SKIP:' "$output"; then
  echo 'guardrail tests must not skip' >&2
  exit 1
fi`,
		`go test -race -count=1 ./...`,
		`archive="$RUNNER_TEMP/gitleaks.tar.gz"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
printf '%s  %s\n' "$GITLEAKS_ARCHIVE_SHA256" "$archive" | sha256sum --check --strict
tar -xzf "$archive" -C "$RUNNER_TEMP" gitleaks
printf '%s\n' "$RUNNER_TEMP" >> "$GITHUB_PATH"`,
		`gitleaks version
test "$(gitleaks version)" = "$GITLEAKS_VERSION"`,
		`make gitleaks`,
	)
)

type workflowDocument struct {
	root *yaml.Node
}

func TestRepositoryNoPublishPolicy(t *testing.T) {
	root := repoRoot(t)
	if err := rejectPackagingSurfaces(root); err != nil {
		t.Fatal(err)
	}
	workflows := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflows)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		found++
		path := filepath.Join(workflows, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseAndValidateWorkflow(string(data)); err != nil {
			t.Fatalf("%s: %v", filepath.ToSlash(path), err)
		}
	}
	if found == 0 {
		t.Fatal("no workflows found to enforce")
	}
}

func TestPackagingSurfaceNegativeControls(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"GoReleaser", ".goreleaser.yml"},
		{"release automation", ".release-please-manifest.json"},
		{"Homebrew formula", "Formula/synthcorpus-gen.rb"},
		{"Scoop manifest", "bucket/synthcorpus-gen.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("forbidden release surface\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := rejectPackagingSurfaces(root); err == nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("expected packaging-surface failure for %s, got %v", tc.path, err)
			}
		})
	}
}

func TestWorkflowPolicyNegativeControls(t *testing.T) {
	baseData, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	base := string(baseData)
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"permissions write-all", func(s string) string {
			return strings.Replace(s, "permissions:\n  contents: read", "permissions: write-all", 1)
		}, "permissions"},
		{"job permissions write-all", func(s string) string {
			return mutateFirstJob(s, "    permissions: write-all\n")
		}, "permissions"},
		{"job issues write", func(s string) string {
			return mutateFirstJob(s, "    permissions:\n      issues: write\n")
		}, "permissions"},
		{"job pull-requests write", func(s string) string {
			return mutateFirstJob(s, "    permissions:\n      pull-requests: write\n")
		}, "permissions"},
		{"id-token write", func(s string) string { return strings.Replace(s, "contents: read", "id-token: write", 1) }, "permissions"},
		{"github token", injectDefaultStepEnv("TOKEN", "${{ github.token }}"), "github"},
		{"secret dot expression", injectDefaultStepEnv("TOKEN", "${{ secrets.EXAMPLE }}"), "secret"},
		{"secret bracket expression", injectDefaultStepEnv("TOKEN", "${{ secrets['EXAMPLE'] }}"), "secret"},
		{"whole secrets context", injectDefaultStepEnv("ALL_SECRETS", "${{ toJson(secrets) }}"), "secret"},
		{"whole github context", injectDefaultStepEnv("GITHUB_CONTEXT", "${{ toJson(github) }}"), "github"},
		{"reusable secrets inherit", func(s string) string { return mutateFirstJob(s, "    secrets: inherit\n") }, "secret"},
		{"checkout true with unrelated false", func(s string) string {
			s = strings.Replace(s, "persist-credentials: false", "persist-credentials: true", 1)
			return s
		}, "persist-credentials"},
		{"job missing timeout", func(s string) string { return strings.Replace(s, "    timeout-minutes: 15\n", "", 1) }, "timeout"},
		{"mutable action", func(s string) string {
			return strings.Replace(s, "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "actions/checkout@v4", 1)
		}, "full commit SHA"},
		{"upload artifact", insertUbuntuStep("      - name: Upload\n        uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567\n"), "steps"},
		{"build-push enabled", insertUbuntuStep("      - name: Publish image\n        uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567\n        with:\n          push: true\n"), "steps"},
		{"github script", insertUbuntuStep("      - name: Release\n        uses: actions/github-script@0123456789abcdef0123456789abcdef01234567\n        with:\n          script: github.rest.repos.createRelease({})\n"), "steps"},
		{"gh api release", replaceFirstDefaultCommand("gh api --method POST repos/example/project/releases"), "release API"},
		{"curl short upload", replaceFirstDefaultCommand("curl -T ./bin/synthcorpus-gen https://uploads.invalid/file"), "upload"},
		{"continue on error", func(s string) string {
			return strings.Replace(s, "      - name: Vet\n", "      - name: Vet\n        continue-on-error: true\n", 1)
		}, "continue-on-error"},
		{"constant false condition", injectDefaultStepCondition("${{ false }}"), "conditions"},
		{"runtime false condition", injectDefaultStepCondition("${{ github.event_name == 'never' }}"), "conditions"},
		{"branch condition", injectDefaultStepCondition("${{ github.ref == 'refs/heads/main' }}"), "conditions"},
		{"gitleaks job condition", func(s string) string {
			return strings.Replace(s, "  gitleaks:\n", "  gitleaks:\n    if: ${{ github.event_name == 'never' }}\n", 1)
		}, "conditions"},
		{"gitleaks scan condition", injectScannerCondition("${{ 0 == 1 }}"), "conditions"},
		{"shell soft failure", replaceFirstDefaultCommand("go test ./... || true"), "soft-failure"},
		{"reviewed command in wrong step", replaceFirstDefaultCommand("go test -race -count=1 ./..."), "job/step binding"},
		{"custom shell wrapper", func(s string) string {
			return strings.Replace(s, "      - name: Vet\n        run:", "      - name: Vet\n        shell: 'bash -c \"curl -T ./bin/synthcorpus-gen https://uploads.invalid; bash {0}\"'\n        run:", 1)
		}, "shell"},
		{"root defaults shell", func(s string) string {
			return strings.Replace(s, "permissions:\n", "defaults:\n  run:\n    shell: 'bash -c \"curl -T ./bin/synthcorpus-gen https://uploads.invalid; bash {0}\"'\npermissions:\n", 1)
		}, "workflow key"},
		{"job defaults shell", func(s string) string {
			return mutateFirstJob(s, "    defaults:\n      run:\n        shell: 'bash -c \"curl -T ./bin/synthcorpus-gen https://uploads.invalid; bash {0}\"'\n")
		}, "not allowed"},
		{"workflow env", func(s string) string {
			return strings.Replace(s, "permissions:\n", "env:\n  GOFLAGS: -mod=vendor\npermissions:\n", 1)
		}, "workflow key"},
		{"workflow BASH_ENV", func(s string) string {
			return strings.Replace(s, "permissions:\n", "env:\n  BASH_ENV: ./ci/wrapper.sh\npermissions:\n", 1)
		}, "workflow key"},
		{"job env", func(s string) string { return mutateFirstJob(s, "    env:\n      GOFLAGS: -mod=vendor\n") }, "not allowed"},
		{"job BASH_ENV", func(s string) string { return mutateFirstJob(s, "    env:\n      BASH_ENV: ./ci/wrapper.sh\n") }, "not allowed"},
		{"job strategy", func(s string) string { return mutateFirstJob(s, "    strategy:\n      fail-fast: false\n") }, "not allowed"},
		{"step BASH_ENV", injectDefaultStepEnv("BASH_ENV", "/tmp/wrapper"), "env"},
		{"step GOFLAGS", injectDefaultStepEnv("GOFLAGS", "-mod=vendor"), "env"},
		{"extra Gitleaks env", func(s string) string {
			return strings.Replace(s, "          GITLEAKS_VERSION: 8.30.1\n          GITLEAKS_ARCHIVE_SHA256:", "          GITLEAKS_VERSION: 8.30.1\n          GOFLAGS: -mod=vendor\n          GITLEAKS_ARCHIVE_SHA256:", 1)
		}, "environment"},
		{"changed Gitleaks version", func(s string) string {
			return strings.Replace(s, "GITLEAKS_VERSION: 8.30.1", "GITLEAKS_VERSION: 8.30.2", 1)
		}, "GITLEAKS_VERSION"},
		{"changed Gitleaks checksum", func(s string) string {
			return strings.Replace(s, "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", "051f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb0", 1)
		}, "GITLEAKS_ARCHIVE_SHA256"},
		{"duplicate mapping key", func(s string) string {
			return strings.Replace(s, "    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    runs-on: macos-latest", 1)
		}, "duplicate"},
		{"YAML alias", func(s string) string {
			return strings.Replace(s, "    runs-on: ubuntu-latest", "    runs-on: &runner ubuntu-latest\n    container: *runner", 1)
		}, "anchor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAndValidateWorkflow(tc.mutate(base))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("expected %q failure, got %v", tc.want, err)
			}
		})
	}
}

func TestReviewedGithubContextProperties(t *testing.T) {
	for _, expression := range []string{
		"${{ github.workflow }}",
		"${{ github.event.pull_request.number || github.ref }}",
		"${{ github.event_name == 'pull_request' }}",
	} {
		if err := validateSensitiveReferences(&yaml.Node{Kind: yaml.ScalarNode, Value: expression}, "positive control"); err != nil {
			t.Fatalf("reviewed expression %q failed: %v", expression, err)
		}
	}
}

func TestCurrentWorkflowPositiveControl(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAndValidateWorkflow(string(data)); err != nil {
		t.Fatalf("exact current workflow must remain accepted: %v", err)
	}
}

func mutateFirstJob(workflow, addition string) string {
	return strings.Replace(workflow, "    timeout-minutes: 15\n", "    timeout-minutes: 15\n"+addition, 1)
}

func insertUbuntuStep(step string) func(string) string {
	return func(workflow string) string {
		return strings.Replace(workflow, "  basic-macos:\n", step+"  basic-macos:\n", 1)
	}
}

func replaceFirstDefaultCommand(command string) func(string) string {
	return func(workflow string) string {
		return strings.Replace(workflow, "        run: go vet ./...", "        run: "+command, 1)
	}
}

func injectDefaultStepEnv(key, value string) func(string) string {
	return func(workflow string) string {
		return strings.Replace(workflow, "      - name: Vet\n        run:", "      - name: Vet\n        env:\n          "+key+": "+value+"\n        run:", 1)
	}
}

func injectDefaultStepCondition(condition string) func(string) string {
	return func(workflow string) string {
		return strings.Replace(workflow, "      - name: Vet\n", "      - name: Vet\n        if: "+condition+"\n", 1)
	}
}

func injectScannerCondition(condition string) func(string) string {
	return func(workflow string) string {
		return strings.Replace(workflow, "      - name: Scan committed tree and run scanner canaries\n", "      - name: Scan committed tree and run scanner canaries\n        if: "+condition+"\n", 1)
	}
}

func rejectPackagingSurfaces(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			switch rel {
			case ".git", "bin", ".cache", ".gocache":
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(entry.Name())
		lower := strings.ToLower(rel)
		alwaysForbidden := strings.HasPrefix(base, ".goreleaser") || strings.HasPrefix(base, ".release-please") ||
			(strings.Contains("/"+lower, "/formula/") && strings.HasSuffix(base, ".rb")) ||
			(strings.Contains("/"+lower, "/bucket/") && strings.HasSuffix(base, ".json"))
		if alwaysForbidden {
			return fmt.Errorf("generator packaging surface is forbidden by repository policy: %s", rel)
		}
		return nil
	})
}

func parseAndValidateWorkflow(data string) (*workflowDocument, error) {
	doc, err := parseWorkflow(data)
	if err != nil {
		return nil, err
	}
	if err := validateWorkflow(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func parseWorkflow(data string) (*workflowDocument, error) {
	dec := yaml.NewDecoder(strings.NewReader(data))
	var document yaml.Node
	if err := dec.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse workflow YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse workflow YAML: multiple documents are forbidden")
		}
		return nil, fmt.Errorf("parse workflow YAML: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("workflow must be one YAML document with a mapping root")
	}
	root := document.Content[0]
	if err := rejectYAMLAmbiguity(root, "workflow"); err != nil {
		return nil, err
	}
	return &workflowDocument{root: root}, nil
}

func rejectYAMLAmbiguity(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("%s: YAML anchors and aliases are forbidden", path)
	}
	switch node.Kind {
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s: malformed YAML mapping", path)
		}
		seen := make(map[string]bool, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Value == "<<" {
				return fmt.Errorf("%s: complex and merge mapping keys are forbidden", path)
			}
			if seen[key.Value] {
				return fmt.Errorf("%s: duplicate mapping key %q", path, key.Value)
			}
			seen[key.Value] = true
			if err := rejectYAMLAmbiguity(value, path+"."+key.Value); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			if err := rejectYAMLAmbiguity(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateWorkflow(doc *workflowDocument) error {
	root := doc.root
	if err := validateSensitiveReferences(root, "workflow"); err != nil {
		return err
	}
	if err := validatePermissions(mappingValue(root, "permissions"), "workflow permissions", true); err != nil {
		return err
	}
	if err := validateExactKeys(root, "workflow", "name", "on", "permissions", "concurrency", "jobs"); err != nil {
		return err
	}
	name, err := requiredScalarValue(root, "name", "workflow")
	if err != nil || name != "check" {
		return errors.New("workflow name must be exactly check")
	}
	if err := validateTriggers(mappingValue(root, "on")); err != nil {
		return err
	}
	if err := validateConcurrency(mappingValue(root, "concurrency")); err != nil {
		return err
	}
	jobs, err := requiredMappingValue(root, "jobs", "workflow")
	if err != nil {
		return err
	}
	if err := validateExactKeys(jobs, "workflow jobs", "basic-ubuntu", "basic-macos", "gitleaks"); err != nil {
		return err
	}
	for _, jobID := range []string{"basic-ubuntu", "basic-macos", "gitleaks"} {
		job := mappingValue(jobs, jobID)
		if job.Kind != yaml.MappingNode {
			return fmt.Errorf("job %s must be a mapping", jobID)
		}
		if err := validateJob(jobID, job); err != nil {
			return err
		}
	}
	return nil
}

func validateJob(jobID string, job *yaml.Node) error {
	context := "job " + jobID
	if mappingValue(job, "if") != nil {
		return fmt.Errorf("%s: conditions are forbidden", context)
	}
	if permissions := mappingValue(job, "permissions"); permissions != nil {
		return fmt.Errorf("%s permissions are forbidden; only workflow contents: read is allowed", context)
	}
	if mappingValue(job, "secrets") != nil {
		return fmt.Errorf("%s: secrets are forbidden", context)
	}
	if mappingValue(job, "timeout-minutes") == nil {
		return fmt.Errorf("%s timeout-minutes is required", context)
	}
	if err := validateExactKeys(job, context, "name", "runs-on", "timeout-minutes", "steps"); err != nil {
		return err
	}
	name, err := requiredScalarValue(job, "name", context)
	if err != nil || name != jobID {
		return fmt.Errorf("%s name must be exactly %s", context, jobID)
	}
	runner, err := requiredScalarValue(job, "runs-on", context)
	if err != nil {
		return err
	}
	wantRunner := "ubuntu-latest"
	if jobID == "basic-macos" {
		wantRunner = "macos-latest"
	}
	if runner != wantRunner {
		return fmt.Errorf("%s runs-on must be exactly %s", context, wantRunner)
	}
	timeout, err := requiredScalarValue(job, "timeout-minutes", context)
	if err != nil {
		return err
	}
	minutes, err := strconv.Atoi(timeout)
	if err != nil || minutes != 15 {
		return fmt.Errorf("%s timeout-minutes must be exactly 15", context)
	}
	steps := mappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s steps must be a sequence", context)
	}
	wantSteps := expectedStepNames(jobID)
	if len(steps.Content) != len(wantSteps) {
		return fmt.Errorf("%s steps must be exactly the reviewed ordered set", context)
	}
	for i, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			return fmt.Errorf("%s step %d must be a mapping", context, i+1)
		}
		if err := validateStep(context, i+1, wantSteps[i], step); err != nil {
			return err
		}
	}
	return nil
}

func expectedStepNames(jobID string) []string {
	commonStart := []string{"Check out source", "Set up Go", "Assert Go version"}
	switch jobID {
	case "basic-ubuntu":
		return append(commonStart, "Check formatting", "Vet", "Verify platform and no-publish policies", "Prove guardrails run without skips", "Test default lane")
	case "basic-macos":
		return append(commonStart, "Check formatting", "Vet", "Prove guardrails run without skips", "Test default lane")
	case "gitleaks":
		return append(commonStart, "Install verified Gitleaks", "Assert Gitleaks version", "Scan committed tree and run scanner canaries")
	default:
		return nil
	}
}

func validateStep(job string, index int, wantName string, step *yaml.Node) error {
	context := fmt.Sprintf("%s step %d", job, index)
	if mappingValue(step, "continue-on-error") != nil {
		return fmt.Errorf("%s: continue-on-error is forbidden", context)
	}
	if mappingValue(step, "if") != nil {
		return fmt.Errorf("%s: conditions are forbidden", context)
	}
	name, err := requiredScalarValue(step, "name", context)
	if err != nil || name != wantName {
		return fmt.Errorf("%s name must be exactly %q", context, wantName)
	}
	uses := mappingValue(step, "uses")
	run := mappingValue(step, "run")
	if (uses == nil) == (run == nil) {
		return fmt.Errorf("%s must contain exactly one of uses or run", context)
	}
	if uses != nil {
		if err := validateExactKeys(step, context, "name", "uses", "with"); err != nil {
			return err
		}
		if uses.Kind != yaml.ScalarNode {
			return fmt.Errorf("%s uses must be a scalar", context)
		}
		return validateActionStep(context, wantName, uses.Value, mappingValue(step, "with"))
	}
	if run.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s run must be a scalar", context)
	}
	wantShell, wantEnv := reviewedRunContext(wantName)
	allowedKeys := []string{"name", "run"}
	if wantShell != "" {
		allowedKeys = append(allowedKeys, "shell")
	}
	if wantEnv != nil {
		allowedKeys = append(allowedKeys, "env")
	}
	if err := validateExactKeys(step, context, allowedKeys...); err != nil {
		return err
	}
	if wantShell != "" {
		shell, err := requiredScalarValue(step, "shell", context)
		if err != nil || shell != wantShell {
			return fmt.Errorf("%s shell must be exactly %s", context, wantShell)
		}
	}
	if err := validateExactEnvironment(context, mappingValue(step, "env"), wantEnv); err != nil {
		return err
	}
	if err := validateShellCommand(context, run.Value); err != nil {
		return err
	}
	wantCommand := reviewedRunCommand(job, wantName)
	if normalizeShellCommand(run.Value) != normalizeShellCommand(wantCommand) {
		return fmt.Errorf("%s command must match its exact reviewed job/step binding", context)
	}
	return nil
}

func reviewedRunContext(name string) (string, map[string]string) {
	switch name {
	case "Assert Go version", "Check formatting", "Prove guardrails run without skips":
		return "bash", nil
	case "Install verified Gitleaks":
		return "bash", map[string]string{
			"GITLEAKS_VERSION":        "8.30.1",
			"GITLEAKS_ARCHIVE_SHA256": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
		}
	case "Assert Gitleaks version":
		return "bash", map[string]string{"GITLEAKS_VERSION": "8.30.1"}
	default:
		return "", nil
	}
}

func reviewedRunCommand(job, name string) string {
	switch name {
	case "Assert Go version":
		switch job {
		case "job basic-ubuntu":
			return `go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"
test "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64"`
		case "job basic-macos":
			return `go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"
test "$(go env GOOS)/$(go env GOARCH)" = "darwin/arm64"`
		case "job gitleaks":
			return `go version
test "$(go env GOVERSION)" = "go$(awk '$1 == "go" { print $2 }' go.mod)"`
		}
	case "Check formatting":
		return `test -z "$(gofmt -l .)"`
	case "Vet":
		return `go vet ./...`
	case "Verify platform and no-publish policies":
		return `go test -count=1 -v ./internal/repopolicy`
	case "Prove guardrails run without skips":
		return `output="$RUNNER_TEMP/guardrail-test.log"
set +e
go test -race -count=1 -v ./internal/guardrail 2>&1 | tee "$output"
status=${PIPESTATUS[0]}
set -e
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
grep -q '^=== RUN' "$output"
if grep -q '^--- SKIP:' "$output"; then
  echo 'guardrail tests must not skip' >&2
  exit 1
fi`
	case "Test default lane":
		return `go test -race -count=1 ./...`
	case "Install verified Gitleaks":
		return `archive="$RUNNER_TEMP/gitleaks.tar.gz"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
printf '%s  %s\n' "$GITLEAKS_ARCHIVE_SHA256" "$archive" | sha256sum --check --strict
tar -xzf "$archive" -C "$RUNNER_TEMP" gitleaks
printf '%s\n' "$RUNNER_TEMP" >> "$GITHUB_PATH"`
	case "Assert Gitleaks version":
		return `gitleaks version
test "$(gitleaks version)" = "$GITLEAKS_VERSION"`
	case "Scan committed tree and run scanner canaries":
		return `make gitleaks`
	}
	return ""
}

func validateActionStep(context, name, ref string, inputs *yaml.Node) error {
	match := actionRef.FindStringSubmatch(ref)
	if match == nil {
		return fmt.Errorf("%s action must use a full commit SHA: %s", context, ref)
	}
	action := match[1]
	switch name {
	case "Check out source":
		if action != "actions/checkout" || match[2] != "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0" {
			return fmt.Errorf("%s action must be the exact reviewed checkout SHA", context)
		}
		return validateExactInputs(context, inputs, map[string]string{"persist-credentials": "false"})
	case "Set up Go":
		if action != "actions/setup-go" || match[2] != "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" {
			return fmt.Errorf("%s action must be the exact reviewed setup-go SHA", context)
		}
		return validateExactInputs(context, inputs, map[string]string{"go-version-file": "go.mod", "cache": "false"})
	default:
		return fmt.Errorf("%s action step %q is not allowed by repository workflow policy", context, name)
	}
}

func validateExactEnvironment(context string, env *yaml.Node, expected map[string]string) error {
	if expected == nil {
		if env != nil {
			return fmt.Errorf("%s env is forbidden", context)
		}
		return nil
	}
	if env == nil || env.Kind != yaml.MappingNode || len(env.Content)/2 != len(expected) {
		return fmt.Errorf("%s environment must be exactly the reviewed set", context)
	}
	for key, want := range expected {
		value := mappingValue(env, key)
		if value == nil || value.Kind != yaml.ScalarNode || value.Value != want {
			return fmt.Errorf("%s environment requires %s: %s", context, key, want)
		}
	}
	for i := 0; i < len(env.Content); i += 2 {
		if _, ok := expected[env.Content[i].Value]; !ok {
			return fmt.Errorf("%s environment key %q is not allowed", context, env.Content[i].Value)
		}
	}
	return nil
}

func validateExactInputs(context string, inputs *yaml.Node, expected map[string]string) error {
	if inputs == nil || inputs.Kind != yaml.MappingNode {
		return fmt.Errorf("%s requires explicit action inputs", context)
	}
	if len(inputs.Content)/2 != len(expected) {
		return fmt.Errorf("%s action inputs must be exactly the reviewed set", context)
	}
	for key, want := range expected {
		value := mappingValue(inputs, key)
		if value == nil || value.Kind != yaml.ScalarNode || value.Value != want {
			return fmt.Errorf("%s requires %s: %s", context, key, want)
		}
	}
	for i := 0; i < len(inputs.Content); i += 2 {
		if _, ok := expected[inputs.Content[i].Value]; !ok {
			return fmt.Errorf("%s action input %q is not allowed", context, inputs.Content[i].Value)
		}
	}
	return nil
}

func validatePermissions(node *yaml.Node, context string, required bool) error {
	if node == nil {
		if required {
			return fmt.Errorf("%s must declare exactly contents: read", context)
		}
		return nil
	}
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
		return fmt.Errorf("%s may grant exactly contents: read; read-all and write-all are forbidden", context)
	}
	if node.Content[0].Value != "contents" || node.Content[1].Kind != yaml.ScalarNode || node.Content[1].Value != "read" {
		return fmt.Errorf("%s may grant exactly contents: read; every write permission is forbidden", context)
	}
	return nil
}

func validateTriggers(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.MappingNode {
		return errors.New("workflow on must be the exact pull_request and main push trigger mapping")
	}
	if err := validateExactKeys(node, "workflow on", "pull_request", "push"); err != nil {
		return err
	}
	pullRequest := mappingValue(node, "pull_request")
	if pullRequest == nil || pullRequest.Kind != yaml.ScalarNode || pullRequest.Value != "" {
		return errors.New("workflow pull_request trigger must be unconditional")
	}
	push, err := requiredMappingValue(node, "push", "workflow on")
	if err != nil {
		return err
	}
	if err := validateExactKeys(push, "workflow push trigger", "branches"); err != nil {
		return err
	}
	branches := mappingValue(push, "branches")
	if branches == nil || branches.Kind != yaml.SequenceNode || len(branches.Content) != 1 || branches.Content[0].Kind != yaml.ScalarNode || branches.Content[0].Value != "main" {
		return errors.New("workflow push branches must be exactly main")
	}
	return nil
}

func validateConcurrency(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.MappingNode {
		return errors.New("workflow concurrency must be the exact reviewed mapping")
	}
	if err := validateExactKeys(node, "workflow concurrency", "group", "cancel-in-progress"); err != nil {
		return err
	}
	group, err := requiredScalarValue(node, "group", "workflow concurrency")
	if err != nil || group != "check-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}" {
		return errors.New("workflow concurrency group must be exactly the reviewed expression")
	}
	cancel, err := requiredScalarValue(node, "cancel-in-progress", "workflow concurrency")
	if err != nil || cancel != "${{ github.event_name == 'pull_request' }}" {
		return errors.New("workflow cancel-in-progress must be exactly the reviewed expression")
	}
	return nil
}

func validateExactKeys(mapping *yaml.Node, context string, allowed ...string) error {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", context)
	}
	want := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		want[key] = true
	}
	if len(mapping.Content)/2 != len(want) {
		for i := 0; i < len(mapping.Content); i += 2 {
			key := mapping.Content[i].Value
			if !want[key] {
				return fmt.Errorf("%s key %q is not allowed", context, key)
			}
		}
		return fmt.Errorf("%s must contain exactly the reviewed keys", context)
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		if !want[key] {
			return fmt.Errorf("%s key %q is not allowed", context, key)
		}
	}
	return nil
}

func validateSensitiveReferences(node *yaml.Node, path string) error {
	if node.Kind == yaml.ScalarNode {
		if strings.Contains(node.Value, "${{") && !strings.Contains(node.Value, "}}") {
			return fmt.Errorf("%s contains a malformed GitHub expression", path)
		}
		for _, match := range workflowExpression.FindAllStringSubmatch(node.Value, -1) {
			expression := match[1]
			if secretsIdentifier.MatchString(expression) {
				return fmt.Errorf("%s references the secrets context", path)
			}
			for _, location := range githubIdentifier.FindAllStringIndex(expression, -1) {
				remainder := strings.TrimLeft(expression[location[1]:], " \t\r\n")
				if !strings.HasPrefix(remainder, ".") {
					return fmt.Errorf("%s references the whole github context", path)
				}
				property := strings.TrimLeft(remainder[1:], " \t\r\n")
				end := strings.IndexFunc(property, func(r rune) bool {
					return !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
				})
				if end >= 0 {
					property = property[:end]
				}
				switch property {
				case "workflow", "event", "event_name", "ref":
				default:
					return fmt.Errorf("%s references unreviewed github property %q", path, property)
				}
			}
		}
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if strings.EqualFold(key.Value, "secrets") {
				return fmt.Errorf("%s.%s declares a secret source", path, key.Value)
			}
			if err := validateSensitiveReferences(value, path+"."+key.Value); err != nil {
				return err
			}
		}
	} else if node.Kind == yaml.SequenceNode {
		for i, child := range node.Content {
			if err := validateSensitiveReferences(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateShellCommand(context, command string) error {
	active := activeShellText(command)
	lower := strings.ToLower(active)
	if softFailure.MatchString(lower) {
		return fmt.Errorf("%s contains a forbidden shell soft-failure form", context)
	}
	if curlUpload.MatchString(lower) {
		return fmt.Errorf("%s contains a forbidden upload command", context)
	}
	normalized := strings.Join(strings.Fields(lower), " ")
	if strings.Contains(normalized, "gh api") && strings.Contains(normalized, "release") {
		return fmt.Errorf("%s contains a forbidden GitHub release API command", context)
	}
	for _, needle := range []string{
		"gh release", "npm publish", "cargo publish", "docker push", "goreleaser",
		"aws s3 cp", "gsutil cp", "rclone copy", "cosign attest", "gh attestation",
	} {
		if strings.Contains(normalized, needle) {
			return fmt.Errorf("%s contains forbidden publish/release/provenance command %q", context, needle)
		}
	}
	if !reviewedShellCommands[normalizeShellCommand(command)] {
		return fmt.Errorf("%s shell command is not in the exact reviewed allowlist", context)
	}
	return nil
}

func shellCommandSet(commands ...string) map[string]bool {
	set := make(map[string]bool, len(commands))
	for _, command := range commands {
		set[normalizeShellCommand(command)] = true
	}
	return set
}

func normalizeShellCommand(command string) string {
	return strings.TrimSpace(strings.ReplaceAll(command, "\r\n", "\n"))
}

func activeShellText(command string) string {
	var active []string
	for _, line := range strings.Split(command, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		active = append(active, trimmed)
	}
	return strings.Join(active, "\n")
}

func isConstantFalse(node *yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	compact := strings.ToLower(strings.Join(strings.Fields(node.Value), ""))
	return compact == "false" || compact == "${{false}}"
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func requiredMappingValue(mapping *yaml.Node, key, context string) (*yaml.Node, error) {
	value := mappingValue(mapping, key)
	if value == nil || value.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s %s must be a mapping", context, key)
	}
	return value, nil
}

func requiredScalarValue(mapping *yaml.Node, key, context string) (string, error) {
	value := mappingValue(mapping, key)
	if value == nil || value.Kind != yaml.ScalarNode || strings.TrimSpace(value.Value) == "" {
		return "", fmt.Errorf("%s %s must be a non-empty scalar", context, key)
	}
	return value.Value, nil
}

func mustParseWorkflow(t *testing.T, data string) *workflowDocument {
	t.Helper()
	doc, err := parseWorkflow(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
