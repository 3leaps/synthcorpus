package repopolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const platformPolicyPath = "ci/platforms.json"

type platformPolicy struct {
	SchemaVersion string     `json:"schema_version"`
	Kind          string     `json:"kind"`
	Platforms     []platform `json:"platforms"`
}

type platform struct {
	ID     string        `json:"id"`
	GOOS   string        `json:"goos"`
	GOARCH string        `json:"goarch"`
	Runner runnerPolicy  `json:"runner"`
	Lanes  platformLanes `json:"lanes"`
}

type runnerPolicy struct {
	State             string `json:"state"`
	Label             string `json:"label,omitempty"`
	JobID             string `json:"job_id,omitempty"`
	JobName           string `json:"job_name,omitempty"`
	MissingCapability string `json:"missing_capability,omitempty"`
	Reason            string `json:"reason,omitempty"`
	LiftCondition     string `json:"lift_condition,omitempty"`
}

type platformLanes struct {
	SidecarFree     lanePolicy `json:"sidecar_free"`
	CommittedGolden lanePolicy `json:"committed_golden"`
	GeneratedReal   lanePolicy `json:"generated_real"`
}

type lanePolicy struct {
	Obligation        string `json:"obligation"`
	Execution         string `json:"execution"`
	Command           string `json:"command,omitempty"`
	MissingCapability string `json:"missing_capability,omitempty"`
	Reason            string `json:"reason,omitempty"`
	LiftCondition     string `json:"lift_condition,omitempty"`
}

func TestPlatformPolicy(t *testing.T) {
	root := repoRoot(t)
	policy := mustLoadPlatformPolicy(t, filepath.Join(root, platformPolicyPath))
	if err := validatePlatformPolicy(policy); err != nil {
		t.Fatal(err)
	}
	workflowData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := parseAndValidateWorkflow(string(workflowData))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWorkflowBindings(policy, workflow); err != nil {
		t.Fatal(err)
	}
	logNonActivePolicy(t, policy)
}

func TestPlatformPolicyNegativeControls(t *testing.T) {
	root := repoRoot(t)
	policyPath := filepath.Join(root, platformPolicyPath)
	workflowPath := filepath.Join(root, ".github", "workflows", "check.yml")
	workflowData, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("assertion only in comment", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		assertion := `test "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64"`
		mutated := strings.Replace(string(workflowData), assertion, "# "+assertion, 1)
		workflow := mustParseWorkflow(t, mutated)
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "linux/amd64")
	})

	t.Run("Linux assertion moved to macOS job", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		linuxAssertion := `test "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64"`
		darwinAssertion := `test "$(go env GOOS)/$(go env GOARCH)" = "darwin/arm64"`
		mutated := strings.Replace(string(workflowData), linuxAssertion, "true", 1)
		mutated = strings.Replace(mutated, darwinAssertion, darwinAssertion+"\n          "+linuxAssertion, 1)
		workflow := mustParseWorkflow(t, mutated)
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "basic-ubuntu")
	})

	t.Run("active lane command removed", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		mutated := strings.Replace(string(workflowData), "go test -race -count=1 ./...", "go test -race -count=1 ./cmd/...", 1)
		workflow := mustParseWorkflow(t, mutated)
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "sidecar_free")
	})

	t.Run("conditional step does not count as active execution", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		old := "      - name: Test default lane\n        run: go test -race -count=1 ./..."
		replacement := "      - name: Test default lane\n        if: github.ref == 'refs/heads/main'\n        run: go test -race -count=1 ./..."
		mutated := strings.Replace(string(workflowData), old, replacement, 1)
		workflow := mustParseWorkflow(t, mutated)
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "sidecar_free")
	})

	t.Run("active generated-real lane has no bound command", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		p := platformByID(t, &policy, "linux-amd64")
		p.Lanes.GeneratedReal.Execution = "active"
		p.Lanes.GeneratedReal.Command = "make generated-real-check"
		p.Lanes.GeneratedReal.MissingCapability = ""
		p.Lanes.GeneratedReal.Reason = ""
		p.Lanes.GeneratedReal.LiftCondition = ""
		workflow := mustParseWorkflow(t, string(workflowData))
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "generated_real")
	})

	t.Run("blocked lane missing reason", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		platformByID(t, &policy, "linux-amd64").Lanes.GeneratedReal.Reason = ""
		wantPolicyFailure(t, validatePlatformPolicy(policy), "explanatory")
	})

	t.Run("blocked lane missing lift condition", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		platformByID(t, &policy, "darwin-arm64").Lanes.CommittedGolden.LiftCondition = ""
		wantPolicyFailure(t, validatePlatformPolicy(policy), "explanatory")
	})

	t.Run("sidecar-free obligation removed", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		platformByID(t, &policy, "linux-amd64").Lanes.SidecarFree.Obligation = ""
		wantPolicyFailure(t, validatePlatformPolicy(policy), "sidecar_free obligation")
	})

	t.Run("duplicate platform row", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		policy.Platforms = append(policy.Platforms, policy.Platforms[0])
		wantPolicyFailure(t, validatePlatformPolicy(policy), "duplicate")
	})

	t.Run("missing platform row", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		policy.Platforms = policy.Platforms[:len(policy.Platforms)-1]
		wantPolicyFailure(t, validatePlatformPolicy(policy), "missing")
	})

	t.Run("comments-only workflow does not bind", func(t *testing.T) {
		policy := mustLoadPlatformPolicy(t, policyPath)
		workflow := mustParseWorkflow(t, `name: comments-only
permissions:
  contents: read
jobs:
  placeholder:
    name: placeholder
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: |
          # runs-on: ubuntu-latest
          # test "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64"
          # go test -race -count=1 ./...
          true
`)
		wantBindingFailure(t, validateWorkflowBindings(policy, workflow), "basic-ubuntu")
	})
}

func mustLoadPlatformPolicy(t *testing.T, path string) platformPolicy {
	t.Helper()
	policy, err := loadPlatformPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func loadPlatformPolicy(path string) (platformPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return platformPolicy{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var policy platformPolicy
	if err := dec.Decode(&policy); err != nil {
		return platformPolicy{}, fmt.Errorf("parse platform policy: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return platformPolicy{}, errors.New("parse platform policy: multiple JSON values")
		}
		return platformPolicy{}, fmt.Errorf("parse platform policy: %w", err)
	}
	return policy, nil
}

func validatePlatformPolicy(policy platformPolicy) error {
	if policy.SchemaVersion != "v0" || policy.Kind != "synthcorpus-ci-platform-policy" {
		return fmt.Errorf("unsupported platform policy identity %q/%q", policy.SchemaVersion, policy.Kind)
	}
	wantCoords := map[string][2]string{
		"linux-amd64":   {"linux", "amd64"},
		"linux-arm64":   {"linux", "arm64"},
		"darwin-arm64":  {"darwin", "arm64"},
		"windows-amd64": {"windows", "amd64"},
		"windows-arm64": {"windows", "arm64"},
	}
	wantRunners := map[string][3]string{
		"linux-amd64":  {"ubuntu-latest", "basic-ubuntu", "basic-ubuntu"},
		"darwin-arm64": {"macos-latest", "basic-macos", "basic-macos"},
	}
	wantExecution := map[string][3]string{
		"linux-amd64":   {"active", "blocked", "blocked"},
		"linux-arm64":   {"deferred", "deferred", "deferred"},
		"darwin-arm64":  {"active", "blocked", "blocked"},
		"windows-amd64": {"deferred", "deferred", "excluded"},
		"windows-arm64": {"deferred", "deferred", "excluded"},
	}

	seen := make(map[string]bool, len(policy.Platforms))
	for _, p := range policy.Platforms {
		coords, ok := wantCoords[p.ID]
		if !ok {
			return fmt.Errorf("unexpected platform %q", p.ID)
		}
		if seen[p.ID] {
			return fmt.Errorf("duplicate platform %q", p.ID)
		}
		seen[p.ID] = true
		if p.GOOS != coords[0] || p.GOARCH != coords[1] {
			return fmt.Errorf("platform %s declares %s/%s, want %s/%s", p.ID, p.GOOS, p.GOARCH, coords[0], coords[1])
		}

		if binding, active := wantRunners[p.ID]; active {
			if p.Runner.State != "active" || p.Runner.Label != binding[0] || p.Runner.JobID != binding[1] || p.Runner.JobName != binding[2] {
				return fmt.Errorf("platform %s active runner binding is invalid", p.ID)
			}
			if hasExplanation(p.Runner.MissingCapability, p.Runner.Reason, p.Runner.LiftCondition) {
				return fmt.Errorf("platform %s active runner cannot carry non-active explanation fields", p.ID)
			}
		} else {
			if p.Runner.State != "deferred" || p.Runner.Label != "" || p.Runner.JobID != "" || p.Runner.JobName != "" {
				return fmt.Errorf("platform %s deferred runner binding is invalid", p.ID)
			}
			if !hasCompleteExplanation(p.Runner.MissingCapability, p.Runner.Reason, p.Runner.LiftCondition) {
				return fmt.Errorf("platform %s deferred runner requires complete explanatory fields", p.ID)
			}
		}

		lanes := []struct {
			name string
			lane lanePolicy
			want string
		}{
			{"sidecar_free", p.Lanes.SidecarFree, wantExecution[p.ID][0]},
			{"committed_golden", p.Lanes.CommittedGolden, wantExecution[p.ID][1]},
			{"generated_real", p.Lanes.GeneratedReal, wantExecution[p.ID][2]},
		}
		for _, item := range lanes {
			wantObligation := "required"
			if item.name == "generated_real" && strings.HasPrefix(p.ID, "windows-") {
				wantObligation = "excluded"
			}
			if item.lane.Obligation != wantObligation {
				return fmt.Errorf("platform %s %s obligation %q, want %q", p.ID, item.name, item.lane.Obligation, wantObligation)
			}
			if item.lane.Execution != item.want {
				return fmt.Errorf("platform %s %s execution %q, want %q", p.ID, item.name, item.lane.Execution, item.want)
			}
			if err := validateLaneShape(p, item.name, item.lane); err != nil {
				return err
			}
		}
	}
	if len(seen) != len(wantCoords) {
		return fmt.Errorf("platform policy has %d unique rows, want %d; a platform row is missing", len(seen), len(wantCoords))
	}
	for id := range wantCoords {
		if !seen[id] {
			return fmt.Errorf("platform policy missing %s", id)
		}
	}
	return nil
}

func validateLaneShape(p platform, name string, lane lanePolicy) error {
	switch lane.Execution {
	case "active":
		if p.Runner.State != "active" {
			return fmt.Errorf("platform %s %s cannot be active without an active runner", p.ID, name)
		}
		if strings.TrimSpace(lane.Command) == "" {
			return fmt.Errorf("platform %s %s active lane requires a command", p.ID, name)
		}
		if hasExplanation(lane.MissingCapability, lane.Reason, lane.LiftCondition) {
			return fmt.Errorf("platform %s %s active lane cannot carry non-active explanation fields", p.ID, name)
		}
	case "blocked", "deferred", "excluded":
		if lane.Command != "" || !hasCompleteExplanation(lane.MissingCapability, lane.Reason, lane.LiftCondition) {
			return fmt.Errorf("platform %s %s non-active lane requires complete explanatory fields and no active command", p.ID, name)
		}
	default:
		return fmt.Errorf("platform %s %s has invalid execution state %q", p.ID, name, lane.Execution)
	}
	return nil
}

func validateWorkflowBindings(policy platformPolicy, workflow *workflowDocument) error {
	jobs, err := requiredMappingValue(workflow.root, "jobs", "workflow")
	if err != nil {
		return err
	}
	for _, p := range policy.Platforms {
		if p.Runner.State != "active" {
			continue
		}
		job := mappingValue(jobs, p.Runner.JobID)
		if job == nil {
			return fmt.Errorf("platform %s bound workflow job %s is missing", p.ID, p.Runner.JobID)
		}
		name, err := requiredScalarValue(job, "name", "job "+p.Runner.JobID)
		if err != nil || name != p.Runner.JobName {
			return fmt.Errorf("platform %s bound job %s display name must be %q", p.ID, p.Runner.JobID, p.Runner.JobName)
		}
		runner, err := requiredScalarValue(job, "runs-on", "job "+p.Runner.JobID)
		if err != nil || runner != p.Runner.Label {
			return fmt.Errorf("platform %s bound job %s runner must be %q", p.ID, p.Runner.JobID, p.Runner.Label)
		}
		if mappingValue(job, "if") != nil {
			return fmt.Errorf("platform %s bound job %s cannot be conditional", p.ID, p.Runner.JobID)
		}
		assertion := fmt.Sprintf(`test "$(go env GOOS)/$(go env GOARCH)" = "%s/%s"`, p.GOOS, p.GOARCH)
		if !commandInJob(job, assertion) {
			return fmt.Errorf("platform %s bound job %s is missing exact %s/%s assertion", p.ID, p.Runner.JobID, p.GOOS, p.GOARCH)
		}
		lanes := []struct {
			name string
			lane lanePolicy
		}{
			{"sidecar_free", p.Lanes.SidecarFree},
			{"committed_golden", p.Lanes.CommittedGolden},
			{"generated_real", p.Lanes.GeneratedReal},
		}
		for _, item := range lanes {
			if item.lane.Execution == "active" && !commandInJob(job, item.lane.Command) {
				return fmt.Errorf("platform %s bound job %s is missing active %s command %q", p.ID, p.Runner.JobID, item.name, item.lane.Command)
			}
		}
	}
	return nil
}

func commandInJob(job *yaml.Node, command string) bool {
	steps := mappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return false
	}
	for _, step := range steps.Content {
		if mappingValue(step, "if") != nil {
			continue
		}
		run := mappingValue(step, "run")
		if run == nil || run.Kind != yaml.ScalarNode {
			continue
		}
		for _, line := range strings.Split(run.Value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if line == command {
				return true
			}
		}
	}
	return false
}

func logNonActivePolicy(t *testing.T, policy platformPolicy) {
	t.Helper()
	for _, p := range policy.Platforms {
		if p.Runner.State != "active" {
			t.Logf("runner state: platform=%s execution=%s missing_capability=%q reason=%q lift_condition=%q",
				p.ID, p.Runner.State, p.Runner.MissingCapability, p.Runner.Reason, p.Runner.LiftCondition)
		}
		for _, item := range []struct {
			name string
			lane lanePolicy
		}{{"sidecar_free", p.Lanes.SidecarFree}, {"committed_golden", p.Lanes.CommittedGolden}, {"generated_real", p.Lanes.GeneratedReal}} {
			if item.lane.Execution != "active" {
				t.Logf("lane state: platform=%s lane=%s obligation=%s execution=%s missing_capability=%q reason=%q lift_condition=%q",
					p.ID, item.name, item.lane.Obligation, item.lane.Execution, item.lane.MissingCapability, item.lane.Reason, item.lane.LiftCondition)
			}
		}
	}
}

func platformByID(t *testing.T, policy *platformPolicy, id string) *platform {
	t.Helper()
	for i := range policy.Platforms {
		if policy.Platforms[i].ID == id {
			return &policy.Platforms[i]
		}
	}
	t.Fatalf("platform %s not found", id)
	return nil
}

func hasExplanation(values ...string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

func hasCompleteExplanation(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func wantBindingFailure(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
		t.Fatalf("expected binding failure containing %q, got %v", contains, err)
	}
}

func wantPolicyFailure(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
		t.Fatalf("expected policy failure containing %q, got %v", contains, err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
