//go:build scanner

package provability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Hermetic gitleaks tests: never mutate the real worktree.
// Always run with Dir=sourceRoot and --source . so finding paths are
// source-root-relative (required for ^fixtures/... allowlist anchors).

func TestGitleaksCommittedTreeClean(t *testing.T) {
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitleaks, "detect", "--source", ".", "--no-git", "--config", config, "--no-banner")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gitleaks on committed tree: %v\n%s", err, out)
	}
}

func TestGitleaksRootCanaryDetected(t *testing.T) {
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	src := t.TempDir()
	canary := filepath.Join(src, "CANARY_ROOT.txt")
	if err := os.WriteFile(canary, []byte(rsaPrivateKeyCanary()), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "CANARY_ROOT.txt", "private-key") {
		t.Fatalf("expected private-key on CANARY_ROOT.txt, got %#v", summarize(findings))
	}
}

func TestGitleaksUnrelatedRuleOnSyntheticPathStillDetected(t *testing.T) {
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	src := t.TempDir()
	dir := filepath.Join(src, "fixtures", "gpg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	pat := "ghp_" + "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW1xY2"
	if err := os.WriteFile(filepath.Join(dir, "private.asc"), append(orig, []byte("\n"+pat+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "private.asc", "github-pat") {
		t.Fatalf("expected github-pat on private.asc, got %#v", summarize(findings))
	}
	for _, f := range findings {
		if f.RuleID == "private-key" && strings.HasSuffix(filepath.ToSlash(f.File), "fixtures/gpg/private.asc") {
			t.Fatalf("reviewed private-key content should be suppressed at registered path, got %v", f)
		}
	}
}

func TestGitleaksByteIdenticalCopyOutsidePathDetected(t *testing.T) {
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	src := t.TempDir()
	regDir := filepath.Join(src, "fixtures", "gpg")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regDir, "private.asc"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	elseDir := filepath.Join(src, "elsewhere")
	if err := os.MkdirAll(elseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elseDir, "copied-private.asc"), orig, 0o600); err != nil {
		t.Fatal(err)
	}

	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "copied-private.asc", "private-key") {
		t.Fatalf("expected private-key on unregistered copy, got %#v", summarize(findings))
	}
	for _, f := range findings {
		if f.RuleID == "private-key" && filepath.ToSlash(f.File) == "fixtures/gpg/private.asc" {
			t.Fatalf("registered path should remain suppressed, got %v", f)
		}
	}
}

func TestGitleaksSuffixShadowPathDetected(t *testing.T) {
	// elsewhere/fixtures/gpg/private.asc must NOT match ^fixtures/... anchors.
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	src := t.TempDir()
	regDir := filepath.Join(src, "fixtures", "gpg")
	shadow := filepath.Join(src, "elsewhere", "fixtures", "gpg")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shadow, 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regDir, "private.asc"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shadow, "private.asc"), orig, 0o600); err != nil {
		t.Fatal(err)
	}

	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "elsewhere/fixtures/gpg/private.asc", "private-key") &&
		!hasFinding(findings, "elsewhere\\fixtures\\gpg\\private.asc", "private-key") {
		// Match on path ending
		ok := false
		for _, f := range findings {
			if f.RuleID == "private-key" && strings.Contains(filepath.ToSlash(f.File), "elsewhere/fixtures/gpg/private.asc") {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("expected private-key on suffix-shadow path, got %#v", summarize(findings))
		}
	}
	for _, f := range findings {
		if f.RuleID == "private-key" && filepath.ToSlash(f.File) == "fixtures/gpg/private.asc" {
			t.Fatalf("true registered path should be suppressed, got %v", f)
		}
	}
}

func TestGitleaksDifferentPrivateKeyAtRegisteredPathDetected(t *testing.T) {
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	src := t.TempDir()
	dir := filepath.Join(src, "fixtures", "gpg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Distinct synthetic RSA block — not the reviewed fixture bytes.
	if err := os.WriteFile(filepath.Join(dir, "private.asc"), []byte(rsaPrivateKeyCanary()), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "private.asc", "private-key") {
		t.Fatalf("expected private-key for different content at registered path, got %#v", summarize(findings))
	}
}

func TestGitleaksOneFieldMutationAtRegisteredPathDetected(t *testing.T) {
	// Exact-content allowlist: mutating one field of the reviewed specimen must unsuppress.
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	mut := bytes.ReplaceAll(orig, []byte("=AAAA"), []byte("=BBBB"))
	if bytes.Equal(mut, orig) {
		t.Fatal("expected mutation of =AAAA to =BBBB to change fixture bytes")
	}
	if !bytes.Contains(mut, []byte("=BBBB")) {
		t.Fatal("mutation did not apply")
	}

	src := t.TempDir()
	dir := filepath.Join(src, "fixtures", "gpg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.asc"), mut, 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "private.asc", "private-key") {
		t.Fatalf("expected private-key for one-field mutation at registered path, got %#v", summarize(findings))
	}
}

func TestGitleaksPrependedPrivateKeyHeaderAtRegisteredPathDetected(t *testing.T) {
	// Full-match content anchors: reviewed specimen as a substring of a larger
	// private-key finding must not be allowlisted.
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	// Distinct begin line so the Gitleaks Match spans more than the reviewed block.
	prepended := append([]byte("-----BEGIN "+"RSA PRIVATE KEY-----\n"), orig...)

	src := t.TempDir()
	dir := filepath.Join(src, "fixtures", "gpg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.asc"), prepended, 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "private.asc", "private-key") {
		t.Fatalf("expected private-key for prepended distinct header at registered path, got %#v", summarize(findings))
	}
}

func TestGitleaksCaseShadowPathDetected(t *testing.T) {
	// Path predicates are case-sensitive: uppercase path is not the inventory path.
	gitleaks := mustGitleaks(t)
	repo := repoRoot(t)
	config := filepath.Join(repo, ".gitleaks.toml")

	orig, err := os.ReadFile(filepath.Join(repo, "fixtures", "gpg", "private.asc"))
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	// Only the case-shadow path (no canonical lowercase path).
	dir := filepath.Join(src, "FIXTURES", "GPG")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PRIVATE.ASC"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	findings := runGitleaksExpectLeak(t, gitleaks, config, src, report)
	if !hasFinding(findings, "FIXTURES/GPG/PRIVATE.ASC", "private-key") &&
		!hasFinding(findings, "FIXTURES\\GPG\\PRIVATE.ASC", "private-key") {
		ok := false
		for _, f := range findings {
			if f.RuleID == "private-key" && strings.Contains(strings.ToUpper(filepath.ToSlash(f.File)), "FIXTURES/GPG/PRIVATE.ASC") {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("expected private-key on case-shadow path, got %#v", summarize(findings))
		}
	}
}

func TestClassifyGitleaksOutcome(t *testing.T) {
	// Table-testable outcome classification; exit codes from helper-process re-exec (no shell).
	cases := []struct {
		name    string
		ctxErr  error
		runErr  error
		wantErr string
	}{
		{name: "timeout", ctxErr: context.DeadlineExceeded, runErr: context.DeadlineExceeded, wantErr: "timed out"},
		{name: "success", runErr: nil, wantErr: "expected gitleaks leak"},
		{name: "generic", runErr: errors.New("boom"), wantErr: "ExitError"},
		{name: "wrong-exit", runErr: exitErrorWithCode(t, 2), wantErr: "exit code 1"},
		{name: "ok-exit-1", runErr: exitErrorWithCode(t, 1), wantErr: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyGitleaksLeakOutcome(tc.ctxErr, tc.runErr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestHelperProcess is re-exec'd by exitErrorWithCode; not a real test.
func TestHelperProcess(*testing.T) {
	if os.Getenv("SYNTHCORPUS_HELPER_PROCESS") != "1" {
		return
	}
	code := 1
	if v := os.Getenv("SYNTHCORPUS_HELPER_EXIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			code = n
		}
	}
	os.Exit(code)
}

func rsaPrivateKeyCanary() string {
	return "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGFwO\n" +
		"-----END " + "RSA PRIVATE KEY-----\n"
}

// runGitleaksExpectLeak requires a started process that exits with code 1
// (configured --exit-code 1), not timeout/start failure, then returns findings.
// Runs with Dir=sourceRoot and --source . for relative finding paths.
func runGitleaksExpectLeak(t *testing.T, gitleaks, config, sourceRoot, report string) []gitleaksFinding {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitleaks, "detect",
		"--source", ".", "--no-git", "--config", config, "--no-banner",
		"-f", "json", "-r", report, "--exit-code", "1")
	cmd.Dir = sourceRoot
	err := cmd.Run()
	if cerr := classifyGitleaksLeakOutcome(ctx.Err(), err); cerr != nil {
		t.Fatal(cerr)
	}
	return readFindings(t, report)
}

func classifyGitleaksLeakOutcome(ctxErr, runErr error) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return errors.New("gitleaks canary timed out")
	}
	if runErr == nil {
		return errors.New("expected gitleaks leak exit (code 1)")
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return errors.New("expected *exec.ExitError from started gitleaks")
	}
	if code := exitErr.ExitCode(); code != 1 {
		return errors.New("expected exit code 1")
	}
	return nil
}

// exitErrorWithCode builds a real *exec.ExitError by re-execing this test
// binary under TestHelperProcess (cross-platform; no external shell).
func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"SYNTHCORPUS_HELPER_PROCESS=1",
		"SYNTHCORPUS_HELPER_EXIT="+strconv.Itoa(code),
	)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee
	}
	t.Fatalf("helper process did not return ExitError: %v", err)
	return err
}

type gitleaksFinding struct {
	RuleID string `json:"RuleID"`
	File   string `json:"File"`
}

func readFindings(t *testing.T, report string) []gitleaksFinding {
	t.Helper()
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("parse report: %v\n%s", err, data)
	}
	return findings
}

func hasFinding(findings []gitleaksFinding, fileSubstr, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && strings.Contains(filepath.ToSlash(f.File), filepath.ToSlash(fileSubstr)) {
			return true
		}
	}
	return false
}

func summarize(findings []gitleaksFinding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.RuleID+"@"+filepath.ToSlash(f.File))
	}
	return out
}

func mustGitleaks(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Fatalf("gitleaks required for scanner lane: %v", err)
	}
	return path
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}
