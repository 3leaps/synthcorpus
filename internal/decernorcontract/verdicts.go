package decernorcontract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	VerdictManifestPath = "manifests/decernor-scan-verdicts.json"
	verdictManifestKind = "synthcorpus-decernor-scan-verdicts"
)

// Profiles every severity map must name, per the manifest semantics.
var verdictProfiles = []string{"artifact", "workstation"}

// VerdictManifest is the expected-verdict manifest (v0). Unknown fields are
// rejected so a shape change cannot pass silently.
type VerdictManifest struct {
	SchemaVersion         string                    `json:"schema_version"`
	Kind                  string                    `json:"kind"`
	MaterialLane          string                    `json:"material_lane"`
	FixturesRoot          string                    `json:"fixtures_root"`
	ExpectationSource     string                    `json:"expectation_source"`
	ExpectationProvenance map[string]string         `json:"expectation_provenance"`
	Placements            map[string]string         `json:"placements"`
	InvariantRules        map[string]string         `json:"invariant_rules"`
	ClassInvariants       map[string][]string       `json:"class_invariants"`
	Fixtures              map[string]VerdictFixture `json:"fixtures"`
}

// VerdictFixture is one specimen's expected verdict.
type VerdictFixture struct {
	Class      string           `json:"class"`
	Placement  string           `json:"placement"`
	Expect     *VerdictFinding  `json:"expect"`
	AlsoExpect []VerdictFinding `json:"also_expect"`
	Guardread  string           `json:"guardread"`
	SHA256     string           `json:"sha256"`
}

// VerdictFinding is an expected finding code and its severity per profile.
type VerdictFinding struct {
	Code     string            `json:"code"`
	Severity map[string]string `json:"severity"`
}

// ScanFinding is the subset of a decernor scan finding this lane judges.
type ScanFinding struct {
	Path           string `json:"path"`
	Code           string `json:"code"`
	Severity       string `json:"severity"`
	Classification string `json:"classification"`
	Exposure       string `json:"exposure"`
}

type scanReport struct {
	Profile  string        `json:"profile"`
	Findings []ScanFinding `json:"findings"`
}

// Observation is what the pinned binary reported for one staged specimen.
type Observation struct {
	Profiles    map[string]string        // report profile, by requested profile
	Findings    map[string][]ScanFinding // by profile
	Refused     bool
	StdoutBytes int
}

// LoadVerdictManifest reads and validates the verdict manifest.
func LoadVerdictManifest(path string) (VerdictManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VerdictManifest{}, err
	}
	var m VerdictManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return VerdictManifest{}, fmt.Errorf("parse verdict manifest: %w", err)
	}
	if err := validateVerdictManifest(m); err != nil {
		return VerdictManifest{}, err
	}
	return m, nil
}

func validateVerdictManifest(m VerdictManifest) error {
	if m.SchemaVersion != "v0" || m.Kind != verdictManifestKind {
		return fmt.Errorf("verdict manifest %q/%q", m.SchemaVersion, m.Kind)
	}
	if !filepath.IsLocal(filepath.FromSlash(m.FixturesRoot)) {
		return fmt.Errorf("fixtures_root %q must stay inside the repository", m.FixturesRoot)
	}
	if len(m.Fixtures) == 0 {
		return errors.New("verdict manifest has no fixtures")
	}
	for rule := range m.InvariantRules {
		if _, ok := ruleChecks[rule]; !ok {
			return fmt.Errorf("manifest declares rule %q this lane does not implement", rule)
		}
	}
	for rule := range ruleChecks {
		if _, ok := m.InvariantRules[rule]; !ok {
			return fmt.Errorf("lane implements rule %q the manifest does not declare", rule)
		}
	}
	for class, rules := range m.ClassInvariants {
		if len(rules) == 0 {
			return fmt.Errorf("class %s has no rules", class)
		}
		seen := map[string]bool{}
		for _, rule := range rules {
			if _, ok := m.InvariantRules[rule]; !ok {
				return fmt.Errorf("class %s names undeclared rule %q", class, rule)
			}
			if seen[rule] {
				return fmt.Errorf("class %s repeats rule %q", class, rule)
			}
			seen[rule] = true
		}
	}
	for rel, f := range m.Fixtures {
		if !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fmt.Errorf("fixture path %q must stay inside the fixtures root", rel)
		}
		if _, ok := m.Placements[f.Placement]; !ok {
			return fmt.Errorf("%s: undeclared placement %q", rel, f.Placement)
		}
		if _, ok := placementDirs[f.Placement]; !ok {
			return fmt.Errorf("%s: placement %q is not implemented by this lane", rel, f.Placement)
		}
		if _, ok := m.ClassInvariants[f.Class]; !ok {
			return fmt.Errorf("%s: class %q has no invariants", rel, f.Class)
		}
		if f.Guardread != "refuse" && f.Guardread != "pass" {
			return fmt.Errorf("%s: guardread %q", rel, f.Guardread)
		}
		for _, e := range expectations(f) {
			if e.Code == "" || len(e.Severity) != len(verdictProfiles) {
				return fmt.Errorf("%s: expectation %q must name a code and exactly %d profiles", rel, e.Code, len(verdictProfiles))
			}
			for _, p := range verdictProfiles {
				if e.Severity[p] == "" {
					return fmt.Errorf("%s: %s has no %s severity", rel, e.Code, p)
				}
			}
		}
	}
	return nil
}

// placementDirs maps each declared placement to the directory, relative to a
// fresh staging root, where the specimen is written.
var placementDirs = map[string]string{
	"agent-key-dir": filepath.Join("home", "private-keys-v1.d"),
	"keyring-home":  "home",
	"root":          "root",
}

func expectations(f VerdictFixture) []VerdictFinding {
	var out []VerdictFinding
	if f.Expect != nil {
		out = append(out, *f.Expect)
	}
	return append(out, f.AlsoExpect...)
}

// ruleChecks implements each declared invariant rule from its manifest text.
var ruleChecks = map[string]func(Observation) error{
	"has-finding": func(o Observation) error {
		for _, p := range verdictProfiles {
			if len(o.Findings[p]) == 0 {
				return fmt.Errorf("no finding under %s", p)
			}
		}
		return nil
	},
	"not-hardware-stub": func(o Observation) error {
		for _, p := range verdictProfiles {
			for _, f := range o.Findings[p] {
				if f.Classification == "hardware-stub" {
					return fmt.Errorf("%s classified as hardware-stub under %s", f.Code, p)
				}
			}
		}
		return nil
	},
	"unsafe-every-profile": func(o Observation) error {
		for _, p := range verdictProfiles {
			unsafe := false
			for _, f := range o.Findings[p] {
				unsafe = unsafe || f.Severity == "unsafe"
			}
			if !unsafe {
				return fmt.Errorf("no unsafe finding under %s", p)
			}
		}
		return nil
	},
	"guardread-refuse": func(o Observation) error {
		if !o.Refused || o.StdoutBytes != 0 {
			return fmt.Errorf("guardread refused=%v stdout=%d bytes", o.Refused, o.StdoutBytes)
		}
		return nil
	},
	"guardread-pass": func(o Observation) error {
		if o.Refused {
			return errors.New("guardread refused")
		}
		return nil
	},
	"no-secret-exposure": func(o Observation) error {
		for _, p := range verdictProfiles {
			for _, f := range o.Findings[p] {
				if f.Exposure == "secret" {
					return fmt.Errorf("%s reports exposure secret under %s", f.Code, p)
				}
			}
		}
		return nil
	},
	"no-finding": func(o Observation) error {
		for _, p := range verdictProfiles {
			if n := len(o.Findings[p]); n != 0 {
				return fmt.Errorf("%d findings under %s", n, p)
			}
		}
		return nil
	},
}

// JudgeVerdict compares one observation with its manifest entry: the exact
// expected findings per profile, the guardread verdict, and every rule the
// fixture's class declares.
func JudgeVerdict(m VerdictManifest, f VerdictFixture, o Observation) []error {
	var errs []error
	want := expectations(f)
	for _, p := range verdictProfiles {
		if o.Profiles != nil && o.Profiles[p] != p {
			errs = append(errs, fmt.Errorf("scan --profile %s reported profile %q", p, o.Profiles[p]))
		}
		got := make([]string, 0, len(o.Findings[p]))
		for _, finding := range o.Findings[p] {
			got = append(got, finding.Code+"/"+finding.Severity)
		}
		exp := make([]string, 0, len(want))
		for _, e := range want {
			exp = append(exp, e.Code+"/"+e.Severity[p])
		}
		sort.Strings(got)
		sort.Strings(exp)
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			errs = append(errs, fmt.Errorf("%s findings = [%s], want [%s]", p, strings.Join(got, ","), strings.Join(exp, ",")))
		}
	}
	switch f.Guardread {
	case "refuse":
		if !o.Refused || o.StdoutBytes != 0 {
			errs = append(errs, fmt.Errorf("guardread: want refusal with empty stdout, got refused=%v stdout=%d bytes", o.Refused, o.StdoutBytes))
		}
	case "pass":
		if o.Refused {
			errs = append(errs, errors.New("guardread: want pass, got refusal"))
		}
	}
	for _, rule := range m.ClassInvariants[f.Class] {
		if err := ruleChecks[rule](o); err != nil {
			errs = append(errs, fmt.Errorf("invariant %s: %w", rule, err))
		}
	}
	return errs
}

// CheckScanVerdicts stages every specimen at its placement, runs the pinned
// binary's scan (both profiles) and guardread, and judges each result.
func CheckScanVerdicts(ctx context.Context, repoRoot, explicitBinary string) error {
	m, err := LoadVerdictManifest(filepath.Join(repoRoot, VerdictManifestPath))
	if err != nil {
		return err
	}
	binary, err := ResolvePinnedBinary(ctx, repoRoot, explicitBinary)
	if err != nil {
		return err
	}
	rels := make([]string, 0, len(m.Fixtures))
	for rel := range m.Fixtures {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var failures []string
	for _, rel := range rels {
		f := m.Fixtures[rel]
		obs, err := observe(ctx, binary, filepath.Join(repoRoot, filepath.FromSlash(m.FixturesRoot), filepath.FromSlash(rel)), f)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		for _, e := range JudgeVerdict(m, f, obs) {
			failures = append(failures, rel+": "+e.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d verdict mismatches:\n%s", len(failures), strings.Join(failures, "\n"))
	}
	return nil
}

func observe(ctx context.Context, binary, src string, f VerdictFixture) (Observation, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return Observation{}, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != f.SHA256 {
		return Observation{}, errors.New("specimen does not match its manifest digest")
	}
	root, err := os.MkdirTemp("", "sc-verdict-")
	if err != nil {
		return Observation{}, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	dir := filepath.Join(root, placementDirs[f.Placement])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Observation{}, err
	}
	staged := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		return Observation{}, err
	}
	obs := Observation{Findings: map[string][]ScanFinding{}, Profiles: map[string]string{}}
	for _, p := range verdictProfiles {
		out, err := exec.CommandContext(ctx, binary, "scan", "--profile", p, "--format", "json", "--fail-on", "none", dir).Output() // #nosec G204 -- pinned, identity-checked binary; fixed argv.
		if err != nil {
			return Observation{}, fmt.Errorf("scan %s: %w", p, err)
		}
		var report scanReport
		if err := json.Unmarshal(out, &report); err != nil {
			return Observation{}, fmt.Errorf("scan %s: decode: %w", p, err)
		}
		obs.Profiles[p] = report.Profile
		for _, finding := range report.Findings {
			if finding.Path == staged {
				obs.Findings[p] = append(obs.Findings[p], finding)
			}
		}
	}
	out, err := exec.CommandContext(ctx, binary, "guardread", staged).Output() // #nosec G204 -- pinned, identity-checked binary; fixed argv.
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 3:
		obs.Refused = true
	default:
		return Observation{}, fmt.Errorf("guardread: %w", err)
	}
	obs.StdoutBytes = len(out)
	return obs, nil
}
