package decernorcontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerdictManifestLoads(t *testing.T) {
	if _, err := LoadVerdictManifest(filepath.Join(repoRoot(t), VerdictManifestPath)); err != nil {
		t.Fatal(err)
	}
}

func TestVerdictManifestRejectsShapeDrift(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), VerdictManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(name string, edit func(map[string]any)) {
		t.Helper()
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		edit(raw)
		out, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "m.json")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVerdictManifest(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	firstFixture := func(raw map[string]any) map[string]any {
		for _, v := range raw["fixtures"].(map[string]any) {
			return v.(map[string]any)
		}
		return nil
	}
	mutate("unknown top-level field", func(r map[string]any) { r["extra"] = true })
	mutate("unimplemented rule", func(r map[string]any) { r["invariant_rules"].(map[string]any)["new-rule"] = "x" })
	mutate("missing implemented rule", func(r map[string]any) { delete(r["invariant_rules"].(map[string]any), "no-finding") })
	mutate("unknown placement", func(r map[string]any) { firstFixture(r)["placement"] = "elsewhere" })
	mutate("unknown guardread", func(r map[string]any) { firstFixture(r)["guardread"] = "maybe" })
	mutate("non-local fixtures root", func(r map[string]any) { r["fixtures_root"] = "../outside" })
	mutate("profile missing", func(r map[string]any) {
		for _, v := range r["fixtures"].(map[string]any) {
			f := v.(map[string]any)
			if e, ok := f["expect"].(map[string]any); ok {
				delete(e["severity"].(map[string]any), "workstation")
				return
			}
		}
	})
}

// Each rule must reject an observation that breaks its stated meaning.
func TestVerdictRulesRejectViolations(t *testing.T) {
	finding := func(sev, class, exposure string) ScanFinding {
		return ScanFinding{Code: "C", Severity: sev, Classification: class, Exposure: exposure}
	}
	both := func(f ...ScanFinding) map[string][]ScanFinding {
		return map[string][]ScanFinding{"artifact": f, "workstation": f}
	}
	cases := []struct {
		rule     string
		pass     Observation
		violated Observation
	}{
		{"has-finding", Observation{Findings: both(finding("info", "x", "public"))}, Observation{Findings: map[string][]ScanFinding{"artifact": {finding("info", "x", "public")}}}},
		{"not-hardware-stub", Observation{Findings: both(finding("unsafe", "unsafe-secret", "secret"))}, Observation{Findings: both(finding("info", "hardware-stub", "sensitive"))}},
		{"unsafe-every-profile", Observation{Findings: both(finding("unsafe", "x", "secret"))}, Observation{Findings: map[string][]ScanFinding{"artifact": {finding("unsafe", "x", "secret")}, "workstation": {finding("info", "x", "secret")}}}},
		{"guardread-refuse", Observation{Refused: true}, Observation{Refused: true, StdoutBytes: 1}},
		{"guardread-pass", Observation{}, Observation{Refused: true}},
		{"no-secret-exposure", Observation{Findings: both(finding("info", "hardware-stub", "sensitive"))}, Observation{Findings: both(finding("info", "hardware-stub", "secret"))}},
		{"no-finding", Observation{Findings: both()}, Observation{Findings: map[string][]ScanFinding{"workstation": {finding("info", "x", "public")}}}},
	}
	if len(cases) != len(ruleChecks) {
		t.Fatalf("controls cover %d rules, lane implements %d", len(cases), len(ruleChecks))
	}
	for _, c := range cases {
		if err := ruleChecks[c.rule](c.pass); err != nil {
			t.Errorf("%s rejected a conforming observation: %v", c.rule, err)
		}
		if err := ruleChecks[c.rule](c.violated); err == nil {
			t.Errorf("%s accepted a violation", c.rule)
		}
	}
}

func TestJudgeVerdictRequiresExactFindings(t *testing.T) {
	m := VerdictManifest{ClassInvariants: map[string][]string{"c": {}}}
	f := VerdictFixture{
		Class:     "c",
		Expect:    &VerdictFinding{Code: "A", Severity: map[string]string{"artifact": "unsafe", "workstation": "info"}},
		Guardread: "refuse",
	}
	ok := Observation{Refused: true, Findings: map[string][]ScanFinding{
		"artifact":    {{Code: "A", Severity: "unsafe"}},
		"workstation": {{Code: "A", Severity: "info"}},
	}}
	if errs := JudgeVerdict(m, f, ok); len(errs) != 0 {
		t.Fatalf("conforming observation rejected: %v", errs)
	}
	extra := Observation{Refused: true, Findings: map[string][]ScanFinding{
		"artifact":    {{Code: "A", Severity: "unsafe"}, {Code: "B", Severity: "info"}},
		"workstation": {{Code: "A", Severity: "info"}},
	}}
	wrongSeverity := Observation{Refused: true, Findings: map[string][]ScanFinding{
		"artifact":    {{Code: "A", Severity: "unsafe"}},
		"workstation": {{Code: "A", Severity: "unsafe"}},
	}}
	passed := Observation{Findings: ok.Findings}
	for name, o := range map[string]Observation{"extra finding": extra, "wrong severity": wrongSeverity, "guardread pass": passed} {
		if errs := JudgeVerdict(m, f, o); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	none := VerdictFixture{Class: "c", Guardread: "pass"}
	if errs := JudgeVerdict(m, none, Observation{Findings: map[string][]ScanFinding{"artifact": {{Code: "A", Severity: "info"}}}}); len(errs) == 0 {
		t.Error("finding accepted where the manifest expects none")
	}
	for _, e := range JudgeVerdict(m, f, extra) {
		if !strings.Contains(e.Error(), "artifact") {
			t.Errorf("mismatch does not name its profile: %v", e)
		}
	}
}

func TestJudgeVerdictRequiresReportedProfile(t *testing.T) {
	m := VerdictManifest{ClassInvariants: map[string][]string{"c": {}}}
	f := VerdictFixture{Class: "c", Guardread: "pass"}
	ok := Observation{Profiles: map[string]string{"artifact": "artifact", "workstation": "workstation"}}
	if errs := JudgeVerdict(m, f, ok); len(errs) != 0 {
		t.Fatalf("conforming observation rejected: %v", errs)
	}
	missing := Observation{Profiles: map[string]string{"artifact": "", "workstation": "workstation"}}
	if errs := JudgeVerdict(m, f, missing); len(errs) == 0 {
		t.Error("missing report profile accepted")
	}
}
