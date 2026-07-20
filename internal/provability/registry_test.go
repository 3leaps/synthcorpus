package provability

import (
	"strings"
	"testing"
)

func TestValidateRegistryOK(t *testing.T) {
	if err := ValidateRegistry(Registry); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRegistryRejectsDuplicatePath(t *testing.T) {
	reg := []Fixture{
		{Rel: "a", Kind: "k", Class: "c", Lane: LaneCommitted, Proofs: []string{ProofRegularFile}},
		{Rel: "a", Kind: "k", Class: "c", Lane: LaneCommitted, Proofs: []string{ProofRegularFile}},
	}
	if err := ValidateRegistry(reg); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateRegistryRejectsUnknownProof(t *testing.T) {
	reg := []Fixture{
		{Rel: "a", Kind: "k", Class: "c", Lane: LaneCommitted, Proofs: []string{"not-a-real-proof"}},
	}
	if err := ValidateRegistry(reg); err == nil || !strings.Contains(err.Error(), "unknown proof") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateRegistryRejectsEmptyKind(t *testing.T) {
	reg := []Fixture{
		{Rel: "a", Kind: "", Class: "c", Lane: LaneCommitted, Proofs: []string{ProofRegularFile}},
	}
	if err := ValidateRegistry(reg); err == nil {
		t.Fatal("expected empty kind error")
	}
}

func TestFixturesWithProofCoversDeclaredIDs(t *testing.T) {
	// Every required proof ID used in the registry must have at least one fixture.
	for _, p := range AllRequiredProofs() {
		if len(FixturesWithProof(p)) == 0 {
			t.Errorf("proof %q declared but no fixtures reference it", p)
		}
	}
}

func TestProofImplementationCoverage(t *testing.T) {
	missing, stale := CheckProofImplementationCoverage(AllRequiredProofs(), implementedProofs)
	if len(missing) > 0 {
		t.Errorf("required proofs lack implementation harness: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("implemented proofs not required by registry (stale): %v", stale)
	}
}

func TestCheckProofImplementationCoverageDetectsMissing(t *testing.T) {
	// Independent catalog omits a required ID → must fail.
	impl := map[string]struct{}{}
	for id := range implementedProofs {
		impl[id] = struct{}{}
	}
	delete(impl, ProofMinisignInvalidPoint)
	missing, _ := CheckProofImplementationCoverage(AllRequiredProofs(), impl)
	found := false
	for _, m := range missing {
		if m == ProofMinisignInvalidPoint {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing %s, got %v", ProofMinisignInvalidPoint, missing)
	}
}

func TestCheckProofImplementationCoverageDetectsStale(t *testing.T) {
	impl := map[string]struct{}{}
	for id := range implementedProofs {
		impl[id] = struct{}{}
	}
	impl["stale-proof-id"] = struct{}{}
	_, stale := CheckProofImplementationCoverage(AllRequiredProofs(), impl)
	found := false
	for _, s := range stale {
		if s == "stale-proof-id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected stale-proof-id, got %v", stale)
	}
}
