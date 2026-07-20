// Package provability holds the closed committed-synthetic fixture inventory
// and proofs that those specimens are unusable as real keys.
package provability

import (
	"fmt"
	"sort"
)

// LaneCommitted marks a coverage-matrix "C" cell.
const LaneCommitted = "C"

// Proof identifiers referenced by registry entries and tests.
const (
	ProofRegularFile           = "regular-file"
	ProofNoGeneratedRealMarker = "no-generated-real-marker"
	ProofMinisignPublicShape   = "minisign-public-42-ed"
	ProofMinisignInvalidPoint  = "minisign-ed25519-invalid-point"
	ProofMinisignSecretStruct  = "minisign-secret-not-valid-body"
	ProofMinisignParseMarker   = "minisign-malformed-marker-shape"
	ProofGPGImportEmptyRings   = "gpg-import-empty-rings" // sidecars tag
	ProofSSHKeygenY            = "ssh-keygen-y-reject"    // sidecars
	ProofSSHKeygenL            = "ssh-keygen-l-reject"    // sidecars
	ProofMinisignSignReject    = "minisign-sign-reject"   // sidecars
	ProofMinisignVerifyReject  = "minisign-verify-reject" // sidecars
)

// knownProofs is the closed set of proof IDs that may appear in Fixture.Proofs.
// Implementations must register coverage for every ID used by Registry.
var knownProofs = map[string]struct{}{
	ProofRegularFile:           {},
	ProofNoGeneratedRealMarker: {},
	ProofMinisignPublicShape:   {},
	ProofMinisignInvalidPoint:  {},
	ProofMinisignSecretStruct:  {},
	ProofMinisignParseMarker:   {},
	ProofGPGImportEmptyRings:   {},
	ProofSSHKeygenY:            {},
	ProofSSHKeygenL:            {},
	ProofMinisignSignReject:    {},
	ProofMinisignVerifyReject:  {},
}

// Fixture is one committed-synthetic specimen.
type Fixture struct {
	// Rel is the path under fixtures/ using forward slashes.
	Rel   string
	Kind  string
	Class string
	Lane  string
	// Proofs lists required proof IDs for this file (must all be enforced).
	Proofs []string
	// OptionalProofs are documented consumer expectations not enforced in this
	// slice (e.g. decernor golden-lane checks).
	OptionalProofs []string
}

// Registry is the closed inventory of every non-document regular file under fixtures/.
// Adding or removing a file requires updating this table and the matching proofs.
var Registry = []Fixture{
	{
		Rel: "minisign/public-complete.pub", Kind: "minisign", Class: "public", Lane: LaneCommitted,
		Proofs:         []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofMinisignPublicShape, ProofMinisignInvalidPoint, ProofMinisignVerifyReject},
		OptionalProofs: []string{"decernor-minisign-dual"},
	},
	{
		Rel: "minisign/public-malformed.pub", Kind: "minisign", Class: "public-malformed", Lane: LaneCommitted,
		Proofs:         []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofMinisignParseMarker},
		OptionalProofs: []string{"decernor-parse-unsupported"},
	},
	{
		Rel: "minisign/secret-truncated.key", Kind: "minisign", Class: "private", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofMinisignSecretStruct, ProofMinisignSignReject},
	},
	{
		Rel: "ssh/id_ed25519.pub", Kind: "ssh", Class: "public", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofSSHKeygenL},
	},
	{
		Rel: "ssh/id_ed25519", Kind: "ssh", Class: "private", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofSSHKeygenY},
	},
	{
		Rel: "gpg/public.asc", Kind: "gpg", Class: "public", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofGPGImportEmptyRings},
	},
	{
		Rel: "gpg/private.asc", Kind: "gpg", Class: "private", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofGPGImportEmptyRings},
	},
	{
		Rel: "gpg/revocation.asc", Kind: "gpg", Class: "revocation", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofGPGImportEmptyRings},
	},
	{
		Rel: "malformed/minisign-truncated.key", Kind: "malformed", Class: "edge", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofMinisignSecretStruct, ProofMinisignSignReject},
	},
	{
		Rel: "malformed/ssh-truncated", Kind: "malformed", Class: "edge", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofSSHKeygenY},
	},
	{
		Rel: "malformed/gpg-truncated.asc", Kind: "malformed", Class: "edge", Lane: LaneCommitted,
		Proofs: []string{ProofRegularFile, ProofNoGeneratedRealMarker, ProofGPGImportEmptyRings},
	},
}

// ValidateRegistry checks structural integrity of the inventory.
func ValidateRegistry(reg []Fixture) error {
	seen := map[string]struct{}{}
	for i, f := range reg {
		if f.Rel == "" {
			return fmt.Errorf("registry[%d]: empty path", i)
		}
		if _, ok := seen[f.Rel]; ok {
			return fmt.Errorf("duplicate registry path %q", f.Rel)
		}
		seen[f.Rel] = struct{}{}
		if f.Kind == "" || f.Class == "" {
			return fmt.Errorf("%s: empty kind/class", f.Rel)
		}
		if f.Lane != LaneCommitted {
			return fmt.Errorf("%s: lane must be %q, got %q", f.Rel, LaneCommitted, f.Lane)
		}
		if len(f.Proofs) == 0 {
			return fmt.Errorf("%s: no required proofs", f.Rel)
		}
		for _, p := range f.Proofs {
			if _, ok := knownProofs[p]; !ok {
				return fmt.Errorf("%s: unknown proof %q", f.Rel, p)
			}
		}
	}
	return nil
}

// RegistryPaths returns the set of relative fixture paths (fails closed on duplicates).
func RegistryPaths() (map[string]Fixture, error) {
	if err := ValidateRegistry(Registry); err != nil {
		return nil, err
	}
	out := make(map[string]Fixture, len(Registry))
	for _, f := range Registry {
		out[f.Rel] = f
	}
	return out, nil
}

// FixturesWithProof returns registry entries declaring the given required proof.
func FixturesWithProof(proof string) []Fixture {
	var out []Fixture
	for _, f := range Registry {
		for _, p := range f.Proofs {
			if p == proof {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// AllRequiredProofs returns sorted unique required proof IDs from the registry.
func AllRequiredProofs() []string {
	set := map[string]struct{}{}
	for _, f := range Registry {
		for _, p := range f.Proofs {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
