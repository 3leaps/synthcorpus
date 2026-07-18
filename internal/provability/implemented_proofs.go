package provability

import "sort"

// implementedProofs is the independent catalog of proof IDs that have a
// dedicated pure-Go or sidecar test harness. It must not be derived from
// Registry: drift is detected by comparing AllRequiredProofs() against this set.
//
// When adding a new required proof, update BOTH knownProofs/Registry and this map
// and implement the harness that exercises it.
var implementedProofs = map[string]struct{}{
	// inventory / pure structure
	ProofRegularFile:           {}, // TestClosedFixtureInventory
	ProofNoGeneratedRealMarker: {}, // TestNoGeneratedRealMarkersInFixtures
	ProofMinisignPublicShape:   {}, // TestMinisignPublicCompleteInvalidEd25519Point
	ProofMinisignInvalidPoint:  {}, // TestMinisignPublicCompleteInvalidEd25519Point
	ProofMinisignSecretStruct:  {}, // TestMinisignSecretBodiesAreNotValidSecrets
	ProofMinisignParseMarker:   {}, // TestMinisignPublicMalformedMarkerShape
	// sidecars tag
	ProofGPGImportEmptyRings:  {}, // TestSidecarGPGImportLeavesEmptyRings
	ProofSSHKeygenY:           {}, // TestSidecarSSHRejects
	ProofSSHKeygenL:           {}, // TestSidecarSSHRejects
	ProofMinisignSignReject:   {}, // TestSidecarMinisignRejects
	ProofMinisignVerifyReject: {}, // TestSidecarMinisignRejects
}

// CheckProofImplementationCoverage reports required-but-unimplemented and
// stale-implemented IDs (both slices sorted). required is typically
// AllRequiredProofs(); implemented defaults to implementedProofs when nil.
func CheckProofImplementationCoverage(required []string, implemented map[string]struct{}) (missing, stale []string) {
	if implemented == nil {
		implemented = implementedProofs
	}
	reqSet := map[string]struct{}{}
	for _, id := range required {
		reqSet[id] = struct{}{}
		if _, ok := implemented[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range implemented {
		if _, ok := reqSet[id]; !ok {
			stale = append(stale, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}
