package lexmatrix

import (
	"strings"
	"testing"
)

func generateForTest(t *testing.T) *Result {
	t.Helper()
	res, err := Generate(Options{Seed: 7312026})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return res
}

func TestGenerateIsDeterministic(t *testing.T) {
	first := generateForTest(t)
	second := generateForTest(t)

	firstDigest, err := FixtureDigest(first)
	if err != nil {
		t.Fatalf("digest first run: %v", err)
	}
	secondDigest, err := FixtureDigest(second)
	if err != nil {
		t.Fatalf("digest second run: %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("same seed produced different fixture digests: %s vs %s", firstDigest, secondDigest)
	}
	if first.Fixtures.SourceManifestSHA256 != second.Fixtures.SourceManifestSHA256 {
		t.Fatalf("same seed produced different manifest digests")
	}
	if len(first.Artifacts) != len(second.Artifacts) {
		t.Fatalf("same seed produced %d and %d artifacts", len(first.Artifacts), len(second.Artifacts))
	}
	for id, text := range first.Artifacts {
		if second.Artifacts[id] != text {
			t.Fatalf("artifact %s differs between runs", id)
		}
	}
}

func TestDifferentSeedsDiverge(t *testing.T) {
	a, err := Generate(Options{Seed: 1})
	if err != nil {
		t.Fatalf("Generate(1): %v", err)
	}
	b, err := Generate(Options{Seed: 2})
	if err != nil {
		t.Fatalf("Generate(2): %v", err)
	}
	aDigest, _ := FixtureDigest(a)
	bDigest, _ := FixtureDigest(b)
	if aDigest == bDigest {
		t.Fatal("different seeds produced an identical fixture set")
	}
}

// TestSpansLocateVariants is the answer key's own integrity check: every
// declared span must actually cover an anchored variant inside its source
// artifact, and never spill into the surrounding text.
func TestSpansLocateVariants(t *testing.T) {
	res := generateForTest(t)

	for _, c := range res.Fixtures.Cases {
		artifact, ok := res.Artifacts[c.SourceID]
		if !ok {
			t.Fatalf("case %s references undeclared source %s", c.CaseID, c.SourceID)
		}
		for i, s := range c.Expected.Spans {
			if s.Unit != "utf8_byte" {
				t.Fatalf("case %s span %d has unit %q", c.CaseID, i, s.Unit)
			}
			if s.Start < 0 || s.Length < 1 || s.Start+s.Length > len(artifact) {
				t.Fatalf("case %s span %d [%d,%d) is outside artifact of %d bytes",
					c.CaseID, i, s.Start, s.Start+s.Length, len(artifact))
			}
			slice := artifact[s.Start : s.Start+s.Length]
			if !strings.HasPrefix(slice, Anchor) {
				t.Fatalf("case %s span %d covers %q, which does not start with the anchor", c.CaseID, i, slice)
			}
			if strings.ContainsAny(slice, "\n\"<>=;") {
				t.Fatalf("case %s span %d covers %q, which spills into surrounding text", c.CaseID, i, slice)
			}
		}
	}
}

// TestNoVariantMatchesUnmutatedTerm is the corpus-level counterpart to
// TestAnchorSurvivesEveryTransform: it compares the bytes the answer key points
// at against the term's plain rendering on that surface. A transform can change
// the token slice and still render identically, so only this comparison catches
// a positive case that contains no mutation at all.
func TestNoVariantMatchesUnmutatedTerm(t *testing.T) {
	for _, seed := range []uint32{7312026, 1, 2, 128, 1123, 1848} {
		res, err := Generate(Options{Seed: seed, IncludeExtensions: true})
		if err != nil {
			t.Fatalf("seed %d: Generate: %v", seed, err)
		}

		terms := map[string][]string{}
		for _, term := range res.Manifest.Terms {
			terms[term.TermID] = term.Tokens
		}

		for _, c := range res.Fixtures.Cases {
			if c.Expected.Disposition != "finding" {
				continue
			}
			artifact := res.Artifacts[c.SourceID]
			for _, s := range c.Expected.Spans {
				variant := artifact[s.Start : s.Start+s.Length]
				plain := joinTokens(Surface(c.Surface), terms[c.TermID], nil)
				if variant == plain {
					t.Fatalf("seed %d case %s (%s x %s): answer key claims a mutation but the artifact holds the plain term %q",
						seed, c.CaseID, c.Surface, c.Mutation.Class, variant)
				}
			}
		}
	}
}

// TestGenerateAcceptsArbitrarySeeds guards the CLI's promise that any 32-bit
// seed produces a corpus. A transform that cannot find a scalar to act on used
// to abort the whole run for roughly one seed in 170.
func TestGenerateAcceptsArbitrarySeeds(t *testing.T) {
	for seed := uint32(0); seed < 200; seed++ {
		if _, err := Generate(Options{Seed: seed, IncludeExtensions: true}); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
	}
}

func TestNegativeCasesDeclareNoSpans(t *testing.T) {
	res := generateForTest(t)

	for _, c := range res.Fixtures.Cases {
		switch c.Expected.Disposition {
		case "allowed", "unsupported":
			if len(c.Expected.Spans) != 0 || c.Expected.MinFindings != 0 || c.Expected.MaxFindings != 0 {
				t.Fatalf("case %s is %s but declares findings", c.CaseID, c.Expected.Disposition)
			}
		case "finding":
			if len(c.Expected.Spans) == 0 || c.Expected.MinFindings < 1 {
				t.Fatalf("case %s is a finding with no span", c.CaseID)
			}
		}
		if c.Expected.Disposition == "unsupported" && c.Expected.UnsupportedReasonCode == "" {
			t.Fatalf("case %s is unsupported without a reason code", c.CaseID)
		}
	}
}

func TestCaseIdentifiersAreUnique(t *testing.T) {
	res := generateForTest(t)

	seen := map[string]bool{}
	for _, c := range res.Fixtures.Cases {
		if seen[c.CaseID] {
			t.Fatalf("duplicate case id %s", c.CaseID)
		}
		seen[c.CaseID] = true
	}
}

func TestEveryReferenceResolves(t *testing.T) {
	res := generateForTest(t)

	terms := map[string]bool{}
	for _, term := range res.Manifest.Terms {
		terms[term.TermID] = true
	}
	sources := map[string]bool{}
	for _, source := range res.Manifest.Sources {
		sources[source.SourceID] = true
	}

	for _, c := range res.Fixtures.Cases {
		if !terms[c.TermID] {
			t.Fatalf("case %s references undeclared term %s", c.CaseID, c.TermID)
		}
		if !sources[c.SourceID] {
			t.Fatalf("case %s references undeclared source %s", c.CaseID, c.SourceID)
		}
	}
}

// TestAnchorSurvivesEveryTransform holds the grammar's central promise: a
// mutated form is still greppable as synthetic.
func TestAnchorSurvivesEveryTransform(t *testing.T) {
	classes := []Class{
		ClassIdentity, ClassCase, ClassSeparator, ClassPlural, ClassInsertion,
		ClassDeletion, ClassSubstitution, ClassTransposition, ClassTokenSplit,
		ClassTokenJoin, ClassTruncation, ClassVowelDrop, ClassUnicodeConfusable,
		ClassUnicodeNormalization,
	}
	d := newDeriver(99)

	for _, class := range classes {
		spec := specsForClass(class)[4] // the longest shape, so every transform applies
		term, err := newTerm(d, class, spec, "anchor-test|"+string(class))
		if err != nil {
			t.Fatalf("%s: newTerm: %v", class, err)
		}
		tokens, m, err := applyTransform(d, class, term, SurfaceSnakeCase, "anchor-test|"+string(class))
		if err != nil {
			t.Fatalf("%s: applyTransform: %v", class, err)
		}
		if err := requireAnchor(tokens, string(class)); err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		if m.EditDistance > 4 {
			t.Fatalf("%s: edit distance %d exceeds the contract cap", class, m.EditDistance)
		}
		if class == ClassIdentity {
			continue
		}
		changed := strings.Join(tokens, "\x00") != strings.Join(term.Tokens, "\x00")
		if !changed && m.JoinerOverride == nil {
			t.Fatalf("%s: transform produced no observable change", class)
		}
	}
}

func TestRequiredMatrixShape(t *testing.T) {
	cells := RequiredCells()
	if len(cells) != 49 {
		t.Fatalf("required matrix has %d cells, want 49", len(cells))
	}

	seen := map[Cell]bool{}
	for _, cell := range cells {
		if seen[cell] {
			t.Fatalf("duplicate cell %v", cell)
		}
		seen[cell] = true
	}

	for cell, want := range elevatedCells {
		if !seen[cell] {
			t.Fatalf("elevated cell %v is not part of the required matrix", cell)
		}
		if got := severityFor(cell); got != want {
			t.Fatalf("cell %v severity %s, want %s", cell, got, want)
		}
	}
}

func TestAccountingMeetsFloors(t *testing.T) {
	res := generateForTest(t)

	if err := res.Accounting.CheckFloors(); err != nil {
		t.Fatalf("floors: %v", err)
	}
	if res.Accounting.RequiredCells != len(RequiredCells()) {
		t.Fatalf("accounted %d required cells, matrix declares %d",
			res.Accounting.RequiredCells, len(RequiredCells()))
	}
	if res.Accounting.CriticalSeeds == 0 {
		t.Fatal("no critical seeds were generated")
	}
	for _, cell := range res.Accounting.Cells {
		if cell.Clusters < FloorClustersPerCell {
			t.Fatalf("cell %s x %s has no duplicate cluster", cell.Surface, cell.Class)
		}
	}
}

func TestCriticalSeedsAreDeterministicFindings(t *testing.T) {
	res := generateForTest(t)

	count := 0
	for _, c := range res.Fixtures.Cases {
		if !c.CriticalSeed {
			continue
		}
		count++
		if c.Lane != string(LaneDeterministic) {
			t.Fatalf("critical seed %s sits in lane %s", c.CaseID, c.Lane)
		}
		if c.Expected.Disposition != "finding" {
			t.Fatalf("critical seed %s has disposition %s", c.CaseID, c.Expected.Disposition)
		}
		if c.Severity != string(SeverityCritical) {
			t.Fatalf("critical seed %s carries severity %s", c.CaseID, c.Severity)
		}
	}
	if count == 0 {
		t.Fatal("no critical seeds present")
	}
}

func TestShortCasesAreBelowPolicyLength(t *testing.T) {
	res := generateForTest(t)

	perSurface := map[string]int{}
	for _, c := range res.Fixtures.Cases {
		if c.NegativeControlClass != "short_term" {
			continue
		}
		perSurface[c.Surface]++
		if c.TermLength.ScalarBand != "1_3" {
			t.Fatalf("case %s is a short-term control in band %s", c.CaseID, c.TermLength.ScalarBand)
		}
		if c.TermLength.NormalizedScalarCount > 3 {
			t.Fatalf("case %s is a short-term control of %d scalars", c.CaseID, c.TermLength.NormalizedScalarCount)
		}
		if c.Expected.UnsupportedReasonCode != "term_length_below_policy" {
			t.Fatalf("case %s has reason code %q", c.CaseID, c.Expected.UnsupportedReasonCode)
		}
	}
	for _, surface := range surfaceOrder {
		if perSurface[string(surface)] < FloorShortCasesPerSurface {
			t.Fatalf("surface %s has %d short cases, floor is %d",
				surface, perSurface[string(surface)], FloorShortCasesPerSurface)
		}
	}
}

func TestDispositionActionTableRejectsDisagreement(t *testing.T) {
	if err := checkDispositionAction("lexcase-000001", "finding", "dismiss"); err == nil {
		t.Fatal("a finding paired with dismiss was accepted")
	}
	if err := checkDispositionAction("lexcase-000001", "allowed", "confirm"); err == nil {
		t.Fatal("an allowed case paired with confirm was accepted")
	}
	if err := checkDispositionAction("lexcase-000001", "unsupported", "unsupported"); err != nil {
		t.Fatalf("valid pairing rejected: %v", err)
	}
}

func TestCollisionCheckCatchesCommonWords(t *testing.T) {
	if err := checkCollisions([]collisionCandidate{{value: "zzlxconfigab", label: "probe", term: true}}); err == nil {
		t.Fatal("a term containing a common word passed the collision check")
	}
	if err := checkCollisions([]collisionCandidate{{value: "zzlxq7fm2k", label: "probe", term: true}}); err != nil {
		t.Fatalf("a clean term was rejected: %v", err)
	}
	// A variant, not just a term, must be screened: transforms can synthesise
	// a word no base term contains.
	if err := checkCollisions([]collisionCandidate{{value: "zzlxsessionq", label: "variant"}}); err == nil {
		t.Fatal("a variant containing a common word passed the collision check")
	}
}

func TestCollisionCheckCatchesDuplicateTerms(t *testing.T) {
	dup := []collisionCandidate{
		{value: "zzlxq7fm2k", label: "lexterm-00001", term: true},
		{value: "zzlxq7fm2k", label: "lexterm-00002", term: true},
	}
	if err := checkCollisions(dup); err == nil {
		t.Fatal("two terms resolving to the same value passed the collision check")
	}

	// Two variants sharing a value is ordinary — only searched terms must be
	// unique.
	variants := []collisionCandidate{
		{value: "zzlxq7fm2k", label: "a"},
		{value: "zzlxq7fm2k", label: "b"},
	}
	if err := checkCollisions(variants); err != nil {
		t.Fatalf("duplicate variants were rejected: %v", err)
	}
}

func TestGeneratedTermsCarryTheAnchor(t *testing.T) {
	res := generateForTest(t)

	anchored := 0
	for _, term := range res.Manifest.Terms {
		if strings.HasPrefix(term.Value, Anchor) {
			anchored++
			continue
		}
		// Two deliberate exceptions: common-word decoys, where an ordinary
		// word is the whole control, and below-policy-length terms, which are
		// too short to hold a full anchor and lead with a prefix of one.
		if isCommonWordDecoy(term.Value) || isBelowPolicyShape(term.Value) {
			continue
		}
		t.Fatalf("term %s (%q) carries neither the anchor nor a documented exception shape", term.TermID, term.Value)
	}
	if anchored == 0 {
		t.Fatal("no anchored terms were generated")
	}
}

// isBelowPolicyShape reports whether a value is a below-policy-length term:
// at most three scalars, leading with a prefix of the anchor.
func isBelowPolicyShape(value string) bool {
	runes := []rune(value)
	if len(runes) == 0 || len(runes) > 3 {
		return false
	}
	return strings.HasPrefix(Anchor, string(runes[:len(runes)-1]))
}

func isCommonWordDecoy(value string) bool {
	for _, word := range commonWords {
		if strings.HasPrefix(value, word) {
			return true
		}
	}
	return false
}

func TestFixtureSetHeaderIsContractShaped(t *testing.T) {
	res := generateForTest(t)
	fs := res.Fixtures

	if fs.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version %q", fs.SchemaVersion)
	}
	if fs.VocabularyNamespace != Namespace {
		t.Fatalf("namespace %q", fs.VocabularyNamespace)
	}
	if fs.LexicalCandidateCount < len(fs.Cases) {
		t.Fatalf("candidate count %d is below the case count %d", fs.LexicalCandidateCount, len(fs.Cases))
	}
	if len(fs.SourceManifestSHA256) != 64 {
		t.Fatalf("manifest digest %q is not a sha256", fs.SourceManifestSHA256)
	}
	if fs.Generator.Name != GeneratorName || fs.Generator.Version != GeneratorVersion {
		t.Fatalf("generator identity %+v", fs.Generator)
	}
}

func TestExtensionCellsAreScopedOut(t *testing.T) {
	res, err := Generate(Options{Seed: 7312026, IncludeExtensions: true})
	if err != nil {
		t.Fatalf("Generate with extensions: %v", err)
	}

	extensions := 0
	for _, c := range res.Fixtures.Cases {
		if c.Scope == string(ScopeExtension) {
			extensions++
		}
	}
	if extensions == 0 {
		t.Fatal("no extension-scoped cases were generated")
	}

	base := generateForTest(t)
	for _, c := range base.Fixtures.Cases {
		if c.Scope != string(ScopeRequired) {
			t.Fatalf("case %s is scoped %s in a required-only run", c.CaseID, c.Scope)
		}
	}
}
