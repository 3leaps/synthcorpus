package lexmatrix

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// Options controls a generation run.
type Options struct {
	// Seed fixes every derived choice. The same seed and the same generator
	// version always produce byte-identical output.
	Seed uint32
	// Profile is the corpus profile recorded in the fixture set.
	Profile string
	// IncludeExtensions adds the implemented-but-not-required cells, marked
	// as extension scope.
	IncludeExtensions bool
}

// Result is everything one generation run produced.
type Result struct {
	Fixtures   FixtureSet
	Manifest   Manifest
	Artifacts  map[string]string
	Accounting Accounting
}

// builder accumulates a corpus while keeping identifier sequences monotonic.
type builder struct {
	deriver deriver
	opts    Options

	cases     []Case
	terms     []ManifestTerm
	sources   []ManifestSource
	artifacts map[string]string

	caseSeq    int
	termSeq    int
	sourceSeq  int
	clusterSeq int

	// searchable holds every value a detector will be asked to look for, plus
	// every rendered variant planted in an artifact, for the collision check.
	searchable []collisionCandidate
	// usedTermValues is the set of searched term values already issued, so a
	// re-derivation can avoid them.
	usedTermValues map[string]bool
	// decoyIDs maps a decoy value to the single identifier it was issued, so
	// one string never appears in the manifest under several term IDs.
	decoyIDs map[string]string
}

// Generate builds a complete corpus in memory.
func Generate(opts Options) (*Result, error) {
	if opts.Profile == "" {
		opts.Profile = "seed"
	}

	b := &builder{
		deriver:        newDeriver(opts.Seed),
		opts:           opts,
		artifacts:      make(map[string]string),
		usedTermValues: make(map[string]bool),
		decoyIDs:       make(map[string]string),
	}

	cells := RequiredCells()
	if opts.IncludeExtensions {
		cells = append(cells, ExtensionCells()...)
	}

	for _, cell := range cells {
		scope := ScopeRequired
		if isExtensionCell(cell) {
			scope = ScopeExtension
		}
		if err := b.buildCell(cell, scope); err != nil {
			return nil, err
		}
	}

	for _, surface := range surfaceOrder {
		if err := b.buildNegativeControls(surface); err != nil {
			return nil, err
		}
		if err := b.buildShortCases(surface); err != nil {
			return nil, err
		}
	}

	if err := checkCollisions(b.searchable); err != nil {
		return nil, err
	}

	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Namespace:     Namespace,
		Generator:     b.generator(),
		Terms:         b.terms,
		Sources:       b.sources,
	}

	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return nil, err
	}

	fixtures := FixtureSet{
		SchemaVersion:         SchemaVersion,
		FixtureSetID:          fixtureSetID(opts),
		VocabularyNamespace:   Namespace,
		Generator:             b.generator(),
		SourceManifestSHA256:  manifestDigest,
		Profile:               opts.Profile,
		LexicalCandidateCount: b.candidateCount(),
		Cases:                 b.cases,
	}

	accounting := buildAccounting(fixtures)
	if err := accounting.CheckFloors(); err != nil {
		return nil, err
	}

	return &Result{
		Fixtures:   fixtures,
		Manifest:   manifest,
		Artifacts:  b.artifacts,
		Accounting: accounting,
	}, nil
}

// fixtureSetID names a corpus. It must vary with everything that changes the
// corpus, not just the seed: a required-only run and an extension run share a
// seed but are different collections, and a consumer keying a cache on this
// identifier would otherwise conflate them.
func fixtureSetID(opts Options) string {
	id := fmt.Sprintf("lexset-matrix-v1-%s-%d", opts.Profile, opts.Seed)
	if opts.IncludeExtensions {
		id += "-ext"
	}
	return id
}

func (b *builder) generator() Generator {
	return Generator{Name: GeneratorName, Version: GeneratorVersion, Seed: b.opts.Seed}
}

// buildCell populates one (surface x class) coordinate: a duplicate cluster
// followed by independent occurrences.
func (b *builder) buildCell(cell Cell, scope Scope) error {
	specs := specsForClass(cell.Class)
	terms := make([]Term, 0, len(specs))
	termIDs := make([]string, 0, len(specs))

	for i, spec := range specs {
		label := fmt.Sprintf("%s|%s|term%d", cell.Surface, cell.Class, i)
		term, termID, err := b.newProtectedTerm(cell.Class, spec, label)
		if err != nil {
			return err
		}
		terms = append(terms, term)
		termIDs = append(termIDs, termID)
	}

	severity := severityFor(cell)
	lane := laneFor(cell.Class)
	criticalCell := lane == LaneDeterministic && mixHasCritical(cell.Surface)

	// The cluster: one term, one artifact, clusterSize identical occurrences.
	clusterID := b.nextClusterID()
	clusterLabel := fmt.Sprintf("%s|%s|cluster", cell.Surface, cell.Class)
	clusterTokens, clusterMutation, err := applyTransform(b.deriver, cell.Class, terms[0], cell.Surface, clusterLabel)
	if err != nil {
		return err
	}
	if err := requireAnchor(clusterTokens, clusterLabel); err != nil {
		return err
	}
	clusterVariant := joinTokens(cell.Surface, clusterTokens, clusterMutation.JoinerOverride)
	if err := requireObservable(cell, terms[0], clusterVariant, clusterLabel); err != nil {
		return err
	}
	b.noteVariant(clusterVariant, clusterLabel)

	fragments := make([]fragment, 0, clusterSize)
	for i := 0; i < clusterSize; i++ {
		fragments = append(fragments, newFragment(cell.Surface, clusterVariant))
	}
	sourceID, spans := b.addSource(cell.Surface, artifactHeader(cell.Surface), fragments)

	for i := 0; i < clusterSize; i++ {
		criticalSeed := criticalCell && i < 4
		caseSeverity := severity
		if criticalSeed {
			caseSeverity = SeverityCritical
		}
		c := Case{
			SourceID:     sourceID,
			TermID:       termIDs[0],
			TermClass:    termClassFor(cell.Surface, terms[0].TokenCount()),
			Lane:         string(lane),
			Surface:      string(cell.Surface),
			Mutation:     mutationRecord(clusterMutation),
			Expected:     findingExpectation(spans[i]),
			Severity:     string(caseSeverity),
			TermLength:   termLength(terms[0]),
			CriticalSeed: criticalSeed,
			Scope:        string(scope),
			Review:       Review{ExpectedAction: "confirm", ClusterID: strPtr(clusterID)},
			Tags:         []string{"cluster"},
		}
		if err := b.addCase(c); err != nil {
			return err
		}
	}

	// Independent occurrences fill the cell to its floor.
	for i := clusterSize; i < FloorPositivesPerCell; i++ {
		term := terms[(i-clusterSize)%len(terms)]
		termID := termIDs[(i-clusterSize)%len(termIDs)]
		label := fmt.Sprintf("%s|%s|case%d", cell.Surface, cell.Class, i)

		tokens, m, err := applyTransform(b.deriver, cell.Class, term, cell.Surface, label)
		if err != nil {
			return err
		}
		if err := requireAnchor(tokens, label); err != nil {
			return err
		}
		variant := joinTokens(cell.Surface, tokens, m.JoinerOverride)
		if err := requireObservable(cell, term, variant, label); err != nil {
			return err
		}
		b.noteVariant(variant, label)

		sourceID, spans := b.addSource(cell.Surface, artifactHeader(cell.Surface), []fragment{newFragment(cell.Surface, variant)})

		criticalSeed := criticalCell && i < 4
		caseSeverity := severity
		if criticalSeed {
			caseSeverity = SeverityCritical
		}
		c := Case{
			SourceID:     sourceID,
			TermID:       termID,
			TermClass:    termClassFor(cell.Surface, term.TokenCount()),
			Lane:         string(lane),
			Surface:      string(cell.Surface),
			Mutation:     mutationRecord(m),
			Expected:     findingExpectation(spans[0]),
			Severity:     string(caseSeverity),
			TermLength:   termLength(term),
			CriticalSeed: criticalSeed,
			Scope:        string(scope),
			Review:       Review{ExpectedAction: "confirm", ClusterID: nil},
		}
		if err := b.addCase(c); err != nil {
			return err
		}
	}
	return nil
}

// negativeSpec describes one negative control.
type negativeSpec struct {
	class       string
	transformID string
	disposition string
	action      string
}

// negativeSpecs are the non-length negative controls emitted for every
// surface, in fixed order.
var negativeSpecs = []negativeSpec{
	{"common_word", "negative.common_word", "allowed", "dismiss"},
	{"shared_prefix", "negative.shared_prefix", "review_only", "manual_review"},
	{"shared_token", "negative.shared_token", "review_only", "manual_review"},
	{"substring", "negative.substring", "allowed", "dismiss"},
	{"high_entropy_identifier", "negative.high_entropy", "allowed", "dismiss"},
	{"generated_code", "negative.generated_code", "allowed", "allowlist"},
	{"dependency_metadata", "negative.dependency_metadata", "allowed", "allowlist"},
}

func (b *builder) buildNegativeControls(surface Surface) error {
	baseLabel := fmt.Sprintf("%s|negative", surface)
	base, err := newTerm(b.deriver, ClassIdentity, termSpec{tokens: 3, bodyLen: 10}, baseLabel+"|base")
	if err != nil {
		return err
	}

	for i, spec := range negativeSpecs {
		label := fmt.Sprintf("%s|%s", baseLabel, spec.class)
		term, header, err := b.negativeTerm(spec.class, base, surface, label)
		if err != nil {
			return err
		}
		termID := b.addTerm(term, TermDecoy)

		variant := joinTokens(surface, term.Tokens, nil)
		sourceID, _ := b.addSource(surface, header, []fragment{newFragment(surface, variant)})

		c := Case{
			SourceID:  sourceID,
			TermID:    termID,
			TermClass: termClassFor(surface, term.TokenCount()),
			Lane:      string(LaneNegativeContro),
			Surface:   string(surface),
			Mutation: MutationRecord{
				Class:             string(ClassIdentity),
				TransformID:       spec.transformID,
				EditDistance:      intPtr(0),
				NormalizationForm: "NFC",
			},
			Expected: Expected{
				Disposition: spec.disposition,
				MinFindings: 0,
				MaxFindings: 0,
				Spans:       []SpanRecord{},
			},
			Severity:             string(SeverityLow),
			TermLength:           termLength(term),
			CriticalSeed:         false,
			Scope:                string(ScopeRequired),
			NegativeControlClass: spec.class,
			Review:               Review{ExpectedAction: spec.action, ClusterID: nil},
			Tags:                 []string{"negative-control"},
		}
		if err := b.addCase(c); err != nil {
			return fmt.Errorf("negative control %d on %s: %w", i, surface, err)
		}
	}
	return nil
}

// negativeTerm builds the decoy for one negative-control class, along with the
// artifact header that class needs.
func (b *builder) negativeTerm(class string, base Term, surface Surface, label string) (Term, string, error) {
	header := artifactHeader(surface)

	switch class {
	case "common_word":
		// The only decoy without an anchor: an ordinary word is the point.
		first := commonWords[b.deriver.intn(len(commonWords), label, "word1")]
		second := commonWords[(b.deriver.intn(len(commonWords), label, "word2")+1)%len(commonWords)]
		return Term{Tokens: []string{first, second}}, header, nil

	case "shared_prefix":
		baseBody := strings.TrimPrefix(base.Tokens[0], Anchor)
		shared := baseBody
		if len([]rune(shared)) > 2 {
			shared = string([]rune(shared)[:2])
		}
		tail := b.deriver.body(6, label, "tail")
		return Term{Tokens: []string{Anchor + shared + tail}}, header, nil

	case "shared_token":
		tail := b.deriver.body(5, label, "tail")
		return Term{Tokens: []string{base.Tokens[0], tail}}, header, nil

	case "substring":
		runes := []rune(base.Tokens[0])
		cut := len([]rune(Anchor)) + 1
		if len(runes) > cut+1 {
			runes = runes[:len(runes)-1]
		}
		return Term{Tokens: []string{string(runes)}}, header, nil

	case "high_entropy_identifier":
		body := b.deriver.body(24, label, "entropy")
		return Term{Tokens: []string{Anchor + body}}, header, nil

	case "generated_code":
		body := b.deriver.body(8, label, "gen")
		return Term{Tokens: []string{Anchor + body, b.deriver.body(4, label, "gen2")}},
			"// Code generated by a build tool. DO NOT EDIT.\n" + header, nil

	case "dependency_metadata":
		body := b.deriver.body(8, label, "dep")
		return Term{Tokens: []string{Anchor + body, b.deriver.body(4, label, "dep2")}},
			"# lockfile entry — resolved dependency\n" + header, nil

	default:
		return Term{}, "", fmt.Errorf("unknown negative control class %q", class)
	}
}

// buildShortCases emits the explicit below-policy-length cases for a surface.
func (b *builder) buildShortCases(surface Surface) error {
	for i := 0; i < shortCasesPerSurface; i++ {
		length := (i % 3) + 1
		term, err := shortTerm(b.deriver, length, fmt.Sprintf("%s|short%d", surface, i))
		if err != nil {
			return err
		}
		termID := b.decoyTermID(term)

		variant := joinTokens(surface, term.Tokens, nil)
		sourceID, _ := b.addSource(surface, artifactHeader(surface), []fragment{newFragment(surface, variant)})

		c := Case{
			SourceID:  sourceID,
			TermID:    termID,
			TermClass: termClassFor(surface, term.TokenCount()),
			Lane:      string(LaneNegativeContro),
			Surface:   string(surface),
			Mutation: MutationRecord{
				Class:             string(ClassIdentity),
				TransformID:       "negative.short_term",
				EditDistance:      intPtr(0),
				NormalizationForm: "NFC",
			},
			Expected: Expected{
				Disposition:           "unsupported",
				MinFindings:           0,
				MaxFindings:           0,
				Spans:                 []SpanRecord{},
				UnsupportedReasonCode: "term_length_below_policy",
			},
			Severity:             string(SeverityLow),
			TermLength:           termLength(term),
			CriticalSeed:         false,
			Scope:                string(ScopeRequired),
			NegativeControlClass: "short_term",
			Review:               Review{ExpectedAction: "unsupported", ClusterID: nil},
			Tags:                 []string{"negative-control", "short-term"},
		}
		if err := b.addCase(c); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) addCase(c Case) error {
	b.caseSeq++
	c.CaseID = fmt.Sprintf("lexcase-%06d", b.caseSeq)
	if err := checkDispositionAction(c.CaseID, c.Expected.Disposition, c.Review.ExpectedAction); err != nil {
		return err
	}
	if c.Expected.MinFindings > c.Expected.MaxFindings {
		return fmt.Errorf("case %s: min_findings exceeds max_findings", c.CaseID)
	}
	if c.CriticalSeed && (c.Lane != string(LaneDeterministic) || c.Expected.Disposition != "finding") {
		return fmt.Errorf("case %s: critical seed must be a deterministic-lane finding", c.CaseID)
	}
	b.cases = append(b.cases, c)
	return nil
}

// newProtectedTerm derives a searched term whose value no earlier term already
// took. Bodies are short enough that the birthday bound bites: at 294 terms per
// run, two cells landing on the same value is routine rather than exotic, and
// two term IDs for one value would make the answer key ambiguous. Re-derivation
// walks a deterministic salt sequence, so the corpus stays reproducible.
func (b *builder) newProtectedTerm(class Class, spec termSpec, label string) (Term, string, error) {
	const maxAttempts = 32

	for attempt := 0; attempt < maxAttempts; attempt++ {
		attemptLabel := label
		if attempt > 0 {
			attemptLabel = fmt.Sprintf("%s|alt%d", label, attempt)
		}

		term, err := newTerm(b.deriver, class, spec, attemptLabel)
		if err != nil {
			return Term{}, "", err
		}
		value := term.Normalized()
		if b.usedTermValues[value] {
			continue
		}
		b.usedTermValues[value] = true
		return term, b.addTerm(term, TermProtected), nil
	}
	return Term{}, "", fmt.Errorf("%s: no distinct term value after %d derivations", label, maxAttempts)
}

// decoyTermID issues one identifier per distinct decoy value. The same string
// planted on several surfaces is the same term, and registering it repeatedly
// would inflate the manifest while implying coverage the corpus lacks.
func (b *builder) decoyTermID(term Term) string {
	value := term.Normalized()
	if id, ok := b.decoyIDs[value]; ok {
		return id
	}
	id := b.addTerm(term, TermDecoy)
	b.decoyIDs[value] = id
	return id
}

func (b *builder) addTerm(term Term, role TermRole) string {
	b.termSeq++
	id := fmt.Sprintf("lexterm-%05d", b.termSeq)
	value := term.Normalized()
	b.terms = append(b.terms, ManifestTerm{
		TermID: id,
		Role:   role,
		Value:  value,
		Tokens: append([]string(nil), term.Tokens...),
	})
	if role == TermProtected && strings.HasPrefix(value, Anchor) {
		b.searchable = append(b.searchable, collisionCandidate{value: value, label: id, term: true})
	}
	return id
}

func (b *builder) addSource(surface Surface, header string, fragments []fragment) (string, []span) {
	b.sourceSeq++
	id := fmt.Sprintf("lexsrc-%06d", b.sourceSeq)
	text, spans := assembleArtifact(header, fragments)

	sum := sha256.Sum256([]byte(text))
	b.artifacts[id] = text
	b.sources = append(b.sources, ManifestSource{
		SourceID:   id,
		Surface:    string(surface),
		File:       "sources/" + id + ".txt",
		SHA256:     hex.EncodeToString(sum[:]),
		ByteLength: len(text),
	})
	return id, spans
}

// noteVariant records a rendered variant for the collision check. A transform
// can synthesise a word-like string that no base term contains, so checking
// terms alone would miss it.
func (b *builder) noteVariant(variant, label string) {
	b.searchable = append(b.searchable, collisionCandidate{value: variant, label: label})
}

func (b *builder) nextClusterID() string {
	b.clusterSeq++
	return fmt.Sprintf("lexcluster-%05d", b.clusterSeq)
}

// candidateCount is the number of lexical candidates the corpus presents: one
// per token across every source artifact, under a separator-splitting
// tokenization.
func (b *builder) candidateCount() int {
	total := 0
	for _, text := range b.artifacts {
		total += len(tokenizeCandidates(text))
	}
	return total
}

// tokenizeCandidates splits artifact text into candidate tokens on anything
// that is not a letter or digit.
//
// Letter and digit are Unicode categories, not ASCII ranges: the confusable and
// normalization transforms emit Cyrillic and fullwidth scalars, and classifying
// those as separators would split one identifier into several candidates.
func tokenizeCandidates(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// requireObservable fails closed when a transform rendered to something
// byte-identical to the unmutated term on that surface.
//
// A positive case whose artifact holds the plain term is not a mutation case at
// all: an exact matcher scores it as a hit, so it silently credits a detector
// for work it did not do. Guarding the rendered form rather than the token
// slice is deliberate — a transform can change the tokens and still render
// identically, which is exactly how this class of defect hides.
func requireObservable(cell Cell, term Term, variant, label string) error {
	if variant == joinTokens(cell.Surface, term.Tokens, nil) {
		return fmt.Errorf("%s: %s x %s rendered a variant identical to the unmutated term (%q)",
			label, cell.Surface, cell.Class, variant)
	}
	return nil
}

func mutationRecord(m mutation) MutationRecord {
	return MutationRecord{
		Class:             string(m.Class),
		TransformID:       m.TransformID,
		EditDistance:      intPtr(m.EditDistance),
		NormalizationForm: m.NormalizationForm,
	}
}

func findingExpectation(s span) Expected {
	return Expected{
		Disposition: "finding",
		MinFindings: 1,
		MaxFindings: 1,
		Spans:       []SpanRecord{{Start: s.Start, Length: s.Length, Unit: "utf8_byte"}},
	}
}

func termLength(term Term) TermLength {
	scalars := term.ScalarCount()
	tokens := term.TokenCount()
	return TermLength{
		NormalizedScalarCount: scalars,
		TokenCount:            tokens,
		ScalarBand:            scalarBand(scalars),
		TokenBand:             tokenBand(tokens),
	}
}

func mixHasCritical(surface Surface) bool {
	for _, severity := range severityMix[surface] {
		if severity == SeverityCritical {
			return true
		}
	}
	return false
}

func isExtensionCell(cell Cell) bool {
	for _, class := range extensionClasses[cell.Surface] {
		if class == cell.Class {
			return true
		}
	}
	return false
}
