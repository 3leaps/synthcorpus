package lexmatrix

import "fmt"

// SchemaVersion is the fixture contract this package emits.
const SchemaVersion = "synthetic-lexical-benchmark/v0"

// GeneratorName identifies this generator inside a fixture set.
const GeneratorName = "synthcorpus-lexical"

// GeneratorVersion is the fixture-shape version. Bump it whenever a change
// alters generated output for an unchanged seed.
const GeneratorVersion = "0.1.0"

// FixtureSet is the sterile half of a generation run. Every field is either a
// coordinate, an opaque identifier, or a digest — never a term or a variant.
type FixtureSet struct {
	SchemaVersion         string    `json:"schema_version"`
	FixtureSetID          string    `json:"fixture_set_id"`
	VocabularyNamespace   string    `json:"vocabulary_namespace"`
	Generator             Generator `json:"generator"`
	SourceManifestSHA256  string    `json:"source_manifest_sha256"`
	Profile               string    `json:"profile"`
	LexicalCandidateCount int       `json:"lexical_candidate_count"`
	Cases                 []Case    `json:"cases"`
}

// Generator records what produced a fixture set.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Seed    uint32 `json:"seed"`
}

// Case is one answer-key entry.
type Case struct {
	CaseID               string         `json:"case_id"`
	SourceID             string         `json:"source_id"`
	TermID               string         `json:"term_id"`
	TermClass            string         `json:"term_class"`
	Lane                 string         `json:"lane"`
	Surface              string         `json:"surface"`
	Mutation             MutationRecord `json:"mutation"`
	Expected             Expected       `json:"expected"`
	Severity             string         `json:"severity"`
	TermLength           TermLength     `json:"term_length"`
	CriticalSeed         bool           `json:"critical_seed"`
	Scope                string         `json:"e0_scope"`
	NegativeControlClass string         `json:"negative_control_class,omitempty"`
	Review               Review         `json:"review"`
	Tags                 []string       `json:"tags,omitempty"`
}

// MutationRecord names the transform without carrying its output.
type MutationRecord struct {
	Class             string `json:"class"`
	TransformID       string `json:"transform_id"`
	EditDistance      *int   `json:"edit_distance,omitempty"`
	NormalizationForm string `json:"normalization_form,omitempty"`
}

// Expected is the answer key for a case. Counts are scoped per case, not per
// source artifact: several cases can share a source, and each owns only its own
// spans.
type Expected struct {
	Disposition           string       `json:"disposition"`
	MinFindings           int          `json:"min_findings"`
	MaxFindings           int          `json:"max_findings"`
	Spans                 []SpanRecord `json:"spans"`
	UnsupportedReasonCode string       `json:"unsupported_reason_code,omitempty"`
}

// SpanRecord locates a variant inside its source artifact.
type SpanRecord struct {
	Start  int    `json:"start"`
	Length int    `json:"length"`
	Unit   string `json:"unit"`
}

// TermLength carries the length accounting a runner buckets results by.
type TermLength struct {
	NormalizedScalarCount int    `json:"normalized_scalar_count"`
	TokenCount            int    `json:"token_count"`
	ScalarBand            string `json:"scalar_band"`
	TokenBand             string `json:"token_band"`
}

// Review is the expected human disposition of a case.
type Review struct {
	ExpectedAction string  `json:"expected_action"`
	ClusterID      *string `json:"cluster_id"`
}

// Manifest is the protected half of a generation run: the term values and
// source artifacts the sterile fixture set only references. It is written
// outside any git worktree and shared by digest, never by copy.
type Manifest struct {
	SchemaVersion string           `json:"schema_version"`
	Namespace     string           `json:"vocabulary_namespace"`
	Generator     Generator        `json:"generator"`
	Terms         []ManifestTerm   `json:"terms"`
	Sources       []ManifestSource `json:"sources"`
}

// TermRole separates the terms a detector is asked to search for from the
// decoys that only exist to be found and rejected.
type TermRole string

const (
	// TermProtected marks a term that belongs to the searched vocabulary.
	TermProtected TermRole = "protected"
	// TermDecoy marks a negative control. A decoy must never enter the search
	// set: it is planted to be passed over, and its answer key expects zero
	// findings, so searching for it guarantees a false positive.
	TermDecoy TermRole = "decoy"
)

// ManifestTerm resolves a term identifier to its value.
type ManifestTerm struct {
	TermID string   `json:"term_id"`
	Role   TermRole `json:"role"`
	Value  string   `json:"value"`
	Tokens []string `json:"tokens"`
}

// ManifestSource resolves a source identifier to its artifact on disk.
type ManifestSource struct {
	SourceID   string `json:"source_id"`
	Surface    string `json:"surface"`
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byte_length"`
}

// dispositionActions is the review action each disposition admits. A consumer
// rejects any case whose disposition and expected action disagree, so the
// generator holds to the same table.
var dispositionActions = map[string]map[string]bool{
	"finding":     {"confirm": true, "manual_review": true},
	"allowed":     {"dismiss": true, "allowlist": true},
	"unsupported": {"unsupported": true},
	"review_only": {"manual_review": true},
}

// checkDispositionAction fails closed on a disposition/action pair a consumer
// would reject.
func checkDispositionAction(caseID, disposition, action string) error {
	allowed, ok := dispositionActions[disposition]
	if !ok {
		return fmt.Errorf("case %s: unknown disposition %q", caseID, disposition)
	}
	if !allowed[action] {
		return fmt.Errorf("case %s: disposition %q does not admit review action %q", caseID, disposition, action)
	}
	return nil
}

func intPtr(v int) *int {
	return &v
}

func strPtr(v string) *string {
	return &v
}
