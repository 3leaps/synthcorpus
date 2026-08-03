// Package lexmatrix generates deterministic synthetic lexical-mutation fixture
// sets for detector benchmarking.
//
// The corpus is described by the lexical-mutation matrix v1: a fixed set of
// (surface x transform class) cells with per-cell population floors. Terms are
// built from the synthlex-v1 grammar — an immutable `zzlx` anchor plus a
// seed-derived base32 body — so every generated string is visibly synthetic and
// mutations only ever touch the body.
//
// Two artifacts come out of a generation run:
//
//   - a sterile fixture set holding opaque identifiers and answer-key
//     coordinates only, and
//   - a protected manifest holding the term values and source artifacts.
//
// Only the sterile fixture set is safe to move between systems; the protected
// manifest is referenced from it by digest alone.
package lexmatrix

// Surface is a rendering context a term can appear in.
type Surface string

const (
	SurfaceProse         Surface = "prose"
	SurfacePath          Surface = "path"
	SurfaceCamelCase     Surface = "camel_case"
	SurfaceSnakeCase     Surface = "snake_case"
	SurfaceKebabCase     Surface = "kebab_case"
	SurfaceConfigValue   Surface = "config_value"
	SurfaceCommitMessage Surface = "commit_message"
)

// Class is a transform family applied to a term body.
type Class string

const (
	ClassIdentity             Class = "identity"
	ClassCase                 Class = "case"
	ClassSeparator            Class = "separator"
	ClassPlural               Class = "plural"
	ClassInsertion            Class = "insertion"
	ClassDeletion             Class = "deletion"
	ClassSubstitution         Class = "substitution"
	ClassTransposition        Class = "transposition"
	ClassTokenSplit           Class = "token_split"
	ClassTokenJoin            Class = "token_join"
	ClassUnicodeNormalization Class = "unicode_normalization"
	ClassUnicodeConfusable    Class = "unicode_confusable"
	ClassTruncation           Class = "truncation"
	ClassVowelDrop            Class = "vowel_drop"
)

// Severity is the answer-key severity carried by a case.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Lane separates cases a normalizing exact matcher must catch from cases that
// require approximate matching, and both from negative controls.
type Lane string

const (
	LaneDeterministic  Lane = "deterministic"
	LaneApproximate    Lane = "approximate"
	LaneNegativeContro Lane = "negative_control"
)

// Scope marks whether a case belongs to the required matrix or to an
// opt-in extension beyond it.
type Scope string

const (
	ScopeRequired  Scope = "required"
	ScopeExtension Scope = "extension"
)

// Population floors for the required matrix. Every generated set is checked
// against these before it is written.
const (
	FloorPositivesPerCell     = 12
	FloorTermsPerCell         = 4
	FloorScalarBandsPerCell   = 2
	FloorNegativesPerSurface  = 6
	FloorClustersPerCell      = 1
	FloorShortCasesPerSurface = 12
)

// termsPerCell is the number of distinct terms drawn for each cell. It sits
// above FloorTermsPerCell so band coverage has room.
const termsPerCell = 6

// clusterSize is the number of co-located occurrences forming each cell's
// duplicate/concentration cluster.
const clusterSize = 3

// shortCasesPerSurface is the number of explicit below-policy-length cases
// emitted per surface.
const shortCasesPerSurface = FloorShortCasesPerSurface

// requiredClasses lists the transform classes populated for each surface.
// Order is significant: it drives severity rotation and case derivation.
var requiredClasses = map[Surface][]Class{
	SurfaceProse: {
		ClassCase, ClassSeparator, ClassPlural, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTransposition, ClassTokenSplit, ClassTokenJoin,
	},
	SurfacePath: {
		ClassCase, ClassSeparator, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTokenJoin,
	},
	SurfaceCamelCase: {
		ClassCase, ClassSeparator, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTokenJoin,
	},
	SurfaceSnakeCase: {
		ClassCase, ClassSeparator, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTransposition, ClassTruncation,
	},
	SurfaceKebabCase: {
		ClassCase, ClassSeparator, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTransposition,
	},
	SurfaceConfigValue: {
		ClassCase, ClassSeparator, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTokenJoin,
	},
	SurfaceCommitMessage: {
		ClassCase, ClassSeparator, ClassPlural, ClassInsertion, ClassDeletion,
		ClassSubstitution, ClassTransposition, ClassTokenSplit, ClassTokenJoin,
	},
}

// surfaceOrder fixes iteration order so generation is reproducible.
var surfaceOrder = []Surface{
	SurfaceProse,
	SurfacePath,
	SurfaceCamelCase,
	SurfaceSnakeCase,
	SurfaceKebabCase,
	SurfaceConfigValue,
	SurfaceCommitMessage,
}

// extensionClasses are implemented transforms held outside the required
// matrix. They are emitted only when extensions are requested, and are always
// marked ScopeExtension.
var extensionClasses = map[Surface][]Class{
	SurfaceProse:         {ClassUnicodeNormalization, ClassUnicodeConfusable, ClassVowelDrop},
	SurfacePath:          {ClassUnicodeConfusable, ClassTruncation},
	SurfaceCamelCase:     {ClassVowelDrop, ClassTruncation},
	SurfaceSnakeCase:     {ClassVowelDrop},
	SurfaceKebabCase:     {ClassTruncation, ClassVowelDrop},
	SurfaceConfigValue:   {ClassUnicodeConfusable, ClassTruncation},
	SurfaceCommitMessage: {ClassUnicodeNormalization, ClassVowelDrop},
}

// severityMix is the per-surface severity rotation applied across that
// surface's class list.
var severityMix = map[Surface][]Severity{
	SurfaceProse:         {SeverityMedium, SeverityHigh, SeverityCritical},
	SurfacePath:          {SeverityHigh, SeverityCritical},
	SurfaceCamelCase:     {SeverityHigh, SeverityCritical},
	SurfaceSnakeCase:     {SeverityHigh},
	SurfaceKebabCase:     {SeverityHigh},
	SurfaceConfigValue:   {SeverityHigh},
	SurfaceCommitMessage: {SeverityMedium, SeverityHigh, SeverityCritical},
}

// elevatedCells pins severity for cells that carry a fixed floor regardless of
// where the surface rotation would otherwise land them.
var elevatedCells = map[Cell]Severity{
	{SurfaceProse, ClassTokenSplit}:            SeverityCritical,
	{SurfaceProse, ClassTokenJoin}:             SeverityCritical,
	{SurfaceCamelCase, ClassTokenJoin}:         SeverityCritical,
	{SurfaceSnakeCase, ClassTruncation}:        SeverityHigh,
	{SurfacePath, ClassTokenJoin}:              SeverityHigh,
	{SurfaceCommitMessage, ClassTransposition}: SeverityCritical,
}

// Cell is one (surface x transform class) coordinate of the matrix.
type Cell struct {
	Surface Surface
	Class   Class
}

// RequiredCells returns every cell of the required matrix in generation order.
func RequiredCells() []Cell {
	cells := make([]Cell, 0, 64)
	for _, surface := range surfaceOrder {
		for _, class := range requiredClasses[surface] {
			cells = append(cells, Cell{Surface: surface, Class: class})
		}
	}
	return cells
}

// ExtensionCells returns every implemented-but-not-required cell in
// generation order.
func ExtensionCells() []Cell {
	cells := make([]Cell, 0, 16)
	for _, surface := range surfaceOrder {
		for _, class := range extensionClasses[surface] {
			cells = append(cells, Cell{Surface: surface, Class: class})
		}
	}
	return cells
}

// severityFor resolves a cell's default severity: the pinned value when the
// cell is elevated, otherwise the surface rotation at the class's position.
func severityFor(cell Cell) Severity {
	if pinned, ok := elevatedCells[cell]; ok {
		return pinned
	}
	mix := severityMix[cell.Surface]
	classes := requiredClasses[cell.Surface]
	for i, class := range classes {
		if class == cell.Class {
			return mix[i%len(mix)]
		}
	}
	// Extension cells sit outside the rotation; they take the surface floor.
	return mix[0]
}

// laneFor reports which matching lane a class belongs to. Case and separator
// differences survive normalization, so an exact matcher is expected to catch
// them; every other transform needs approximate matching.
func laneFor(class Class) Lane {
	switch class {
	case ClassIdentity, ClassCase, ClassSeparator:
		return LaneDeterministic
	default:
		return LaneApproximate
	}
}
