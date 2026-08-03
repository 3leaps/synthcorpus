package lexmatrix

import (
	"fmt"
	"sort"
	"strings"
)

// CellAccount is the population of one matrix cell.
type CellAccount struct {
	Surface             string `json:"surface"`
	Class               string `json:"class"`
	Scope               string `json:"e0_scope"`
	Positives           int    `json:"positives"`
	DistinctTerms       int    `json:"distinct_terms"`
	DistinctScalarBands int    `json:"distinct_scalar_bands"`
	Clusters            int    `json:"clusters"`
	CriticalSeeds       int    `json:"critical_seeds"`
}

// SurfaceAccount is the per-surface negative-control population.
type SurfaceAccount struct {
	Surface    string `json:"surface"`
	Negatives  int    `json:"negative_controls"`
	ShortCases int    `json:"short_cases"`
}

// Accounting is the floor evidence for a generated set.
type Accounting struct {
	TotalCases       int              `json:"total_cases"`
	Positives        int              `json:"positives"`
	NegativeControls int              `json:"negative_controls"`
	CriticalSeeds    int              `json:"critical_seeds"`
	RequiredCells    int              `json:"required_cells"`
	Cells            []CellAccount    `json:"cells"`
	Surfaces         []SurfaceAccount `json:"surfaces"`
}

// buildAccounting tallies a generated set by cell and by surface.
func buildAccounting(fs FixtureSet) Accounting {
	type cellKey struct{ surface, class, scope string }

	cellCases := map[cellKey][]Case{}
	surfaceNegatives := map[string]int{}
	surfaceShort := map[string]int{}

	acct := Accounting{TotalCases: len(fs.Cases)}

	for _, c := range fs.Cases {
		if c.Lane == string(LaneNegativeContro) {
			acct.NegativeControls++
			if c.NegativeControlClass == "short_term" {
				surfaceShort[c.Surface]++
			} else {
				surfaceNegatives[c.Surface]++
			}
			continue
		}
		acct.Positives++
		if c.CriticalSeed {
			acct.CriticalSeeds++
		}
		key := cellKey{c.Surface, c.Mutation.Class, c.Scope}
		cellCases[key] = append(cellCases[key], c)
	}

	keys := make([]cellKey, 0, len(cellCases))
	for key := range cellCases {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].surface != keys[j].surface {
			return keys[i].surface < keys[j].surface
		}
		if keys[i].class != keys[j].class {
			return keys[i].class < keys[j].class
		}
		// Scope completes the key. Required and extension class sets happen to
		// be disjoint per surface today, but sort.Slice is not stable, so an
		// incidental tie would make accounting.json ordering non-deterministic.
		return keys[i].scope < keys[j].scope
	})

	for _, key := range keys {
		cases := cellCases[key]
		terms := map[string]bool{}
		bands := map[string]bool{}
		clusters := map[string]bool{}
		criticalSeeds := 0

		for _, c := range cases {
			terms[c.TermID] = true
			bands[c.TermLength.ScalarBand] = true
			if c.Review.ClusterID != nil {
				clusters[*c.Review.ClusterID] = true
			}
			if c.CriticalSeed {
				criticalSeeds++
			}
		}

		account := CellAccount{
			Surface:             key.surface,
			Class:               key.class,
			Scope:               key.scope,
			Positives:           len(cases),
			DistinctTerms:       len(terms),
			DistinctScalarBands: len(bands),
			Clusters:            len(clusters),
			CriticalSeeds:       criticalSeeds,
		}
		acct.Cells = append(acct.Cells, account)
		if key.scope == string(ScopeRequired) {
			acct.RequiredCells++
		}
	}

	for _, surface := range surfaceOrder {
		acct.Surfaces = append(acct.Surfaces, SurfaceAccount{
			Surface:    string(surface),
			Negatives:  surfaceNegatives[string(surface)],
			ShortCases: surfaceShort[string(surface)],
		})
	}

	return acct
}

// CheckFloors fails closed when any required cell or surface sits below the
// matrix's population floors.
func (a Accounting) CheckFloors() error {
	var problems []string

	for _, cell := range a.Cells {
		if cell.Scope != string(ScopeRequired) {
			continue
		}
		where := cell.Surface + " x " + cell.Class
		if cell.Positives < FloorPositivesPerCell {
			problems = append(problems, fmt.Sprintf("%s: %d positives (floor %d)", where, cell.Positives, FloorPositivesPerCell))
		}
		if cell.DistinctTerms < FloorTermsPerCell {
			problems = append(problems, fmt.Sprintf("%s: %d distinct terms (floor %d)", where, cell.DistinctTerms, FloorTermsPerCell))
		}
		if cell.DistinctScalarBands < FloorScalarBandsPerCell {
			problems = append(problems, fmt.Sprintf("%s: %d scalar bands (floor %d)", where, cell.DistinctScalarBands, FloorScalarBandsPerCell))
		}
		if cell.Clusters < FloorClustersPerCell {
			problems = append(problems, fmt.Sprintf("%s: %d clusters (floor %d)", where, cell.Clusters, FloorClustersPerCell))
		}
	}

	for _, surface := range a.Surfaces {
		if surface.Negatives < FloorNegativesPerSurface {
			problems = append(problems, fmt.Sprintf("%s: %d negative controls (floor %d)", surface.Surface, surface.Negatives, FloorNegativesPerSurface))
		}
		if surface.ShortCases < FloorShortCasesPerSurface {
			problems = append(problems, fmt.Sprintf("%s: %d short cases (floor %d)", surface.Surface, surface.ShortCases, FloorShortCasesPerSurface))
		}
	}

	expectedCells := len(RequiredCells())
	if a.RequiredCells != expectedCells {
		problems = append(problems, fmt.Sprintf("required cells populated: %d (matrix declares %d)", a.RequiredCells, expectedCells))
	}

	if len(problems) > 0 {
		return fmt.Errorf("population floors not met:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
