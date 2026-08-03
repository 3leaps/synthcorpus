package lexmatrix

import (
	"fmt"
	"strings"
)

// mutation records what a transform did, in the terms the fixture contract
// reports. It never carries the mutated string itself.
type mutation struct {
	Class             Class
	TransformID       string
	EditDistance      int
	NormalizationForm string
	// JoinerOverride replaces the surface's canonical joiner when non-nil.
	JoinerOverride *string
}

// position addresses one mutable scalar: token index plus rune offset within
// that token. Anchor scalars are never addressable.
type position struct {
	token int
	rune  int
}

// mutablePositions lists every body scalar of a term, in order.
func mutablePositions(tokens []string) []position {
	var out []position
	for ti, token := range tokens {
		runes := []rune(token)
		start := 0
		if ti == 0 {
			start = len([]rune(Anchor))
		}
		for ri := start; ri < len(runes); ri++ {
			out = append(out, position{token: ti, rune: ri})
		}
	}
	return out
}

// applyTransform mutates term under class and returns the variant tokens.
// The anchor is never touched; callers verify that with requireAnchor.
func applyTransform(d deriver, class Class, term Term, surface Surface, label string) ([]string, mutation, error) {
	tokens := append([]string(nil), term.Tokens...)
	positions := mutablePositions(tokens)
	if len(positions) == 0 {
		return nil, mutation{}, fmt.Errorf("%s: term has no mutable body", label)
	}

	switch class {
	case ClassIdentity:
		return tokens, mutation{Class: class, TransformID: "identity.unchanged", NormalizationForm: "NFC"}, nil

	case ClassCase:
		// Upper-case the body of one token; the anchor stays lowercase so the
		// variant is still greppable by anchor.
		ti := d.intn(len(tokens), label, "case-token")
		if surface == SurfaceCamelCase {
			// camel_case renders continuation tokens capitalised already, so
			// upper-casing one of those is invisible. Only the anchored token's
			// body is rendered verbatim, so only it can carry an observable
			// case change on this surface.
			ti = 0
		}
		runes := []rune(tokens[ti])
		start := 0
		if ti == 0 {
			start = len([]rune(Anchor))
		}
		for i := start; i < len(runes); i++ {
			runes[i] = []rune(strings.ToUpper(string(runes[i])))[0]
		}
		tokens[ti] = string(runes)
		return tokens, mutation{Class: class, TransformID: "case.body_upper", NormalizationForm: "NFC"}, nil

	case ClassSeparator:
		joiner := alternateJoiner(surface)
		return tokens, mutation{
			Class:             class,
			TransformID:       "separator.style_shift",
			NormalizationForm: "NFC",
			JoinerOverride:    &joiner,
		}, nil

	case ClassPlural:
		last := len(tokens) - 1
		tokens[last] += "s"
		return tokens, mutation{Class: class, TransformID: "plural.suffix_s", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassInsertion:
		p := positions[d.intn(len(positions), label, "insert-at")]
		ch := bodyAlphabet[d.intn(len(bodyAlphabet), label, "insert-char")]
		runes := []rune(tokens[p.token])
		runes = append(runes[:p.rune], append([]rune{rune(ch)}, runes[p.rune:]...)...)
		tokens[p.token] = string(runes)
		return tokens, mutation{Class: class, TransformID: "insertion.body_char", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassDeletion:
		p, ok := pickDeletable(d, tokens, positions, label)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: no deletable body scalar", label)
		}
		runes := []rune(tokens[p.token])
		tokens[p.token] = string(append(runes[:p.rune], runes[p.rune+1:]...))
		return tokens, mutation{Class: class, TransformID: "deletion.body_char", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassSubstitution:
		p := positions[d.intn(len(positions), label, "subst-at")]
		runes := []rune(tokens[p.token])
		original := runes[p.rune]
		replacement := rune(bodyAlphabet[d.intn(len(bodyAlphabet), label, "subst-char")])
		for replacement == original {
			// Walk the alphabet rather than re-deriving, so the result stays a
			// pure function of the label.
			idx := (strings.IndexRune(bodyAlphabet, replacement) + 1) % len(bodyAlphabet)
			replacement = rune(bodyAlphabet[idx])
		}
		runes[p.rune] = replacement
		tokens[p.token] = string(runes)
		return tokens, mutation{Class: class, TransformID: "substitution.body_char", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassTransposition:
		ti, ri, ok := pickTransposable(d, tokens, label)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: no adjacent distinct body scalars to transpose", label)
		}
		runes := []rune(tokens[ti])
		runes[ri], runes[ri+1] = runes[ri+1], runes[ri]
		tokens[ti] = string(runes)
		// A swap of two adjacent scalars is two single-character edits under
		// plain Levenshtein.
		return tokens, mutation{Class: class, TransformID: "transposition.body_adjacent", EditDistance: 2, NormalizationForm: "NFC"}, nil

	case ClassTokenSplit:
		ti, ri, ok := pickSplit(d, tokens, label)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: no token wide enough to split", label)
		}
		runes := []rune(tokens[ti])
		head := string(runes[:ri])
		tail := string(runes[ri:])
		out := append([]string(nil), tokens[:ti]...)
		out = append(out, head, tail)
		out = append(out, tokens[ti+1:]...)
		return out, mutation{Class: class, TransformID: "token_split.body_boundary", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassTokenJoin:
		if len(tokens) < 2 {
			return nil, mutation{}, fmt.Errorf("%s: token_join needs at least two tokens", label)
		}
		ti := d.intn(len(tokens)-1, label, "join-at")
		out := append([]string(nil), tokens[:ti]...)
		out = append(out, tokens[ti]+tokens[ti+1])
		out = append(out, tokens[ti+2:]...)
		return out, mutation{Class: class, TransformID: "token_join.drop_separator", EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassTruncation:
		out, removed, ok := trimTail(tokens, 3)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: term too short to truncate", label)
		}
		return out, mutation{Class: class, TransformID: "truncation.body_tail", EditDistance: removed, NormalizationForm: "NFC"}, nil

	case ClassVowelDrop:
		out, removed, ok := dropVowels(tokens, 4)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: term has no droppable body vowels", label)
		}
		return out, mutation{Class: class, TransformID: "vowel_drop.body_vowels", EditDistance: removed, NormalizationForm: "NFC"}, nil

	case ClassUnicodeConfusable:
		p, replacement, transformID, ok := pickConfusable(d, tokens, positions, label)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: term has no confusable body scalar", label)
		}
		runes := []rune(tokens[p.token])
		runes[p.rune] = replacement
		tokens[p.token] = string(runes)
		return tokens, mutation{Class: class, TransformID: transformID, EditDistance: 1, NormalizationForm: "NFC"}, nil

	case ClassUnicodeNormalization:
		p, ok := pickCombinable(d, tokens, positions, label)
		if !ok {
			return nil, mutation{}, fmt.Errorf("%s: term has no scalar that accepts a combining mark", label)
		}
		runes := []rune(tokens[p.token])
		out := append([]rune(nil), runes[:p.rune+1]...)
		out = append(out, combiningAcute)
		out = append(out, runes[p.rune+1:]...)
		tokens[p.token] = string(out)
		return tokens, mutation{Class: class, TransformID: "unicode.nfd_combining_mark", EditDistance: 1, NormalizationForm: "NFD"}, nil

	default:
		return nil, mutation{}, fmt.Errorf("%s: unsupported transform class %q", label, class)
	}
}

// combiningAcute is U+0301. Appending it to a base letter yields the
// decomposed form of the corresponding precomposed character.
const combiningAcute = '́'

// confusables maps a Latin scalar to a visually similar scalar from another
// script. Scalars absent here fall back to their fullwidth form, so a
// confusable variant can always be produced.
var confusables = map[rune]rune{
	'a': 'а', // Cyrillic a
	'c': 'с', // Cyrillic es
	'e': 'е', // Cyrillic ie
	'i': 'і', // Cyrillic byelorussian-ukrainian i
	'j': 'ј', // Cyrillic je
	'k': 'к', // Cyrillic ka
	'm': 'м', // Cyrillic em
	'o': 'о', // Cyrillic o
	'p': 'р', // Cyrillic er
	's': 'ѕ', // Cyrillic dze
	't': 'т', // Cyrillic te
	'x': 'х', // Cyrillic ha
	'y': 'у', // Cyrillic u
	'3': 'з', // Cyrillic ze
}

// fullwidthOf returns the fullwidth form of an ASCII letter or digit.
func fullwidthOf(r rune) (rune, bool) {
	switch {
	case r >= 'a' && r <= 'z':
		return 0xFF41 + (r - 'a'), true
	case r >= '0' && r <= '9':
		return 0xFF10 + (r - '0'), true
	default:
		return 0, false
	}
}

// combinable lists base scalars that carry an acute accent sensibly.
var combinable = map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true}

// pickDeletable finds a body scalar whose removal leaves every token
// non-empty.
func pickDeletable(d deriver, tokens []string, positions []position, label string) (position, bool) {
	start := d.intn(len(positions), label, "delete-at")
	for i := 0; i < len(positions); i++ {
		p := positions[(start+i)%len(positions)]
		if len([]rune(tokens[p.token])) > minTokenRunes(p.token) {
			return p, true
		}
	}
	return position{}, false
}

// minTokenRunes is the shortest a token may become: the anchored token must
// keep its anchor plus one body scalar, others must keep one scalar.
func minTokenRunes(tokenIndex int) int {
	if tokenIndex == 0 {
		return len([]rune(Anchor)) + 1
	}
	return 1
}

// pickTransposable finds adjacent distinct body scalars inside one token.
func pickTransposable(d deriver, tokens []string, label string) (int, int, bool) {
	type pair struct{ ti, ri int }
	var pairs []pair
	for ti, token := range tokens {
		runes := []rune(token)
		start := 0
		if ti == 0 {
			start = len([]rune(Anchor))
		}
		for ri := start; ri+1 < len(runes); ri++ {
			if runes[ri] != runes[ri+1] {
				pairs = append(pairs, pair{ti, ri})
			}
		}
	}
	if len(pairs) == 0 {
		return 0, 0, false
	}
	p := pairs[d.intn(len(pairs), label, "transpose-at")]
	return p.ti, p.ri, true
}

// pickSplit finds an offset that divides a token into two non-empty parts,
// keeping the anchor intact and leaving the anchored head at least one body
// scalar.
func pickSplit(d deriver, tokens []string, label string) (int, int, bool) {
	type cut struct{ ti, ri int }
	var cuts []cut
	for ti, token := range tokens {
		runes := []rune(token)
		start := 1
		if ti == 0 {
			start = len([]rune(Anchor)) + 1
		}
		for ri := start; ri < len(runes); ri++ {
			cuts = append(cuts, cut{ti, ri})
		}
	}
	if len(cuts) == 0 {
		return 0, 0, false
	}
	c := cuts[d.intn(len(cuts), label, "split-at")]
	return c.ti, c.ri, true
}

// pickConfusable prefers a cross-script homoglyph and falls back to a
// fullwidth form when the body carries no homoglyph-bearing scalar.
func pickConfusable(d deriver, tokens []string, positions []position, label string) (position, rune, string, bool) {
	var candidates []position
	for _, p := range positions {
		runes := []rune(tokens[p.token])
		if _, ok := confusables[runes[p.rune]]; ok {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) > 0 {
		p := candidates[d.intn(len(candidates), label, "confusable-at")]
		runes := []rune(tokens[p.token])
		return p, confusables[runes[p.rune]], "unicode.confusable_latin", true
	}

	for _, p := range positions {
		runes := []rune(tokens[p.token])
		if wide, ok := fullwidthOf(runes[p.rune]); ok {
			return p, wide, "unicode.confusable_fullwidth", true
		}
	}
	return position{}, 0, "", false
}

func pickCombinable(d deriver, tokens []string, positions []position, label string) (position, bool) {
	var candidates []position
	for _, p := range positions {
		runes := []rune(tokens[p.token])
		if combinable[runes[p.rune]] {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return position{}, false
	}
	return candidates[d.intn(len(candidates), label, "combining-at")], true
}

// trimTail removes up to want scalars from the end of the term, dropping
// emptied trailing tokens. It never consumes the anchor and always leaves at
// least one body scalar.
func trimTail(tokens []string, want int) ([]string, int, bool) {
	out := append([]string(nil), tokens...)
	removed := 0
	for removed < want {
		last := len(out) - 1
		runes := []rune(out[last])
		if len(runes) > minTokenRunes(last) {
			out[last] = string(runes[:len(runes)-1])
			removed++
			continue
		}
		if last == 0 {
			break
		}
		removed += len(runes)
		out = out[:last]
		if removed >= want {
			break
		}
	}
	if removed == 0 {
		return nil, 0, false
	}
	if removed > 4 {
		// The contract caps reported edit distance at 4.
		removed = 4
	}
	return out, removed, true
}

// dropVowels removes up to want body vowels, dropping emptied tokens.
func dropVowels(tokens []string, want int) ([]string, int, bool) {
	out := make([]string, 0, len(tokens))
	removed := 0
	for ti, token := range tokens {
		runes := []rune(token)
		start := 0
		if ti == 0 {
			start = len([]rune(Anchor))
		}
		// Each token must keep at least one body scalar, the same floor
		// deletion and truncation enforce, so compute how many vowels this
		// token can spare before dropping any.
		body := runes[start:]
		budget := want - removed
		if spare := len(body) - 1; budget > spare {
			budget = spare
		}

		kept := append([]rune(nil), runes[:start]...)
		for _, r := range body {
			if budget > 0 && strings.ContainsRune("aeiou", r) {
				budget--
				removed++
				continue
			}
			kept = append(kept, r)
		}
		out = append(out, string(kept))
	}
	if removed == 0 || len(out) == 0 {
		return nil, 0, false
	}
	if len([]rune(out[0])) <= len([]rune(Anchor)) && len(out) == 1 {
		return nil, 0, false
	}
	return out, removed, true
}

// alternateJoiner returns the separator style a separator-class variant shifts
// to for the given surface.
func alternateJoiner(surface Surface) string {
	switch surface {
	case SurfaceProse, SurfaceCommitMessage:
		return "-"
	case SurfacePath:
		return "-"
	case SurfaceCamelCase:
		return "_"
	case SurfaceSnakeCase:
		return "-"
	case SurfaceKebabCase:
		return "_"
	case SurfaceConfigValue:
		return "_"
	default:
		return "-"
	}
}
