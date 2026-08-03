package lexmatrix

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// Namespace is the reserved vocabulary namespace for every term this package
// produces.
const Namespace = "synthlex-v1"

// Anchor prefixes every term. It is immutable: no transform may alter these
// scalars, so any generated string — mutated or not — stays greppable and
// visibly synthetic.
const Anchor = "zzlx"

// bodyAlphabet is the lowercase RFC 4648 base32 alphabet. Bodies are drawn
// from it so terms carry no natural-language content.
const bodyAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// commonWords is a small public common-word list used for collision checking
// and for common_word negative controls. It is deliberately generic.
var commonWords = []string{
	"value", "config", "index", "service", "handler", "record",
	"buffer", "session", "adapter", "payload", "channel", "registry",
}

// Term is a synthlex-v1 term: an anchored first token followed by body-only
// continuation tokens.
type Term struct {
	Tokens []string
}

// Normalized returns the separator-free lowercase form used for length
// accounting and cross-surface comparison.
func (t Term) Normalized() string {
	return strings.ToLower(strings.Join(t.Tokens, ""))
}

// ScalarCount is the normalized scalar length of the term.
func (t Term) ScalarCount() int {
	return len([]rune(t.Normalized()))
}

// TokenCount is the number of tokens in the term.
func (t Term) TokenCount() int {
	return len(t.Tokens)
}

// termSpec describes the shape of a term to derive.
type termSpec struct {
	tokens  int
	bodyLen int
}

// specsForClass returns the six term shapes drawn for a cell. Classes that
// consume body scalars need longer bodies so the mutated form stays above a
// plausible minimum-length policy.
func specsForClass(class Class) []termSpec {
	switch class {
	case ClassTruncation, ClassVowelDrop:
		return []termSpec{
			{tokens: 2, bodyLen: 6},
			{tokens: 2, bodyLen: 6},
			{tokens: 3, bodyLen: 8},
			{tokens: 3, bodyLen: 8},
			{tokens: 4, bodyLen: 14},
			{tokens: 4, bodyLen: 14},
		}
	default:
		return []termSpec{
			{tokens: 2, bodyLen: 4},
			{tokens: 2, bodyLen: 4},
			{tokens: 3, bodyLen: 8},
			{tokens: 3, bodyLen: 8},
			{tokens: 4, bodyLen: 14},
			{tokens: 4, bodyLen: 14},
		}
	}
}

// deriver turns a seed plus a label path into deterministic bytes. Every
// random-looking choice in this package goes through it, so a generation run
// depends on nothing but its seed and this code.
type deriver struct {
	seed uint32
}

func newDeriver(seed uint32) deriver {
	return deriver{seed: seed}
}

// bytes returns 32 deterministic bytes for the given label path.
func (d deriver) bytes(parts ...string) []byte {
	h := sha256.New()
	var seedBuf [4]byte
	binary.BigEndian.PutUint32(seedBuf[:], d.seed)
	h.Write([]byte(Namespace))
	h.Write([]byte{0})
	h.Write(seedBuf[:])
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

// intn returns a deterministic value in [0,n) for the given label path.
func (d deriver) intn(n int, parts ...string) int {
	if n <= 0 {
		return 0
	}
	sum := d.bytes(parts...)
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(n))
}

// body returns a deterministic base32 body of the requested length.
func (d deriver) body(length int, parts ...string) string {
	var out strings.Builder
	out.Grow(length)
	block := d.bytes(parts...)
	for i := 0; i < length; i++ {
		if i > 0 && i%32 == 0 {
			block = d.bytes(append(parts, fmt.Sprintf("block%d", i/32))...)
		}
		out.WriteByte(bodyAlphabet[int(block[i%32])%len(bodyAlphabet)])
	}
	return out.String()
}

// newTerm derives a term of the requested shape. The anchor occupies the head
// of the first token; every remaining scalar is body. The class the term will
// be mutated under is taken into account so the transform always has something
// to work with.
func newTerm(d deriver, class Class, spec termSpec, label string) (Term, error) {
	if spec.tokens < 1 {
		return Term{}, fmt.Errorf("term needs at least one token: %s", label)
	}
	if spec.bodyLen < spec.tokens {
		return Term{}, fmt.Errorf("body of %d scalars cannot fill %d tokens: %s", spec.bodyLen, spec.tokens, label)
	}

	body := ensureApplicable(class, d.body(spec.bodyLen, label, "body"))
	tokens := splitBody(body, spec.tokens)
	tokens[0] = Anchor + tokens[0]

	// Invariants below are enforced after the split, because splitting is what
	// decides which scalars end up adjacent inside a token.
	tokens = ensureTokenBodiesStartWithLetter(tokens)
	if class == ClassTransposition {
		tokens = ensureInTokenTransposable(tokens)
	}
	return Term{Tokens: tokens}, nil
}

// ensureTokenBodiesStartWithLetter forces the first body scalar of every token
// to be a letter.
//
// Two transforms depend on it. Upper-casing an all-digit body is a no-op, and
// on camel_case — the one surface with no separator — joining a token whose
// successor starts with a digit is also a no-op, because the renderer's
// capitalisation has nothing to act on. Either produces a "variant" identical
// to the unmutated term.
func ensureTokenBodiesStartWithLetter(tokens []string) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		runes := []rune(token)
		start := 0
		if i == 0 {
			start = len([]rune(Anchor))
		}
		if start < len(runes) {
			runes[start] = toLetter(runes[start])
		}
		out[i] = string(runes)
	}
	return out
}

// toLetter maps a base32 digit onto a letter and leaves letters alone.
func toLetter(r rune) rune {
	if r >= '2' && r <= '7' {
		return 'a' + (r - '2')
	}
	return r
}

// ensureInTokenTransposable guarantees some token holds two adjacent distinct
// body scalars. Checking this before the split is not enough: the split can
// land the token boundary exactly on the only distinct pair, leaving the
// transform with nothing reachable.
func ensureInTokenTransposable(tokens []string) []string {
	for i, token := range tokens {
		runes := []rune(token)
		start := bodyStart(i)
		for r := start; r+1 < len(runes); r++ {
			if runes[r] != runes[r+1] {
				return tokens
			}
		}
	}

	// Widen the roomiest token's tail into a distinct pair.
	widest, widestLen := -1, 0
	for i, token := range tokens {
		if n := len([]rune(token)) - bodyStart(i); n > widestLen {
			widest, widestLen = i, n
		}
	}
	if widest < 0 || widestLen < 2 {
		return tokens
	}

	out := append([]string(nil), tokens...)
	runes := []rune(out[widest])
	last := len(runes) - 1
	if runes[last] == 'a' {
		runes[last-1] = 'b'
	} else {
		runes[last-1] = 'a'
	}
	out[widest] = string(runes)
	return out
}

// bodyStart is the first mutable rune offset within the token at index i.
func bodyStart(i int) int {
	if i == 0 {
		return len([]rune(Anchor))
	}
	return 0
}

// ensureApplicable nudges a derived body so the transform it will face always
// has a scalar to act on. Without this a body can come back with, say, no
// vowels at all, and a vowel-dropping transform has nothing to drop.
func ensureApplicable(class Class, body string) string {
	runes := []rune(body)
	if len(runes) == 0 {
		return body
	}

	switch class {
	case ClassVowelDrop, ClassUnicodeNormalization:
		if strings.ContainsAny(body, "aeiou") {
			return body
		}
		runes[0] = 'a'
		return string(runes)

	case ClassTransposition:
		for i := 0; i+1 < len(runes); i++ {
			if runes[i] != runes[i+1] {
				return body
			}
		}
		if len(runes) < 2 {
			return body
		}
		// Every scalar is identical; break the run so an adjacent swap is
		// observable.
		if runes[1] == 'a' {
			runes[1] = 'b'
		} else {
			runes[1] = 'a'
		}
		return string(runes)

	default:
		return body
	}
}

// splitBody divides a body into n non-empty parts, front-loading the
// remainder so the anchored token stays the longest.
func splitBody(body string, n int) []string {
	runes := []rune(body)
	parts := make([]string, n)
	base := len(runes) / n
	extra := len(runes) % n

	pos := 0
	for i := 0; i < n; i++ {
		size := base
		if i < extra {
			size++
		}
		parts[i] = string(runes[pos : pos+size])
		pos += size
	}
	return parts
}

// shortTerm derives a below-policy-length term. These lead with a prefix of the
// anchor — being too short to hold the whole anchor is precisely why they are
// below policy — and fill the remaining scalars from the body alphabet so the
// short population is not just one value repeated.
//
// A one-scalar term has no room for filler, so every surface's length-1 cases
// share the single value the grammar admits.
func shortTerm(d deriver, length int, label string) (Term, error) {
	if length < 1 || length > 3 {
		return Term{}, fmt.Errorf("short term length %d outside 1-3", length)
	}

	value := Anchor[:length-1] + d.body(1, label, "short")
	if length == 1 {
		value = Anchor[:1]
	}
	return Term{Tokens: []string{value}}, nil
}

// scalarBand buckets a normalized scalar count into the contract's bands.
func scalarBand(count int) string {
	switch {
	case count <= 3:
		return "1_3"
	case count <= 5:
		return "4_5"
	case count <= 8:
		return "6_8"
	case count <= 14:
		return "9_14"
	default:
		return "15_plus"
	}
}

// tokenBand buckets a token count into the contract's bands.
func tokenBand(count int) string {
	switch {
	case count <= 1:
		return "single"
	case count <= 4:
		return "multi_2_4"
	default:
		return "multi_5_plus"
	}
}

// termClassFor names the shape of a term as it appears on a surface.
func termClassFor(surface Surface, tokenCount int) string {
	if tokenCount <= 1 {
		return "synthetic_token"
	}
	if tokenCount == 2 {
		return "synthetic_compound"
	}
	switch surface {
	case SurfaceProse, SurfaceCommitMessage:
		return "synthetic_phrase"
	default:
		return "synthetic_identifier"
	}
}

// collisionCandidate is one string the collision check must clear: either a
// term a detector will search for, or a variant planted in an artifact.
type collisionCandidate struct {
	value string
	label string
	// term marks searched vocabulary. Two terms sharing a value produce an
	// ambiguous answer key; two variants sharing one are ordinary.
	term bool
}

// checkCollisions fails closed if any generated string could be mistaken for
// natural language, or if two searched terms resolve to the same value.
//
// It takes a slice rather than a map keyed by value: a map silently collapses
// duplicates, which are precisely what the term-uniqueness half of this check
// exists to catch.
func checkCollisions(candidates []collisionCandidate) error {
	seenTerms := make(map[string]string, len(candidates))

	for _, candidate := range candidates {
		lowered := strings.ToLower(candidate.value)
		for _, word := range commonWords {
			if strings.Contains(lowered, word) {
				return fmt.Errorf("generated string %q (%s) contains common word %q", candidate.value, candidate.label, word)
			}
		}
		if !candidate.term {
			continue
		}
		if prior, ok := seenTerms[candidate.value]; ok {
			return fmt.Errorf("terms %s and %s both resolve to %q", prior, candidate.label, candidate.value)
		}
		seenTerms[candidate.value] = candidate.label
	}
	return nil
}

// requireAnchor fails closed if a mutated form lost its anchor. Every
// transform is expected to leave the anchor scalars untouched.
func requireAnchor(tokens []string, label string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("%s produced no tokens", label)
	}
	if !strings.HasPrefix(tokens[0], Anchor) {
		return fmt.Errorf("%s produced %q, which does not carry the anchor", label, tokens[0])
	}
	return nil
}
