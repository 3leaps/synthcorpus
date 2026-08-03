package lexmatrix

import (
	"strings"
)

// canonicalJoiner is the separator a surface normally uses between tokens.
// camel_case has no separator and is handled by joinTokens directly.
var canonicalJoiner = map[Surface]string{
	SurfaceProse:         " ",
	SurfacePath:          "/",
	SurfaceCamelCase:     "",
	SurfaceSnakeCase:     "_",
	SurfaceKebabCase:     "-",
	SurfaceConfigValue:   ".",
	SurfaceCommitMessage: " ",
}

// joinTokens renders tokens in the surface's own style, or in the style the
// transform asked for when it overrode the joiner.
func joinTokens(surface Surface, tokens []string, override *string) string {
	if override != nil {
		return strings.Join(tokens, *override)
	}
	if surface == SurfaceCamelCase {
		var out strings.Builder
		for i, token := range tokens {
			if i == 0 {
				out.WriteString(token)
				continue
			}
			out.WriteString(capitalizeFirst(token))
		}
		return out.String()
	}
	return strings.Join(tokens, canonicalJoiner[surface])
}

func capitalizeFirst(token string) string {
	runes := []rune(token)
	if len(runes) == 0 {
		return token
	}
	return strings.ToUpper(string(runes[0])) + string(runes[1:])
}

// fragment is one occurrence of a variant inside a source artifact: the bytes
// before it, the variant itself, and the bytes after it.
type fragment struct {
	prefix  string
	variant string
	suffix  string
}

// surroundings returns the surface-appropriate context an occurrence sits in.
// The surrounding text is deliberately ordinary so a scanner faces realistic
// non-matching neighbours.
func surroundings(surface Surface) (prefix, suffix string) {
	switch surface {
	case SurfaceProse:
		return "The ", " entry was reviewed by the team.\n"
	case SurfacePath:
		return "src/", ".txt\n"
	case SurfaceCamelCase:
		return "const ", " = loadRecord();\n"
	case SurfaceSnakeCase:
		return "let ", " = 0;\n"
	case SurfaceKebabCase:
		return "<div class=\"", "\"></div>\n"
	case SurfaceConfigValue:
		return "setting = \"", "\"\n"
	case SurfaceCommitMessage:
		return "fix: adjust ", " handling\n"
	default:
		return "", "\n"
	}
}

// artifactHeader is the first line of every source artifact. It keeps the
// files self-describing without naming any consumer.
func artifactHeader(surface Surface) string {
	return "# " + string(surface) + " sample\n"
}

// span is a byte range inside a source artifact.
type span struct {
	Start  int
	Length int
}

// assembleArtifact concatenates fragments under a header and returns the byte
// span of each variant occurrence.
func assembleArtifact(header string, fragments []fragment) (string, []span) {
	var out strings.Builder
	spans := make([]span, 0, len(fragments))

	out.WriteString(header)
	offset := len(header)

	for _, frag := range fragments {
		out.WriteString(frag.prefix)
		offset += len(frag.prefix)

		out.WriteString(frag.variant)
		spans = append(spans, span{Start: offset, Length: len(frag.variant)})
		offset += len(frag.variant)

		out.WriteString(frag.suffix)
		offset += len(frag.suffix)
	}
	return out.String(), spans
}

// newFragment builds a single occurrence of variant on surface.
func newFragment(surface Surface, variant string) fragment {
	prefix, suffix := surroundings(surface)
	return fragment{prefix: prefix, variant: variant, suffix: suffix}
}
