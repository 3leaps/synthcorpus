package provability

import "strings"

// colonKeyringHasKeys reports whether gpg --with-colons listing output contains
// any public/secret key records.
func colonKeyringHasKeys(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub", "sub", "sec", "ssb", "fpr":
			return true
		}
	}
	return false
}
