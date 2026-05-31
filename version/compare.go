package version

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
	pep440 "github.com/aquasecurity/go-pep440-version"
	mvn "github.com/masahiro331/go-mvn-version"
)

// Compare compares two versions under the given ecosystem/versionType scheme.
// Returns cmp ∈ {-1,0,1} and ok=true when parsing succeeded.
// ok=false means "unparseable under this scheme" — caller must fall back to
// exact string match (precision over recall).
func Compare(ecosystem, versionType, a, b string) (cmp int, ok bool) {
	scheme := pickScheme(versionType, ecosystem)
	switch scheme {
	case "semver":
		return compareSemver(a, b)
	case "pep440":
		return comparePEP440(a, b)
	case "maven":
		return compareMaven(a, b)
	default:
		return compareGeneric(a, b)
	}
}

// Within checks if version is inside the range [lowerBound, upperBound).
// The upper bound is exclusive (lessThan) unless lessThanOrEqual is provided.
func Within(ecosystem, versionType, version, lowerBound, lessThan, lessThanOrEqual string) (inRange bool, ok bool) {
	if version == "" {
		return false, false
	}

	scheme := pickScheme(versionType, ecosystem)

	// Check lower bound
	if lowerBound != "" {
		cmp, parsed := compareWithScheme(scheme, version, lowerBound)
		if parsed && cmp < 0 {
			return false, true
		}
		if !parsed && version < lowerBound {
			return false, false
		}
	}

	// Check lessThan upper bound (exclusive)
	if lessThan != "" {
		cmp, parsed := compareWithScheme(scheme, version, lessThan)
		if parsed && cmp < 0 {
			return true, true
		}
		if !parsed && version < lessThan {
			return true, false
		}
		return false, parsed
	}

	// Check lessThanOrEqual upper bound (inclusive)
	if lessThanOrEqual != "" {
		cmp, parsed := compareWithScheme(scheme, version, lessThanOrEqual)
		if parsed && cmp <= 0 {
			return true, true
		}
		if !parsed && version <= lessThanOrEqual {
			return true, false
		}
		return false, parsed
	}

	// No upper bound — if we got here, lower bound passed
	return lowerBound != "", true
}

func pickScheme(versionType, ecosystem string) string {
	vt := strings.ToLower(versionType)
	if vt == "semver" || vt == "npm" || vt == "cargo" || vt == "golang" || vt == "nuget" || vt == "composer" || vt == "hex" || vt == "pub" || vt == "swift" {
		return "semver"
	}
	if vt == "pep440" || vt == "python" || vt == "pypi" {
		return "pep440"
	}
	if vt == "maven" || vt == "java" {
		return "maven"
	}

	eco := strings.ToLower(ecosystem)
	switch eco {
	case "npm", "cargo", "golang", "go", "nuget", "composer", "hex", "pub", "swift":
		return "semver"
	case "pypi", "pip", "python":
		return "pep440"
	case "maven", "java":
		return "maven"
	default:
		return "generic"
	}
}

func compareWithScheme(scheme, a, b string) (int, bool) {
	switch scheme {
	case "semver":
		return compareSemver(a, b)
	case "pep440":
		return comparePEP440(a, b)
	case "maven":
		return compareMaven(a, b)
	default:
		return compareGeneric(a, b)
	}
}

// ── Semver (Masterminds/semver/v3) ──────────────────────────────────────────

func compareSemver(a, b string) (int, bool) {
	if a == "" || b == "" {
		return 0, false
	}
	va, err := semver.NewVersion(normalizeSemver(a))
	if err != nil {
		return 0, false
	}
	vb, err := semver.NewVersion(normalizeSemver(b))
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

func normalizeSemver(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

// ── PEP 440 (aquasecurity/go-pep440-version) ────────────────────────────────

func comparePEP440(a, b string) (int, bool) {
	va, err := pep440.Parse(a)
	if err != nil {
		return 0, false
	}
	vb, err := pep440.Parse(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// ── Maven (masahiro331/go-mvn-version) ──────────────────────────────────────

func compareMaven(a, b string) (int, bool) {
	va, err := mvn.NewVersion(a)
	if err != nil {
		return 0, false
	}
	vb, err := mvn.NewVersion(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// ── Generic fallback ────────────────────────────────────────────────────────
// Hand-rolled normaliser: split on . / - / +, numeric segments compared as
// ints, alpha lexically, numeric < alpha for pre-release ordering.

func compareGeneric(a, b string) (int, bool) {
	sa := splitVersion(a)
	sb := splitVersion(b)
	maxLen := len(sa)
	if len(sb) > maxLen {
		maxLen = len(sb)
	}
	for i := 0; i < maxLen; i++ {
		var pa, pb string
		if i < len(sa) {
			pa = sa[i]
		}
		if i < len(sb) {
			pb = sb[i]
		}
		cmp := compareSegment(pa, pb)
		if cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func splitVersion(v string) []string {
	// Split on . - + _
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '+' || r == '_'
	})
}

func compareSegment(a, b string) int {
	aNum, aIsNum := parseNumeric(a)
	bNum, bIsNum := parseNumeric(b)

	if aIsNum && bIsNum {
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
		return 0
	}
	if aIsNum && !bIsNum {
		// numeric < alpha (pre-release ordering)
		if b == "" {
			return 1 // 1.0 > 1.0-
		}
		return -1
	}
	if !aIsNum && bIsNum {
		if a == "" {
			return -1 // 1.0- < 1.0
		}
		return 1
	}
	return strings.Compare(a, b)
}

func parseNumeric(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
