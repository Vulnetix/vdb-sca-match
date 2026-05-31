package match

import (
	"context"
	"log"
)

// Match represents one CVE matched against a dependency.
type Match struct {
	CveID           string
	Source          string
	Method          string // e.g. "version-range:lessThan", "purl", "cpe", "crit"
	VulnerableRange string // the range expression that matched
}

// MatchDependency runs all match methods for a single dependency and returns
// the union of matched CVEs. Each method fails soft (log+skip) so one bad path
// can't drop the dependency.
func MatchDependency(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	seen := map[string]Match{}

	// 1. version-range matching (primary)
	if m, err := matchVersionRange(ctx, q, dep); err != nil {
		log.Printf("[match] version-range error for %s: %v", dep.Key, err)
	} else {
		for _, mm := range m {
			seen[mm.CveID] = mm
		}
	}

	// 2. PURL-based registry lookup (precise)
	if m, err := matchPurl(ctx, q, dep); err != nil {
		log.Printf("[match] purl error for %s: %v", dep.Key, err)
	} else {
		for _, mm := range m {
			seen[mm.CveID] = mm
		}
	}

	// 3. CPE matching (coarse, only if CPE present)
	if dep.Cpe != "" {
		if m, err := matchCPE(ctx, q, dep); err != nil {
			log.Printf("[match] cpe error for %s: %v", dep.Key, err)
		} else {
			for _, mm := range m {
				seen[mm.CveID] = mm
			}
		}
	}

	// 4. CRIT tagging (only over already-matched cveIds)
	if len(seen) > 0 {
		cveIds := make([]string, 0, len(seen))
		for id := range seen {
			cveIds = append(cveIds, id)
		}
		if critIds, err := matchCrit(ctx, q, cveIds); err != nil {
			log.Printf("[match] crit error for %s: %v", dep.Key, err)
		} else {
			for _, id := range critIds {
				if m, ok := seen[id]; ok {
					m.Method = appendMethod(m.Method, "crit")
					seen[id] = m
				}
			}
		}
	}

	out := make([]Match, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	return out, nil
}

func appendMethod(existing, method string) string {
	if existing == "" {
		return method
	}
	return existing + "," + method
}
