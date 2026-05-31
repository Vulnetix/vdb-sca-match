package match

import (
	"context"
	"fmt"
	"strings"
)

// matchCPE queries CVEAffected.cpes and CVEMetadata.cpesJSON for CPE prefix matches.
// This is coarse matching — lower confidence, surfaced in analysisDetail for auditability.
func matchCPE(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	if dep.Cpe == "" {
		return nil, nil
	}

	// Extract vendor:product from CPE 2.3 URI
	// cpe:2.3:a:vendor:product:version:*:*:*:*:*:*
	prefix := cpePrefix(dep.Cpe)
	if prefix == "" {
		return nil, nil
	}

	// Query CVEAffected.cpes
	rows, err := q.Query(ctx, `
		SELECT DISTINCT "cveId"
		FROM "CVEAffected"
		WHERE cpes ILIKE $1
		LIMIT 200`,
		prefix+"%",
	)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var matches []Match
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		if _, dup := seen[cveID]; dup {
			continue
		}
		seen[cveID] = struct{}{}
		matches = append(matches, Match{
			CveID:  cveID,
			Source: "CVEAffected.cpes",
			Method: "cpe",
		})
	}
	rows.Close()

	// Also query CVEMetadata.cpesJSON
	rows2, err := q.Query(ctx, `
		SELECT DISTINCT "cveId"
		FROM "CVEMetadata"
		WHERE "cpesJSON" ILIKE $1
		LIMIT 200`,
		prefix+"%",
	)
	if err != nil {
		return matches, nil // return what we have
	}
	defer rows2.Close()

	for rows2.Next() {
		var cveID string
		if err := rows2.Scan(&cveID); err != nil {
			continue
		}
		if _, dup := seen[cveID]; dup {
			continue
		}
		seen[cveID] = struct{}{}
		matches = append(matches, Match{
			CveID:  cveID,
			Source: "CVEMetadata.cpesJSON",
			Method: "cpe",
		})
	}

	return matches, nil
}

// cpePrefix extracts the vendor:product prefix from a CPE 2.3 URI.
// cpe:2.3:a:vendor:product:version:*:*:*:*:*:* → "cpe:2.3:a:vendor:product"
func cpePrefix(cpe string) string {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return ""
	}
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return ""
	}
	// parts[0]=cpe, [1]=2.3, [2]=part, [3]=vendor, [4]=product
	return fmt.Sprintf("cpe:2.3:%s:%s:%s", parts[2], parts[3], parts[4])
}
