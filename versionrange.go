package match

import (
	"context"
	"strings"

	ver "github.com/Vulnetix/vdb-sca-match/version"
)

// matchVersionRange queries CVEAffected + CVEAffectedVersion for candidates
// keyed by package name and ecosystem, then decides affected status via
// version range comparison.
func matchVersionRange(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	if dep.Name == "" {
		return nil, nil
	}

	// cveId/source live on CVEAffected (ca); the version bounds live on
	// CVEAffectedVersion (cav). The version column is named "version" (not
	// "versionValue"), and CVEAffectedVersion has no cveId of its own.
	rows, err := q.Query(ctx, `
		SELECT ca."cveId", ca.source, cav.status, cav."versionType",
		       cav.version, cav."lessThan", cav."lessThanOrEqual",
		       cav."isValidVersion"
		FROM "CVEAffected" ca
		JOIN "CVEAffectedVersion" cav ON ca.uuid = cav."affectedId"
		WHERE LOWER(COALESCE(ca."packageName", ca.product)) = LOWER($1)
		  AND ($2 = '' OR LOWER(ca."collectionURL") LIKE '%' || LOWER($2) || '%')
		LIMIT 500`,
		dep.Name, dep.Ecosystem,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []Match
	for rows.Next() {
		var cveID, source, status string
		var versionType, versionValue, lessThan, lessThanOrEqual *string
		var isValidVersion *bool
		if err := rows.Scan(&cveID, &source, &status, &versionType, &versionValue, &lessThan, &lessThanOrEqual, &isValidVersion); err != nil {
			continue
		}

		// Skip if version is marked invalid
		if isValidVersion != nil && !*isValidVersion {
			continue
		}

		vt := ""
		if versionType != nil {
			vt = *versionType
		}
		if vt == "" {
			vt = dep.Ecosystem
		}

		matched, method := decideVersionRange(dep.Version, status, vt, versionValue, lessThan, lessThanOrEqual)
		if matched {
			src := source
			if src == "" {
				src = "CVEAffected"
			}
			matches = append(matches, Match{
				CveID:           cveID,
				Source:          src,
				Method:          method,
				VulnerableRange: buildRangeString(versionValue, lessThan, lessThanOrEqual),
			})
		}
	}
	return matches, nil
}

func decideVersionRange(version, status, versionType string, versionValue, lessThan, lessThanOrEqual *string) (bool, string) {
	if version == "" {
		return false, ""
	}

	switch strings.ToLower(status) {
	case "affected":
		// Exact version match
		if versionValue != nil && *versionValue != "" {
			cmp, ok := ver.Compare("", versionType, version, *versionValue)
			if ok && cmp == 0 {
				return true, "version-range:exact"
			}
			// If unparseable, fall back to string equality
			if !ok && version == *versionValue {
				return true, "version-range:exact"
			}
		}
		// Range check: version < lessThan
		if lessThan != nil && *lessThan != "" {
			cmp, ok := ver.Compare("", versionType, version, *lessThan)
			if ok && cmp < 0 {
				return true, "version-range:lessThan"
			}
			if !ok && version < *lessThan {
				return true, "version-range:lessThan"
			}
		}
		// Range check: version <= lessThanOrEqual
		if lessThanOrEqual != nil && *lessThanOrEqual != "" {
			cmp, ok := ver.Compare("", versionType, version, *lessThanOrEqual)
			if ok && cmp <= 0 {
				return true, "version-range:lessThanOrEqual"
			}
			if !ok && version <= *lessThanOrEqual {
				return true, "version-range:lessThanOrEqual"
			}
		}
	}
	return false, ""
}

func buildRangeString(versionValue, lessThan, lessThanOrEqual *string) string {
	parts := []string{}
	if versionValue != nil && *versionValue != "" {
		parts = append(parts, ">="+*versionValue)
	}
	if lessThan != nil && *lessThan != "" {
		parts = append(parts, "<"+*lessThan)
	}
	if lessThanOrEqual != nil && *lessThanOrEqual != "" {
		parts = append(parts, "<="+*lessThanOrEqual)
	}
	return strings.Join(parts, ", ")
}
