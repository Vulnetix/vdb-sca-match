package match

import (
	"context"
)

// matchPurl queries PackageVersionCVE for registry-precise matches.
func matchPurl(ctx context.Context, q Querier, dep Dependency) ([]Match, error) {
	if dep.Purl == "" {
		return nil, nil
	}

	eco, fullName, version := ParsePurl(dep.Purl)
	if eco == "" || fullName == "" {
		return nil, nil
	}

	rows, err := q.Query(ctx, `
		SELECT pvc."cveId"
		FROM "PackageVersionCVE" pvc
		JOIN "PackageVersion" pv ON pv.uuid = pvc."packageVersionId"
		WHERE LOWER(pv.ecosystem) = LOWER($1)
		  AND LOWER(pv."packageName") = LOWER($2)
		  AND ($3 = '' OR pv.version = $3)
		  AND pvc."relationshipType" IN ('affects','vulnerable')
		LIMIT 200`,
		eco, fullName, version,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []Match
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		matches = append(matches, Match{
			CveID:  cveID,
			Source: "PackageVersionCVE",
			Method: "purl",
		})
	}
	return matches, nil
}
