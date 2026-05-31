package match

import (
	"context"
)

// matchCrit looks up CritRecord entries for the given CVE IDs.
// CRIT only tags — it never discovers new CVEs from a dependency.
func matchCrit(ctx context.Context, q Querier, cveIds []string) ([]string, error) {
	if len(cveIds) == 0 {
		return nil, nil
	}

	rows, err := q.Query(ctx, `
		SELECT DISTINCT "cveId"
		FROM "CritRecord"
		WHERE "cveId" = ANY($1)`,
		cveIds,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}
