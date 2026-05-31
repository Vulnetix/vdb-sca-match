package match

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Querier is the minimal database interface needed by the matching engine.
// Both *pgxpool.Pool and pgx.Tx satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}
