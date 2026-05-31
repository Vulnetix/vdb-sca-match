package match

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── fake Querier / Rows ─────────────────────────────────────────────────────
// A reflection-free stand-in for *pgxpool.Pool. It routes each query to a
// canned row set by table name and decodes into the dest pointer types the
// engine actually uses (*string, **string, **bool). It does NOT validate SQL —
// column-name correctness is verified by review + integration tests.

type fakeRows struct {
	rows [][]any
	idx  int
}

func (r *fakeRows) Next() bool {
	if r.idx < len(r.rows) {
		r.idx++
		return true
	}
	return false
}

func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	for i, d := range dest {
		var v any
		if i < len(row) {
			v = row[i]
		}
		switch p := d.(type) {
		case *string:
			if v == nil {
				*p = ""
			} else {
				*p = v.(string)
			}
		case **string:
			if v == nil {
				*p = nil
			} else {
				s := v.(string)
				*p = &s
			}
		case **bool:
			if v == nil {
				*p = nil
			} else {
				b := v.(bool)
				*p = &b
			}
		default:
			return fmt.Errorf("fakeRows: unsupported dest type %T", d)
		}
	}
	return nil
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

type fakeQuerier struct {
	versionRange [][]any
	purl         [][]any
	cpeAffected  [][]any
	cpeMetadata  [][]any
	crit         [][]any
}

func (f *fakeQuerier) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	switch {
	case strings.Contains(sql, "CVEAffectedVersion"):
		return &fakeRows{rows: f.versionRange}, nil
	case strings.Contains(sql, "PackageVersionCVE"):
		return &fakeRows{rows: f.purl}, nil
	case strings.Contains(sql, "CritRecord"):
		return &fakeRows{rows: f.crit}, nil
	case strings.Contains(sql, "CVEMetadata"):
		return &fakeRows{rows: f.cpeMetadata}, nil
	case strings.Contains(sql, "CVEAffected"):
		return &fakeRows{rows: f.cpeAffected}, nil
	}
	return &fakeRows{}, nil
}

type errRow struct{}

func (errRow) Scan(_ ...any) error { return fmt.Errorf("not implemented") }

func (f *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row { return errRow{} }

// ── tests ───────────────────────────────────────────────────────────────────

func methodsByCve(ms []Match) map[string]Match {
	out := map[string]Match{}
	for _, m := range ms {
		out[m.CveID] = m
	}
	return out
}

// A CVE reached by version-range + purl + crit must fold all methods into one
// Match, keeping the version-range's VulnerableRange.
func TestMatchDependency_MergesMethods(t *testing.T) {
	q := &fakeQuerier{
		// ca.cveId, ca.source, cav.status, cav.versionType, cav.version, lessThan, lessThanOrEqual, isValidVersion
		versionRange: [][]any{
			{"CVE-1", "nvd", "affected", "semver", nil, "2.0.0", nil, nil},
		},
		purl: [][]any{
			{"CVE-1"}, {"CVE-2"},
		},
		crit: [][]any{
			{"CVE-1"},
		},
	}
	dep := Dependency{Name: "lodash", Version: "1.5.0", Ecosystem: "npm", Purl: "pkg:npm/lodash@1.5.0", Key: "k"}

	matches, err := MatchDependency(context.Background(), q, dep)
	if err != nil {
		t.Fatal(err)
	}
	byCve := methodsByCve(matches)
	if len(byCve) != 2 {
		t.Fatalf("expected 2 distinct CVEs, got %d: %+v", len(byCve), matches)
	}

	m1 := byCve["CVE-1"]
	parts := strings.Split(m1.Method, ",")
	sort.Strings(parts)
	gotMethod := strings.Join(parts, ",")
	if gotMethod != "crit,purl,version-range:lessThan" {
		t.Fatalf("CVE-1 methods = %q, want all of version-range:lessThan,purl,crit", m1.Method)
	}
	if m1.VulnerableRange != "<2.0.0" {
		t.Fatalf("CVE-1 VulnerableRange = %q, want %q (from version-range)", m1.VulnerableRange, "<2.0.0")
	}

	if byCve["CVE-2"].Method != "purl" {
		t.Fatalf("CVE-2 method = %q, want purl", byCve["CVE-2"].Method)
	}
}

// CPE matching must run only when the dependency carries a CPE.
func TestMatchDependency_CPEGatedOnPresence(t *testing.T) {
	q := &fakeQuerier{
		cpeAffected: [][]any{{"CVE-CPE"}},
	}

	// No CPE → CPE method must not run, so no CVE-CPE.
	noCPE := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm"}
	matches, _ := MatchDependency(context.Background(), q, noCPE)
	if _, ok := methodsByCve(matches)["CVE-CPE"]; ok {
		t.Fatalf("CPE match should not run without a CPE: %+v", matches)
	}

	// With CPE → CVE-CPE appears via the cpe method.
	withCPE := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm", Cpe: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
	matches, _ = MatchDependency(context.Background(), q, withCPE)
	m := methodsByCve(matches)["CVE-CPE"]
	if m.Method != "cpe" {
		t.Fatalf("expected cpe method for CVE-CPE, got %q (%+v)", m.Method, matches)
	}
}

// CRIT only tags CVEs already discovered — it never introduces new ones.
func TestMatchDependency_CritTagsOnly(t *testing.T) {
	q := &fakeQuerier{
		purl: [][]any{{"CVE-A"}},
		crit: [][]any{{"CVE-A"}, {"CVE-ORPHAN"}}, // CVE-ORPHAN not matched by any discovery method
	}
	dep := Dependency{Name: "x", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/x@1.0.0"}
	matches, _ := MatchDependency(context.Background(), q, dep)
	byCve := methodsByCve(matches)
	if _, ok := byCve["CVE-ORPHAN"]; ok {
		t.Fatalf("crit must not introduce CVE-ORPHAN: %+v", matches)
	}
	if got := byCve["CVE-A"].Method; got != "purl,crit" {
		t.Fatalf("CVE-A method = %q, want purl,crit", got)
	}
}

func TestCPEPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl"},
		{"cpe:2.3:o:linux:linux_kernel:5.0", "cpe:2.3:o:linux:linux_kernel"},
		{"cpe:/a:legacy:uri", ""}, // not 2.3
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := cpePrefix(c.in); got != c.want {
			t.Errorf("cpePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppendMethod(t *testing.T) {
	if got := appendMethod("", "purl"); got != "purl" {
		t.Fatalf("append to empty: %q", got)
	}
	if got := appendMethod("purl", "crit"); got != "purl,crit" {
		t.Fatalf("append new: %q", got)
	}
	if got := appendMethod("purl,crit", "purl"); got != "purl,crit" {
		t.Fatalf("append duplicate should be a no-op: %q", got)
	}
}
