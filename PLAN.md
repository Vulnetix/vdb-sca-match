# PLAN — `vdb-sca-match`

The dependency→CVE matching engine. Given one resolved dependency, it returns every CVE that
affects it — by four methods — recording **which method matched**. It owns the multi-ecosystem
version comparator that does not exist anywhere in the Vulnetix codebase today (verified: no
semver/version library in `vdb-api` or `vdb-api-cyclonedx-uploads` go.mod; `/v2/cli.sca` relies on
pre-computed `PackageVersionCVE` rows).

## Why this module exists
- `vdb-sca-monitor`'s consumer re-evaluates each dependency against the **current** VDB and needs a
  real "version lower-than-fixed / within affected range" decision.
- The same engine is wired into `vdb-api-cyclonedx-uploads` (`LookupComponentCVEs`) and `vdb-api`
  `/v2/cli.sca` (`lookupVulnsForPurl`) so all three paths match identically.
- Consumed as a **sibling Go module** via `replace github.com/Vulnetix/vdb-sca-match =>
  ../vdb-sca-match`, cloned at container-build time (the `ietf-crit-spec` pattern).

## go.mod
```
module github.com/Vulnetix/vdb-sca-match
go 1.25.0
require (
    github.com/jackc/pgx/v5 v5.9.1
    github.com/Masterminds/semver/v3 v3.x          // semver-family ordering
    github.com/aquasecurity/go-pep440-version v0.x // PyPI / PEP 440
    github.com/masahiro331/go-mvn-version v0.x      // Maven ordering
)
```

## File tree
```
vdb-sca-match/
├── go.mod
├── README.md
├── PLAN.md            // this file
├── querier.go        // Querier interface (pgxpool.Pool & pgx.Tx both satisfy)
├── dependency.go     // Dependency input struct
├── match.go          // Match struct + MatchDependency orchestrator
├── versionrange.go   // method "version-range:*" (CVEAffected + CVEAffectedVersion)
├── purl.go           // method "purl" (PackageVersionCVE registry-precise)
├── cpe.go            // method "cpe" (CVEAffected.cpes / CVEMetadata.cpesJSON ILIKE)
├── crit.go           // method "crit" (CritRecord over already-matched cveIds)
├── match_test.go     // method-level tests against a stub Querier
├── versionrange_test.go
└── version/
    ├── compare.go    // Compare + Within: ecosystem-dispatched ordering + parse-ok signal
    └── compare_test.go
```

## Querier abstraction (`querier.go`)
Lets every repo pass its `*pgxpool.Pool` (or a `pgx.Tx`) unchanged:
```go
package match
import (
    "context"
    "github.com/jackc/pgx/v5"
)
type Querier interface {
    Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
    QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
```

## Input + output (`dependency.go`, `match.go`)
```go
type Dependency struct {
    Key, Name, Version, Ecosystem, Purl, Cpe string
}

type Match struct {
    CveID, Source   string
    Method          string // "version-range:lessThan" | "version-range:lessThanOrEqual" |
                            // "version-range:exact" | "purl" | "cpe" | "crit"
    VulnerableRange string // the range expression that matched → Finding.vulnerableVersionRange
}

// MatchDependency runs version-range + purl + cpe, gathers matched cveIds, then runs crit over
// them. Every method fails soft (log + skip on its own error). Returns one Match per (cveId,
// method); a cveId reached by several methods yields several Match rows so the caller can fold the
// methods into Triage.analysisDetail.
func MatchDependency(ctx context.Context, q Querier, dep Dependency) ([]Match, error)
```

## Method 1 — version-range (`versionrange.go`)
Candidates from `CVEAffected` ⋈ `CVEAffectedVersion`, keyed by package name + ecosystem (mirrors
the `CVEAffected` fallback at `vdb-api/internal/handler/v2_cli_sca.go:399-404`):
```sql
-- $1 = dep.Name   $2 = dep.Ecosystem
SELECT ca."cveId", ca.source,
       cav.version, cav.status, cav."versionType", cav."lessThan", cav."lessThanOrEqual"
FROM "CVEAffected" ca
JOIN "CVEAffectedVersion" cav ON cav."affectedId" = ca.uuid
WHERE LOWER(COALESCE(ca."packageName", ca.product)) = LOWER($1)
  AND ($2 = '' OR ca."collectionURL" ILIKE '%' || LOWER($2) || '%' OR ca."collectionURL" IS NULL)
LIMIT 1000;
```
Decision per row via `version.Within`, scheme from `cav.versionType`:
- `status='affected'` AND `version == dep.Version` → `version-range:exact`.
- `lessThan != ''` AND `Compare(dep.Version, lessThan) < 0` → `version-range:lessThan` ("lower
  than fixed"); range string `">= "+version+", < "+lessThan` when a lower bound exists.
- `lessThanOrEqual != ''` AND `Compare(dep.Version, lessThanOrEqual) <= 0` →
  `version-range:lessThanOrEqual`.
- Prefer rows with `isValidVersion = true` when the column is present.
- `Compare` returns `ok=false` (unparseable) → **conservative**: match only on exact string
  equality with `status='affected'`; otherwise skip + log. (Precision over recall.)

## Method 2 — purl (`purl.go`)
Registry-precise, mirrors `lookupVulnsForPurl` primary path (`v2_cli_sca.go:370-378`):
```sql
-- $1=ecosystem $2=fullName $3=version  (from ParsePurl on dep.Purl)
SELECT pvc."cveId", COALESCE(cm.source,'mitre')
FROM "PackageVersionCVE" pvc
JOIN "PackageVersion" pv ON pv.uuid = pvc."packageVersionId"
LEFT JOIN "CVEMetadata" cm ON cm."cveId" = pvc."cveId"
WHERE LOWER(pv.ecosystem) = LOWER($1)
  AND LOWER(pv."packageName") = LOWER($2)
  AND ($3 = '' OR pv.version = $3)
  AND pvc."relationshipType" IN ('affects','vulnerable')
LIMIT 500;
```
Method `"purl"`; range from `pvc.versionRange` when present. (PURL parsing reuses
`vdb-cyclonedx.ParsePurl` or a local copy.)

## Method 3 — cpe (`cpe.go`)
Only when `dep.Cpe != ""`. Reduce the CPE 2.3 string to a `cpe:2.3:a:vendor:product%` prefix:
```sql
-- $1 = 'cpe:2.3:a:vendor:product%'
SELECT DISTINCT "cveId", source FROM "CVEAffected" WHERE cpes ILIKE $1
UNION
SELECT DISTINCT "cveId", source FROM "CVEMetadata" WHERE "cpesJSON" ILIKE $1
LIMIT 500;
```
Method `"cpe"` (coarse, no version math — lower confidence; surfaced in `analysisDetail` so it's
auditable).

## Method 4 — crit (`crit.go`)
`CritRecord` is keyed `(cveId, provider, service, resourceType)` with **no package/purl/cpe
column** (`saas/prisma/models/crit.prisma`) — so CRIT can only **tag** cveIds already matched by
the other methods, never discover from a dependency:
```sql
-- $1 = matchedCveIds (text[])
SELECT "cveId", provider, service, "resourceType", "vectorString"
FROM "CritRecord" WHERE "cveId" = ANY($1);
```
Method `"crit"`.

## Version comparison (`version/compare.go`) — the only genuinely new algorithm
```go
package version

// cmp ∈ {-1,0,1}; ok=false ⇒ unparseable under this scheme ⇒ caller falls back to exact match.
func Compare(ecosystem, versionType, a, b string) (cmp int, ok bool)

// Within encapsulates the range check used by versionrange.go.
func Within(ecosystem, versionType, version, lowerBound, lessThan, lessThanOrEqual string) (inRange bool, ok bool)
```
Scheme dispatch — prefer `versionType` (`CVEAffectedVersion.versionType`: `semver`/`pep440`/
`git`/…), fall back to `ecosystem`:
- **semver family** (npm, cargo, golang, nuget, composer, hex, pub, swift) →
  `github.com/Masterminds/semver/v3` (`NewVersion` tolerates `v` prefix + missing patch).
- **pypi** → `github.com/aquasecurity/go-pep440-version`.
- **maven** → `github.com/masahiro331/go-mvn-version`.
- **fallback** (deb/rpm/apk/gem/generic/unknown) → hand-rolled normaliser: split on `.`/`-`/`+`,
  numeric segments compared as ints, alpha lexically, numeric < alpha for pre-release ordering.

Supersedes the dropped `compareSemver`/`semverParts` from the old CycloneDX parser.

## Unit tests (`version/compare_test.go`) — green before any wiring
- npm `4.17.20 < 4.17.21`; cargo `1.0.0-alpha < 1.0.0`.
- pep440 `1.0.0.post1 > 1.0.0`; `1.0.0.dev1 < 1.0.0`.
- go `v1.6.3 < v1.7.0`.
- maven `1.0-SNAPSHOT < 1.0`.
- generic `1.2.10 > 1.2.9` (int segments, not lexical).
- unparseable `latest`, `*`, `^1.0` → `ok=false`.
- `Within`: lessThan/lessThanOrEqual/exact boundary cases incl. lower-bound gating.

## Wiring into existing repos (after `compare_test` is green)
- **`vdb-api-cyclonedx-uploads`** — `internal/db/vulnlookup.go:50` `LookupComponentCVEs`: build a
  `match.Dependency` and union `MatchDependency`'s cveIds with the existing registry result;
  downstream `EnrichCVE` (already ported, `vulnlookup.go:106`) unchanged.
- **`vdb-api`** — `internal/handler/v2_cli_sca.go:360` `lookupVulnsForPurl`: same augmentation.
  Its Containerfile already clones one sibling (ietf-crit-spec) — add a second clone.

## Risks specific to this module
1. **Version ordering correctness** (highest) — Maven and distro (deb/rpm/apk) ordering are hard;
   the conservative "unparseable → exact-match-only" policy favors precision. Filter
   `CVEAffectedVersion.isValidVersion = true` when available.
2. **CRIT** tags only — never discovers from a dependency.
3. **CPE** matching is coarse (vendor:product prefix, no version math) — lower confidence.

## Source references
- `vdb-api/internal/handler/v2_cli_sca.go` (`lookupVulnsForPurl`, the `CVEAffected`/`PackageVersionCVE`
  query shapes, `enrichCves` for downstream context).
- `saas/prisma/models/cve.prisma` (`CVEAffected`, `CVEAffectedVersion.versionType/lessThan/
  lessThanOrEqual/isValidVersion`), `crit.prisma` (`CritRecord`).

## Companion plans
- `vdb-cyclonedx/PLAN.md` — the CycloneDX parser module.
- `~/.claude/plans/create-a-new-repo-distributed-wolf.md` and `Vulnetix/PLAN.md` — the
  `vdb-sca-monitor` service that consumes both modules.
