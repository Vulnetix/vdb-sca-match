# vdb-sca-match

Dependency→CVE matching engine for Go. Given one resolved dependency, returns every CVE that
affects it — by four methods, recording which method matched:

- **version-range** — `CVEAffected` / `CVEAffectedVersion` with a real multi-ecosystem version
  comparator (semver, PEP 440, Maven, generic fallback): "version lower than fixed" / "within
  affected range".
- **purl** — registry-precise via `PackageVersionCVE`.
- **cpe** — `CVEAffected.cpes` / `CVEMetadata.cpesJSON` prefix match.
- **crit** — `CritRecord` tagging over already-matched CVEs.

```go
import match "github.com/Vulnetix/vdb-sca-match"

matches, err := match.MatchDependency(ctx, pool, match.Dependency{
    Name: "lodash", Version: "4.17.20", Ecosystem: "npm",
    Purl: "pkg:npm/lodash@4.17.20",
})
// each Match carries CveID, Source, Method, VulnerableRange
```

`pool` is any `*pgxpool.Pool` (or `pgx.Tx`) — both satisfy the `Querier` interface.

Shared across `vdb-sca-monitor`, `vdb-api-cyclonedx-uploads`, and `vdb-api` (`/v2/cli.sca`).
Consumed as a sibling module via `replace github.com/Vulnetix/vdb-sca-match => ../vdb-sca-match`
(the `ietf-crit-spec` pattern), cloned at container-build time.

See [PLAN.md](./PLAN.md) for the full design, SQL, and version-comparator spec.

## Status

Scaffold + plan. Implements the version comparator first (`version/compare_test.go` green), then
the four match methods.
