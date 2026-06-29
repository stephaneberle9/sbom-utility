# CLAUDE.md

itemis-specific notes for this fork of CycloneDX/sbom-utility. Work happens on the `itemis` branch.

## License finding

When a component carries no license in the SBOM, licenses are resolved in this order
(see `cmd/license.go`):

1. **Well-known list** (`cmd/license_lookup_wellknown.go`) — a hard-coded fallback, keyed by
   group/name (version-agnostic), for components whose published artifacts advertise no usable
   license metadata.
2. **Finders** (`cmd/license_finder_{maven,npm,p2}.go`) — fetch the POM / `package.json` / Eclipse
   data and read the license from it.

The well-known list is a **stopgap, not the goal**. As soon as a published artifact advertises a
resolvable license, drop its entry from the well-known list and add a covering integration test —
the finder then resolves it directly. Every itemis entry in the well-known list should carry a
comment saying either why it can't be resolved (no/ non-canonical metadata) or which test covers
its finder resolution. `LicenseRef-itemis-Closed` is the canonical id for closed itemis components.

## itemis Nexus authentication

The Maven and npm finders make authenticated requests to the itemis Nexus
(`artifacts.itemis.cloud`) using the `NEXUS_USER` / `NEXUS_PASS` env vars. Basic Auth is
**host-gated** (`addNexusAuthIfApplicable` in `cmd/license_finder.go`) — credentials are never sent
to Maven Central, the public npm registry, or the Eclipse license check service. The private repos
/ registries searched are listed in `cmd/license_finder_maven.go` (`MAVEN_REPOSITORIES`) and
`cmd/license_finder_npm.go` (`NPM_REGISTRIES`).

These integration tests require `NEXUS_USER` / `NEXUS_PASS` (and network) and will fail without them:

- `TestFindLicenseOfMavenComponentInItemisMavenRepos`
- `TestFindLicenseOfNpmComponentInItemisNpmRegistries`

The finders persist results to `cmd/.maven-license-cache.dat` / `.npm-license-cache.dat`; delete
these before a test run to force a real fetch rather than a cached hit.

## Pending follow-up: SECURE libraries missing license metadata

Tracking issue: <https://gitlab.com/itemis/solutions/sec/secure-rcp/-/work_items/901>

These itemis SECURE artifacts still rely on the well-known list because, even in their latest
versions, they advertise no usable license. They are all published from
`itemis/solutions/sec/secure-rcp` (build files `calculation/build.gradle.kts` and
`ts-model/src/kotlin/build.gradle`):

- Maven: `com.itemis:com-itemis-secure`, `com-itemis-secure-jvm`, `com-itemis-secure-js`,
  `secure-calculation-jvm` (the last advertises a non-canonical `Internal Use Only - Proprietary`)
- npm: `@itemis-secure/calculation` (no license), `@itemis-secure/ts-model` (`UNLICENSED`)

When issue 901 is resolved (artifacts advertise `LicenseRef-itemis-Closed`), the cleanup is simply
to drop the corresponding entries from `cmd/license_lookup_wellknown.go` and add covering tests.
The finder can already reach these artifacts: secure-rcp publishes them to `maven-secure-releases`,
which is aggregated by the `maven-secure` group repo that is in `MAVEN_REPOSITORIES`.

Note: `com.itemis:com-itemis-secure-js` is **not** in the well-known list at all, so it currently
resolves to no license. Left as-is intentionally for now.
