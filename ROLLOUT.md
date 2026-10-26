# v6 refresh rollout

Published [tc-core-library-js v4.0.0-rc.1](https://github.com/topcoder-platform/tc-core-library-js/releases/tag/v4.0.0-rc.1) from commit `6c326fea0abfccb5ae29dff2ac5bce01aabc1fa4` on `v6-refresh`. [Core draft PR #7](https://github.com/topcoder-platform/tc-core-library-js/pull/7) targets master. The release includes the package tarball, compiled CommonJS output and TypeScript declarations.

All 28 requested services are committed on `v6-refresh`. The 26 services with configured remotes are pushed and have draft PRs targeting their development branches. Contact and QA are committed locally because their repositories have no configured remote. Original service checkouts and existing edits were preserved; migration worktrees are under `/home/jmgasper/Documents/Git/v6/_worktrees/v6-refresh/`.

## Validation

- Library lint, build and all 14 security/client tests pass. Its production dependency audit reports no known vulnerabilities.
- Lint and build pass in all 28 service worktrees using each project's `nvm use` and package manager.
- 361 targeted service tests pass across 18 services after installing the released package. Contact additionally reports 11 skipped environment-dependent checks.
- No old bus wrapper, old core version or temporary local package reference remains in the scoped dependency lockfiles. Challenge's Forums client and Finance's Billing Accounts client are pinned to matching refresh commits to remove their old transitive dependencies.
- Identity's broader pre-existing auth-flow suite still has 21 failures (35 pass), and its two-factor suite has fixture compilation errors. Both results were reproduced on unchanged `origin/develop` (`ccde1d3`). The new JWT/cache and updated event module tests pass.

## Deployment status

The branches and draft PRs are ready for development review; they have not been merged or deployed. Configure trusted issuers, RSA audiences and HMAC secrets of at least 32 bytes as described in [MIGRATION.md](MIGRATION.md). Autopilot's local login also requires explicit credentials. Development smoke tests should cover real human and machine tokens, the active-session check and representative published events.

The GitHub release is published. npm version `4.0.0-rc.1` was not available when checked, and this workstation has no npm publishing credentials. CircleCI is configured to publish tagged prereleases using its existing `NPM_TOKEN`; all service branches use the GitHub release and do not depend on npm publication.

The old bus wrapper repository has not been archived. Archive it after development rollout and review of out-of-scope consumers.

## Service branches

Every row passed lint and build. Test counts are the focused suites run for this migration, not a claim that the entire service test suite was run.

| Service | Development base | Commit | Draft PR | Targeted tests passed |
| --- | --- | --- | --- | --- |
| autopilot-v6 | develop | [cd55cc5d2](https://github.com/topcoder-platform/autopilot-v6/commit/cd55cc5d2abf8e8f18bdb2834df3112934de1b41) | [#72](https://github.com/topcoder-platform/autopilot-v6/pull/72) | 2 |
| av-scanner-v6 | develop | [3fa1e5a9f](https://github.com/topcoder-platform/av-scanner-v6/commit/3fa1e5a9f03141bf5ca7067712b7b2713dca1131) | [#7](https://github.com/topcoder-platform/av-scanner-v6/pull/7) | 92 |
| billing-accounts-api-v6 | develop | [74b3b02d6](https://github.com/topcoder-platform/billing-accounts-api-v6/commit/74b3b02d6d60307531b4206f4fafa9509d113f24) | [#32](https://github.com/topcoder-platform/billing-accounts-api-v6/pull/32) | Not run |
| bus-api-v6 | develop | [8b797f63e](https://github.com/topcoder-platform/bus-api-v6/commit/8b797f63e47ee057a51c822a7d427717df02fd1f) | [#9](https://github.com/topcoder-platform/bus-api-v6/pull/9) | 20 |
| challenge-api-v6 | develop | [3b79058d1](https://github.com/topcoder-platform/challenge-api-v6/commit/3b79058d11d65b24c6f89e11f80138750cef2935) | [#168](https://github.com/topcoder-platform/challenge-api-v6/pull/168) | 2 |
| contact-api-v6 | local HEAD | `668987b0f` | Local only — no remote | 46 |
| email-service-v6 | develop | [2fe271614](https://github.com/topcoder-platform/email-service-v6/commit/2fe2716144fa632a6dc73030f40a0672eb3a3387) | [#6](https://github.com/topcoder-platform/email-service-v6/pull/6) | Not run |
| engagements-api-v6 | develop | [63fe4e448](https://github.com/topcoder-platform/engagements-api-v6/commit/63fe4e4483d74cd28e37479a4b16c852cc040514) | [#86](https://github.com/topcoder-platform/engagements-api-v6/pull/86) | 6 |
| forms-api-v6 | develop | [d3731308f](https://github.com/topcoder-platform/forms-api-v6/commit/d3731308f5e8291d0939acd259aa0a66a7557cd5) | [#11](https://github.com/topcoder-platform/forms-api-v6/pull/11) | 43 |
| forms-processor-v6 | develop | [7911f5456](https://github.com/topcoder-platform/forms-processor-v6/commit/7911f5456d6cffcf206786334f25e78157c6da47) | [#5](https://github.com/topcoder-platform/forms-processor-v6/pull/5) | 31 |
| forums-api-v6 | develop | [5e116b3e9](https://github.com/topcoder-platform/forums-api-v6/commit/5e116b3e9f28461a2f670c34edbfc761026716d7) | [#24](https://github.com/topcoder-platform/forums-api-v6/pull/24) | 13 |
| groups-api-v6 | develop | [1661c9dd4](https://github.com/topcoder-platform/groups-api-v6/commit/1661c9dd403d6d3a5dc8d8d3b76581975afbf6d8) | [#15](https://github.com/topcoder-platform/groups-api-v6/pull/15) | 24 |
| identity-api-v6 | develop | [9273dce31](https://github.com/topcoder-platform/identity-api-v6/commit/9273dce31ee035ac01d1aba6727adf1f8408d29c) | [#54](https://github.com/topcoder-platform/identity-api-v6/pull/54) | 10 |
| leave-api-v6 | develop | [52001e56a](https://github.com/topcoder-platform/leave-api-v6/commit/52001e56a80bb9f7ac3cf5907ff69d61584f1153) | [#12](https://github.com/topcoder-platform/leave-api-v6/pull/12) | Not run |
| lookups-api-v6 | develop | [c4d04f529](https://github.com/topcoder-platform/lookups-api-v6/commit/c4d04f52911fed001882b4eef6a34b87098c4c33) | [#10](https://github.com/topcoder-platform/lookups-api-v6/pull/10) | Not run |
| marathon-match-api-v6 | develop | [2eeab8d63](https://github.com/topcoder-platform/marathon-match-api-v6/commit/2eeab8d63174cd4797f3b8dc9d62449494a873d3) | [#450](https://github.com/topcoder-platform/marathon-match-api-v6/pull/450) | 14 |
| member-api-v6 | develop | [f61f76356](https://github.com/topcoder-platform/member-api-v6/commit/f61f763565da55de67b1fade67c787a370209930) | [#168](https://github.com/topcoder-platform/member-api-v6/pull/168) | Not run |
| opportunities-api-v6 | develop | [fab9a65aa](https://github.com/topcoder-platform/opportunities-api-v6/commit/fab9a65aae0f97a110eedc8ffef8464792b77e84) | [#5](https://github.com/topcoder-platform/opportunities-api-v6/pull/5) | Not run |
| procurement-api-v6 | develop | [0b4af22d1](https://github.com/topcoder-platform/procurement-api-v6/commit/0b4af22d1a29f721591ceaa185246b84563dc3a9) | [#5](https://github.com/topcoder-platform/procurement-api-v6/pull/5) | Not run |
| projects-api-v6 | dev | [4499e720c](https://github.com/topcoder-platform/projects-api-v6/commit/4499e720c5d51ec4c26cdddf573b335507b03119) | [#59](https://github.com/topcoder-platform/projects-api-v6/pull/59) | 11 |
| qa-v6 | local HEAD | `8c1e893d7` | Local only — no remote | Not run |
| reports-api-v6 | develop | [3c35330f5](https://github.com/topcoder-platform/reports-api-v6/commit/3c35330f5aaf333784dcc907ab600c1c4a0872ed) | [#186](https://github.com/topcoder-platform/reports-api-v6/pull/186) | Not run |
| resource-api-v6 | develop | [4b0b3c7f7](https://github.com/topcoder-platform/resource-api-v6/commit/4b0b3c7f7e6cc539a9bd132a5e4225ec34437813) | [#35](https://github.com/topcoder-platform/resource-api-v6/pull/35) | Not run |
| review-api-v6 | develop | [b5754ae58](https://github.com/topcoder-platform/review-api-v6/commit/b5754ae58d1f9030bc14f5e521a204a1fd081b75) | [#375](https://github.com/topcoder-platform/review-api-v6/pull/375) | 1 |
| standardized-skills-api | develop | [9ec3c76e5](https://github.com/topcoder-platform/standardized-skills-api/commit/9ec3c76e5a06aa279a806f3aa423572b5106acbb) | [#137](https://github.com/topcoder-platform/standardized-skills-api/pull/137) | 2 |
| status-api-v6 | develop | [e65bf4ba3](https://github.com/topcoder-platform/status-api-v6/commit/e65bf4ba3c8e32aff4a15cda0524e1d112ec61f4) | [#4](https://github.com/topcoder-platform/status-api-v6/pull/4) | 20 |
| support-api-v6 | develop | [241127f6a](https://github.com/topcoder-platform/support-api-v6/commit/241127f6af4a882fcd930fc670c5b364b90bde88) | [#18](https://github.com/topcoder-platform/support-api-v6/pull/18) | 13 |
| tc-finance-api | dev | [d262ae673](https://github.com/topcoder-platform/tc-finance-api/commit/d262ae673a4b46d5bc9a902eaf279cffe50c9414) | [#210](https://github.com/topcoder-platform/tc-finance-api/pull/210) | 11 |
