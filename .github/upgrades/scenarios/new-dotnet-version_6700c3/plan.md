# .NET Version Upgrade Plan

Table of contents
- Executive Summary
- Migration Strategy
- Detailed Dependency Analysis
- Project-by-Project Plans
- Package Update Reference
- Breaking Changes Catalog
- Testing & Validation Strategy
- Risk Management
- Complexity & Effort Assessment
- Source Control Strategy
- Success Criteria


## 1. Executive Summary

Scenario: Upgrade solution from `net9.0` to `net10.0` across all projects.

Selected Strategy
-----------------
**All-At-Once Strategy** — All projects upgraded simultaneously in a single coordinated operation.

Rationale
---------
- Solution size and shape: 19 SDK-style projects, homogeneous patterns, all currently targeting `net9.0`.
- Assessment shows mostly `Low` difficulty per project and clear package update candidates.
- Fewer than 30 projects and good test surface make an atomic upgrade practical.
- Discovered cross-cutting scenarios to address as part of upgrade:
  - Migrate `Newtonsoft.Json` → `System.Text.Json` where feasible (affects several projects).
  - Migrate `System.Data.SqlClient` → `Microsoft.Data.SqlClient` for `WebHost.Customization`.

Key Metrics (from assessment)
-----------------------------
- Total projects: 19 (all require upgrade)
- Total NuGet packages: 70 (23 need upgrade / 6 incompatible / 17 recommended)
- Total issues flagged: 410 (binary/source/behavioral incompatibilities present)

Primary Objective
-----------------
Produce a single atomic set of changes that updates all project TargetFramework entries to `net10.0`, updates package references as specified in the assessment, resolves compilation and test failures, and results in a solution that builds and has automated tests passing.

## 2. Migration Strategy

Approach
--------
Apply the **All-At-Once** strategy: update every project and MSBuild import consistently in a single controlled operation. This is an atomic migration: there are no intermediate framework-mixed states in the branch used for the upgrade.

Key considerations
------------------
- Update all `TargetFramework` properties simultaneously. If a project uses multi-targeting, append `net10.0` unless the assessment specifies otherwise.
- Update shared MSBuild imports (`Directory.Build.props`, `Directory.Packages.props`, `Directory.Build.targets`) where package versions or frameworks are centrally managed.
- Address conditional MSBuild logic that evaluates target framework constants (e.g., `$(TargetFramework)` or `$(TargetFrameworkIdentifier)`) to avoid invalid branches after the change.
- Apply all NuGet package updates in the same atomic change. Include replacements (e.g., System.Data.SqlClient → Microsoft.Data.SqlClient) and package removals when functionality is provided by the framework.
- Restore and build the entire solution and fix compilation errors in the same operation (one pass with bounded rebuild/verify).

Phases (for human understanding)
--------------------------------
Phase 0 — Preparation (preflight)
- Verify .NET 10 SDK is available on the build agents/dev machines.
- Update `global.json` if present to reference an SDK that supports `net10.0`.
- Ensure branch `upgrade-to-NET10` exists and working tree is clean (already created).

Phase 1 — Atomic Upgrade (single coordinated batch)
- Update project files and MSBuild imports to `net10.0`.
- Update package references per §Package Update Reference.
- Run `dotnet restore` / restore via your CI mechanism.
- Build the solution and fix all compilation errors resulting from framework/package changes.

Phase 2 — Test Validation
- Run all unit and integration tests.
- Address test failures and re-run tests until green.

Phase 3 — Post-upgrade cleanup
- Remove obsolete packages (e.g., packages replaced by framework functionality).
- Address non-compilation items such as migrating JSON serialization usage, update docs and CI pipeline images.

Source control model
--------------------
- Single feature branch: `upgrade-to-NET10` (already created).
- One atomic commit (preferred) that contains all project file and package reference changes. Include a follow-up commit for code fixes if desired but prefer a single logical changeset.
- Create a PR for review with checklist referencing this plan.

## 3. Detailed Dependency Analysis

Dependency summary
------------------
The assessment produced the solution dependency graph. Key facts:
- Many projects depend on shared building blocks: `EventBus`, `IntegrationEventLogEF`, `WebHost.Customization`.
- `EventBus` and `IntegrationEventLogEF` are low-change libraries used by many services and therefore are critical to migrate in the atomic pass.

Migration ordering (dependency awareness)
---------------------------------------
Although this is an All-At-Once upgrade, the dependency graph informs validation and troubleshooting order post-compile:
- Validate leaf libraries and building blocks first during local verification (e.g., `EventBus`, `IntegrationEventLogEF`, `Ordering.Domain`).
- Then validate library consumers and APIs (services and web projects).

Circular dependencies
---------------------
No blocking circular project dependency cycles were reported in the assessment. If any are discovered during implementation, treat the whole cycle as a unit and migrate all members simultaneously.

## 4. Project-by-Project Plans

All projects to be upgraded simultaneously (atomic operation). The following entries summarize the current and target state and the migration steps to apply as part of the atomic change.

Projects (in alphabetical order by path)
- `src\ApiGateways\Aggregators\Web.Shopping.HttpAggregator\Web.Shopping.HttpAggregator.csproj`
- `src\BuildingBlocks\EventBus\EventBus\EventBus.csproj`
- `src\BuildingBlocks\EventBus\EventBusRabbitMQ\EventBusRabbitMQ.csproj`
- `src\BuildingBlocks\EventBus\EventBusServiceBus\EventBusServiceBus.csproj`
- `src\BuildingBlocks\EventBus\IntegrationEventLogEF\IntegrationEventLogEF.csproj`
- `src\BuildingBlocks\WebHost\WebHost.Customization\WebHost.Customization.csproj`
- `src\Services\Basket\Basket.API\Basket.API.csproj`
- `src\Services\Catalog\Catalog.API\Catalog.API.csproj`
- `src\Services\Coupon\Coupon.API\Coupon.API.csproj`
- `tests\Services\Coupon\Coupon.API.Tests\Coupon.API.Tests.csproj`
- `src\Services\Identity\Identity.API\Identity.API.csproj`
- `src\Services\Ordering\Ordering.API\Ordering.API.csproj`
- `src\Services\Ordering\Ordering.BackgroundTasks\Ordering.BackgroundTasks.csproj`
- `src\Services\Ordering\Ordering.Domain\Ordering.Domain.csproj`
- `src\Services\Ordering\Ordering.Infrastructure\Ordering.Infrastructure.csproj`
- `src\Services\Ordering\Ordering.SignalrHub\Ordering.SignalrHub.csproj`
- `src\Services\Payment\Payment.API\Payment.API.csproj`
- `src\Web\WebSPA\WebSPA.csproj`
- `src\Web\WebStatus\WebStatus.csproj`

Per-project migration steps (apply to all projects in the atomic change)
1. Prerequisites
   - Ensure local/CI .NET 10 SDK available.
   - Record current package versions (assessment provides baseline).
2. Project file changes
   - Update `TargetFramework` (or append `net10.0` for multi-targeted projects) to `net10.0`.
   - Update any `TargetFrameworks` lists that implicitly assume `net9.0` behavior.
   - Update or add `LangVersion` or other build properties only if required.
3. Package updates
   - Update package versions per §Package Update Reference.
   - Replace packages when assessment recommends framework replacements (remove or migrate references accordingly).
4. Code fixes
   - Resolve compilation errors reported after the build pass using the Breaking Changes Catalog as guidance.
   - Migrate JSON usage where appropriate from `Newtonsoft.Json` to `System.Text.Json` API surfaces; prefer localized migration changes discovered by build errors.
   - Replace `System.Data.SqlClient` usages where applicable with `Microsoft.Data.SqlClient` in `WebHost.Customization` and projects that rely on it.
5. Verify
   - Restore, build solution, run tests. Address remaining issues in the same atomic operation.

Project-specific notes (high-impact projects)
- `Ordering.API` — high API change concentration; expect compilation fixes related to Identity and EF packages. Marked in assessment with several binary incompatibilities.
- `Basket.API`, `Coupon.API`, `Identity.API`, `WebSPA`, `WebStatus`, `Ordering.SignalrHub` — contain a non-trivial number of API compatibility issues; validate carefully after update.
- `EventBus` and `IntegrationEventLogEF` — low LOC but high fan-out; ensure compatibility before verifying consumers.

Validation checklist for each project
- [ ] `TargetFramework` updated to `net10.0` in project file or central MSBuild import.
- [ ] Package references updated per plan.
- [ ] Project builds without errors.
- [ ] Unit tests (if present) run and pass.
- [ ] No remaining package vulnerabilities flagged by assessment tools.

## 5. Package Update Reference

Guiding principle: include all package updates the assessment suggested. Group updates by scope.

Common package updates (affecting multiple projects)
- `Microsoft.AspNetCore.*` family: current `9.0.x` → target `10.0.3` where assessment lists `10.0.3` recommended (e.g., `Microsoft.AspNetCore.Authentication.JwtBearer`, `Microsoft.AspNetCore.Mvc.NewtonsoftJson`, `Microsoft.AspNetCore.SpaServices.Extensions`).
- `Microsoft.EntityFrameworkCore.*`: `9.0.11` → `10.0.3` (applies to `IntegrationEventLogEF`, `Ordering.Infrastructure`, `WebHost.Customization`, `Identity.API`).
- `Microsoft.Extensions.*` packages: update recommended to `10.0.3` (logging, hosting, configuration pieces flagged by assessment).
- `Microsoft.NET.Test.Sdk`, `coverlet.collector`: keep compatible test SDKs; update if assessment suggests newer test SDKs.

Category-specific updates
- ASP.NET Core related (API and Web projects)
  - `Microsoft.AspNetCore.Authentication.JwtBearer` 9.0.11 → 10.0.3 (affects multiple API projects)
  - `Microsoft.AspNetCore.Mvc.NewtonsoftJson` 9.0.11 → 10.0.3 (note: assessment recommends moving off Newtonsoft.Json where feasible)

- Entity Framework Core
  - `Microsoft.EntityFrameworkCore` 9.0.11 → 10.0.3
  - `Microsoft.EntityFrameworkCore.Design` 9.0.0 → 10.0.3
  - `Microsoft.EntityFrameworkCore.SqlServer` 9.0.11 → 10.0.3

- Logging / Telemetry
  - `Serilog.*` packages remain compatible at `9.0.0` in assessment; update only if needed for `net10.0` compatibility.

Project-specific exceptions and replacements
- `Newtonsoft.Json` (present in several projects) — assessment flags migration scenario. For each project:
  - If `Newtonsoft.Json` is only used for input/output DTOs and tests, migrate to `System.Text.Json`.
  - If third-party libraries require `Newtonsoft.Json`, keep the package but evaluate scope of migration.
- `System.Data.SqlClient` in `WebHost.Customization` — replace with `Microsoft.Data.SqlClient` where code directly references SQL client types.

Source of exact version numbers
- Use the exact `Suggested Version` fields in the assessment when editing `PackageReference` entries. The plan uses `10.0.3` for Microsoft.AspNetCore family and EF Core where assessment notes it.

⚠️ Security and deprecated packages
- Immediately address packages flagged as deprecated or incompatible (for example: `Microsoft.Azure.ServiceBus` is deprecated — migrate to Azure.Messaging.ServiceBus or other recommended alternative if used).

Record-keeping
- Keep a single change set (or commit) describing all package version changes with a table of `Package | Old Version | New Version | Projects Affected` attached to the PR for reviewer reference.

## 6. Breaking Changes Catalog

This catalog highlights categories and example breaking changes to expect; specific code fixes will be discovered during the build/test pass.

Top items from assessment
- Configuration binder: `ConfigurationBinder.GetValue<T>(...)` binary compatibility changes — review binding calls and options patterns.
- Hosting: `IWebHost`, `Microsoft.AspNetCore.WebHost` replaced by generic host patterns — review startup/Program.cs bootstrapping.
- `System.Uri` behavioral changes — validate URI parsing and normalization where relied upon.
- JwtBearer and identity APIs: `JwtBearerDefaults` and some JwtBearerOptions properties show source incompatibilities — verify authentication configuration.
- EF Core changes: use updated EF Core APIs and ensure migrations/tools are updated to matching EF packages.
- SpaServices and Angular CLI middleware — these APIs have seen source changes; if SPA dev-time middleware used, adapt to new hosting approach.

Common code patterns to check
- Use of `BinaryFormatter`, obsolete security APIs (none flagged specifically but check security rules).
- Places using `Newtonsoft.Json` serialization-specific features (custom converters, TypeNameHandling) that may need adapted System.Text.Json converters.
- Direct references to `System.Data.SqlClient.SqlConnection` constructors and members — replace with `Microsoft.Data.SqlClient` equivalents.

Handling approach
- Fixes discovered during build should be addressed in-line. For cross-cutting API changes (e.g., auth), implement minimal, localized changes to restore compilation and tests.
- Flag complex behavioral differences for manual runtime verification and add tests if missing.

## 7. Testing & Validation Strategy

Automated verification levels
- Project build verification: solution restores and builds without compile errors.
- Unit tests: run all test projects (assessment lists `tests\Services\Coupon\Coupon.API.Tests`).
- Integration tests: if present, execute integration suites after internal fix pass.

Validation checklist (solution-level)
- [ ] dotnet restore completes successfully.
- [ ] dotnet build (solution) completes with 0 errors.
- [ ] All unit tests pass.
- [ ] No high-severity package vulnerabilities remain.

Test execution guidance
- Run unit tests after the atomic upgrade commit in CI or locally. Address failures in the same branch.
- If integration tests rely on external services, use test containers or mocks where possible to keep upgrade deterministic.

Manual validation
- For behavioral changes (e.g., `System.Uri`, authentication flows), plan a quick manual smoke test covering login, API calls, and SPA startup.
- Document any runtime behaviors that differ from expectations and file issues for follow-up if required.

## 8. Risk Management

Risk summary
- Assessment shows many API compatibility markers (binary/source) across multiple projects. While projects are rated `Low` difficulty, API incompatibilities increase execution risk.

Risk classification (examples)
- Low risk: small class libraries with few package updates (e.g., `EventBus`, `IntegrationEventLogEF`).
- Medium risk: services with recommended package updates and some API changes (e.g., `Basket.API`, `Payment.API`).
- High/Medium risk: services with multiple binary incompatibilities and many affected APIs (e.g., `Ordering.API`, `WebSPA`, `WebStatus`, `Coupon.API`).

Mitigations
- Run the upgrade in an isolated branch (`upgrade-to-NET10`) and do not merge until all automated checks pass.
- Use feature flags or environment-switched configuration for runtime behavioral validation if needed.
- Allocate debugging effort to the highest-risk projects first during the build pass; keep detailed logs of compilation errors and fix rationale.

Contingency / rollback
- If the atomic upgrade produces unrecoverable issues, revert the upgrade commit and open follow-up tasks that address the blocking issues individually. Preserve the branch for iterative work.

Security vulnerabilities
- Prioritize updates for packages flagged with vulnerabilities in the assessment. List them in the PR with CVE references where available.

## 9. Complexity & Effort Assessment

Per-project complexity (relative)
- Low: `EventBus`, `IntegrationEventLogEF`, `Ordering.Domain`, `Ordering.Infrastructure` (small LOC, few incidents)
- Medium: `Basket.API`, `Catalog.API`, `Payment.API`, `Identity.API`, `Ordering.BackgroundTasks` (some API and package updates)
- Medium-High: `Ordering.API`, `Ordering.SignalrHub`, `WebSPA`, `WebStatus`, `Coupon.API` (more API incompatibilities and behavior changes)

Notes
- These are relative complexity labels to help triage fixes during the atomic build/test pass. They are not time estimates.

## 10. Source Control Strategy

Branching
- Work on `upgrade-to-NET10` branch created from `main`.

Commit strategy
- Prefer one atomic commit containing project/props/package changes. If code fixes must be separated for clarity, include them in subsequent commits on the same branch but keep the PR as a single review unit.

PR requirements
- PR description must include:
  - Link to this plan.md
  - Table of changed projects and package versions
  - Validation checklist results (restore/build/tests)

Review process
- Require at least one code owner review and CI green build + tests before merging.

## 11. Success Criteria

The upgrade is complete when all of the following are satisfied:
1. All projects target `net10.0` (explicit in project files or central MSBuild imports).
2. All package updates suggested by the assessment have been applied and documented.
3. The solution restores and builds with 0 compilation errors.
4. All automated tests included in the repository pass.
5. No high-severity security vulnerabilities remain in package inventory.
6. CI pipeline runs successfully using .NET 10 SDK and artifacts produce expected outputs.

If all criteria are met, proceed to merge the `upgrade-to-NET10` branch into `main` following normal release controls.

-- End of plan



<!-- End of skeleton -->