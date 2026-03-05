# mslearn-microservices-devops-aspnet-core .NET 10.0 Upgrade Tasks

## Overview

Upgrade the repository from `net9.0` to `net10.0` by updating project TargetFrameworks, package references, building, and running automated tests. The work is executed as an atomic code change: prerequisites → atomic upgrade (project/package updates + compilation fixes) → test validation.

**Progress**: 1/3 tasks complete (33%) ![0%](https://progress-bar.xyz/33)

---

## Tasks

### [✓] TASK-001: Verify prerequisites *(Completed: 2026-03-05 13:34)*
**References**: Plan §Phase 0, Plan §1 Executive Summary

- [✓] (1) Verify .NET 10 SDK is installed on build agents and local developer machines per Plan §Phase 0 (check `dotnet --list-sdks`)
- [✓] (2) Runtime/SDK version meets minimum requirements (**Verify**)
- [✓] (3) Check for `global.json` and update it to reference a .NET 10-compatible SDK if present (per Plan §Phase 0)
- [✓] (4) `global.json` updated or not present (**Verify**)
- [✓] (5) Verify required build tools and environment variables referenced by the plan are available (**Verify**)

### [✗] TASK-002: Atomic framework and package upgrade with compilation fixes
**References**: Plan §Phase 1, Plan §Package Update Reference, Plan §Breaking Changes Catalog, Plan §Project-by-Project Plans

- [✓] (1) Update `TargetFramework` (or append `net10.0` for multi-targeted projects) in all project files listed in Plan §Project-by-Project Plans and update central MSBuild imports (`Directory.Build.props`, `Directory.Packages.props`, `Directory.Build.targets`) where framework or package versions are managed
- [✓] (2) All project files and central imports updated to `net10.0` (**Verify**)
- [✓] (3) Update package references across the solution per Plan §Package Update Reference (including replacements such as `System.Data.SqlClient` → `Microsoft.Data.SqlClient` and package removals where framework provides functionality)
- [ ] (4) All package references updated per plan (**Verify**)
- [✗] (5) Run `dotnet restore` for the solution and ensure all dependencies restore successfully (**Verify**)
- [✗] (6) Build the solution to identify compilation errors (one bounded pass) per Plan §Phase 1
- [✗] (7) Fix all compilation errors found using guidance in Plan §Breaking Changes Catalog and per-project notes (include localized migrations such as `Newtonsoft.Json` → `System.Text.Json` and API replacements)
- [✗] (8) Rebuild the solution to verify fixes applied
- [✗] (9) Solution builds with 0 errors (**Verify**)
- [✗] (10) Commit changes with message: "TASK-002: Atomic upgrade to net10.0 — project files, package updates, compilation fixes"

### [ ] TASK-003: Run full test suite and validate upgrade
**References**: Plan §Phase 2, Plan §Testing & Validation Strategy, Plan §Project-by-Project Plans

- [ ] (1) Run all unit and integration test projects referenced in the plan (example: `tests\Services\Coupon\Coupon.API.Tests`) per Plan §Phase 2
- [ ] (2) Fix any test failures (reference Plan §Breaking Changes Catalog and project-specific notes for likely fixes)
- [ ] (3) Re-run tests after fixes
- [ ] (4) All tests pass with 0 failures (**Verify**)
- [ ] (5) Commit test fixes with message: "TASK-003: Test fixes and validation after net10.0 upgrade"

---




