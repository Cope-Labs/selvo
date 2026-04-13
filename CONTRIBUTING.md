# Contributing to selvo

Thanks for considering it. selvo is a one-person project at Cope Labs;
every PR materially changes the bus factor.

## What's most useful

In rough order of value:

1. **Ecosystem coverage gaps.** The CVE pipeline is fragile in the same
   shape across ecosystems — every new OSV ecosystem that surfaces hides
   a "silent zero" bug somewhere. If you scan a SUSE/openSUSE box (or
   Wolfi/Chainguard, or anything not in
   [project_cve_pipeline_gotchas](selvo/analysis/cve.py)) and counts
   look wrong, file an issue with the package list and what you got.
2. **Self-host pain.** [deploy/selfhost/](deploy/selfhost/) is the
   compose stack we run in production. If something there is unclear,
   file an issue or PR the docs — that's where new users land.
3. **Dashboard polish.** [selvo/api/dashboard.py](selvo/api/dashboard.py)
   carries the entire UI as Python-rendered HTML. Anything from copy fixes
   to better empty states to year-badge tweaks is welcome and quick to
   review.
4. **Scoring weights.** The blast-radius / EPSS / CVSS / exploit-maturity
   blend in [selvo/prioritizer/scorer.py](selvo/prioritizer/scorer.py) is
   tunable. If you have data showing the current weights are wrong for a
   real workload, that's a strong PR.
5. **Test coverage.** Especially for the CVE pipeline. Every silent-zero
   bug we've shipped would have been caught by an integration test that
   actually hits OSV with a known-good package.

## What's harder to merge

- Major scoring algorithm changes without empirical justification.
- New ecosystems we can't easily test against.
- Heavy refactors that mix structure changes with behavior changes —
  please split them.

## Dev setup

```bash
git clone https://github.com/Cope-Labs/selvo.git
cd selvo
pip install -e ".[dev,api]"
pytest
selvo --help
```

The dashboard runs against your local install:

```bash
SELVO_API_AUTH=0 selvo-api --host 127.0.0.1 --port 8765
# open http://127.0.0.1:8765/dash/overview
```

## Filing issues

For bugs: include the ecosystem, a sample package list (source/binary
names + versions), what you expected, what you got. For "I scanned X and
got 0 CVEs" the silent-zero monitor in
[selvo/api/silent_zero.py](selvo/api/silent_zero.py) catches the obvious
ones — if it didn't fire and you still think the result is wrong, that's
exactly the bug shape we want to know about.

For features: a paragraph describing the problem you're trying to solve
is more useful than a paragraph describing the solution.

## Pull requests

- Keep them small. One concept per PR.
- Existing tests must pass: `pytest`.
- New behavior gets a test if practical.
- Match the surrounding style — type hints where reasonable, no
  unnecessary docstrings, no abstraction-for-its-own-sake.
- We default to no comments. Comment when *why* is non-obvious.
- Commit messages follow the existing convention: `area: short summary`
  with body explaining the why. Look at recent `git log` for examples.

## License

By contributing you agree your contribution is licensed under
[Elastic License 2.0](LICENSE) along with the rest of the project.

## Questions

Open a [GitHub Discussion](https://github.com/Cope-Labs/selvo/discussions) or
email <seth@copelabs.dev>.
