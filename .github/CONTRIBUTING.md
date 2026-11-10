# Contributing

Submit changes through a pull request targeting `main`. The GitHub Actions `test`
check must pass against the latest base branch before merging. Contributor changes
require the repository owner's approval; new commits dismiss previous approvals.
Resolve review conversations before merging.

External contributors' workflow runs need maintainer approval before they start.
A workflow approval allows CI to run; it does not approve or merge the code.

The owner also uses pull requests. GitHub does not allow self-approval, so the
owner may explicitly bypass the review requirement for their own pull requests.
The separate CI and pull request requirements still apply. Force pushes and
branch deletion are blocked on the default branch.

Keep runtime configuration, credentials, game binaries, captures, and player data
out of commits. Use the private reporting process in [SECURITY.md](SECURITY.md) for
vulnerabilities. Dependabot changes require review and are not merged automatically.
