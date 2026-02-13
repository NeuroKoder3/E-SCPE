# Contributing to E-SCPE

Thank you for your interest in E-SCPE! We value community input and want to
make it easy for you to participate.

## Important: Licensing Notice

E-SCPE is distributed under the **Source Available License -- No Modifications
(SA-NM v1.0)**. This means:

- **Code contributions (pull requests) are not accepted** because the license
  prohibits derivative works and modifications by third parties.
- You **can** use, run, test, and redistribute the software in its unmodified
  form.

We still very much welcome your participation through the channels listed below.

## How You Can Contribute

### Report Bugs

Found a bug? Please [open an issue](../../issues/new?template=bug_report.yml)
using the **Bug Report** template. Include as much detail as possible:

- Steps to reproduce
- Expected vs. actual behavior
- OS version, Rust version, .NET version
- Relevant log output (redact any sensitive data)

### Request Features

Have an idea for a new feature or improvement? Please
[open an issue](../../issues/new?template=feature_request.yml) using the
**Feature Request** template.

### Report Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.** Please follow the
process described in our [Security Policy](SECURITY.md):

1. Use the [Security Advisories](../../security/advisories) tab, or
2. Contact the maintainer directly through their GitHub profile.

### Improve Documentation

If you spot a typo, unclear explanation, or missing information in the
documentation, please open an issue describing what should be changed.

### Share Feedback

General feedback, questions about the architecture, or deployment advice are all
welcome in [GitHub Discussions](../../discussions) (if enabled) or as issues
labeled `question`.

## Issue Guidelines

- **Search first** -- check if a similar issue already exists before opening a
  new one.
- **One issue per report** -- keep each issue focused on a single bug or
  request.
- **Use templates** -- fill out the provided issue templates completely.
- **Be respectful** -- follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Setup (for reference)

If you want to build and test E-SCPE locally:

### Prerequisites

| Tool      | Version  |
|-----------|----------|
| Rust      | 1.75+    |
| .NET SDK  | 8.0+     |
| Platform  | Windows  |

### Build

```powershell
# Rust core + CLI
cargo build --release

# .NET WinUI app
dotnet build winui/EscpeWinUI.csproj -c Release

# Run tests
cargo test
dotnet test winui.tests/EscpeWinUI.Tests.csproj -c Release
```

### Dependency Auditing

```powershell
cargo deny check
```

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). By
participating, you agree to uphold this code.

## Questions?

If you have questions that don't fit an issue template, feel free to open an
issue with the `question` label or reach out to the maintainer through their
GitHub profile.
