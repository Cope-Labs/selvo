# Copilot Instructions

## Project: selvo — Linux Core Dependency Mapper & Update Prioritizer

### Purpose
Categorically map the most popular "core" Linux dependencies across major package ecosystems (apt/deb, rpm/dnf, pacman, etc.), analyze their dependency graphs, identify version gaps and CVE exposure, and surface highest-value update opportunities that can be rolled forward upstream.

### Architecture
- **discovery/**: Package discovery and ecosystem scrapers (Debian, Fedora, Arch, etc.)
- **graph/**: Dependency tree construction and graph analysis
- **analysis/**: Version gap analysis, CVE checking, upstream tracking
- **prioritizer/**: Scoring engine for update value/impact
- **reporters/**: Output formatters (JSON, Markdown, terminal)
- **cli.py**: Main CLI entrypoint

### Coding Guidelines
- Python 3.11+
- Use `networkx` for dependency graph modeling
- Use `httpx` for async HTTP requests to package APIs
- Use `rich` for terminal output
- Use `typer` for CLI
- Type-annotate all public functions
- Prefer async where IO-bound
- Keep modules small and focused; avoid god-objects
