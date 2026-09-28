# Fork / Research Context

This repository is a personal research fork of the upstream
[HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg) project.

The upstream HyperDbg maintainers and contributors retain authorship and credit for
the original project, its documentation, publications, and upstream changes. This
fork should not be interpreted as a claim of authorship over upstream work.

## Why I keep this fork

I use this repository as a working environment for authorized low-level debugging,
reverse-engineering, virtualization, and systems research. My main technical
interests include C/C++, Windows internals, Intel VT-x/EPT, debugger behavior,
binary analysis, and supporting developer tooling.

Research and testing are intended for systems and software that I own or am
authorized to analyze.

## Branch guide

The commit history is the source of truth for authorship and provenance.

- **`master`** — upstream-aligned baseline.
- **`downstream`** — integration branch that may include newer upstream work and
  ongoing portability/integration changes. Do not treat all commits on this branch
  as original work by this account without checking commit attribution.
- **`ept-hook-above-512gb`** — focused experimental branch. Relative to its merge
  base, it contains a small set of changes around EPT hooking and related debugger
  code. Review the branch diff and commit history for exact attribution.
- **`trace-module`** — older experimental branch retained for historical context.

## How to review my work

When evaluating work in this fork, please use the branch and commit history rather
than the upstream README or publication list. In particular:

1. Check the author/committer on individual commits.
2. Compare an experimental branch with its merge base.
3. Treat upstream release notes, papers, and project-wide features as upstream
   HyperDbg work unless a specific downstream commit shows otherwise.

This separation is intentional: I want my public GitHub history to be useful and
verifiable without overstating ownership of upstream security research.

## Related public work

My GitHub account also contains other low-level systems and developer-tooling
repositories. Some are forks or mirrors and are kept for experimentation; where
that is the case, upstream attribution should be preserved in the same way.

For example, my `codex` fork has a separate `README.fork.md` that documents the
custom translation-plugin work added on top of the upstream project.

## Responsible-use note

The purpose of this research workspace is debugging, compatibility work, defensive
analysis, vulnerability validation in authorized environments, and development of
research tooling. It is not intended to imply authorization to test third-party
systems without permission.
