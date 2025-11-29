# Repository Guidelines

## Project Structure & Module Organization
Source code lives under `src/`. `src/nifasm` provides the assembler/linker entry point (`nifasm.nim`) plus supporting modules such as `assembler.nim`, `x86.nim`, and `elf.nim`. Early optimizer work sits in `src/opt`, currently focused on `partial_inliner.nim`. Documentation and design notes are in `doc/`, with `doc/nativenif.md` outlining the toolchain and `doc/tags.md` feeding generated enums. Sample `.nif` programs for manual verification are stored in `tests/`, while helper generators (for example `tools/gen_tags.nim`) live in `tools/`. Keep generated files like `src/nifasm/tags.nim` and `src/nifasm/model.nim` untouched—edit the source markdown and rerun the generator instead.

## Build, Test, and Development Commands
- `mkdir -p bin && nim c -o:bin/nifasm src/nifasm/nifasm.nim` — builds the assembler as a standalone binary without running it.
- `bin/nifasm tests/hello.nif` — assembles the sample program, producing a binary next to the input file; adjust the path to target additional test cases.
- `nim r tools/gen_tags.nim` — regenerates tag and model enums after editing `doc/tags.md`; rerun whenever opcode metadata changes.
- `nimpretty --indent:2 src/nifasm/*.nim` — optional formatter for harmonizing spacing before review.

## Coding Style & Naming Conventions
Code follows idiomatic Nim style: two-space indentation, `camelCase` procedures (`handleCmdLine`), `PascalCase` types/constants (`TagEnum`, `Version`), and `snake_case` file names. Group related imports using the `/` syntax (`import std / [...]`). Keep procs short, prefer explicit error helpers like `error()` over inline string building, and document non-obvious control flow with concise comments. Generated enums or records should come from `tools/gen_tags.nim`; manual edits drift quickly.

## Testing Guidelines
There is currently no automated test runner, so treat `tests/` as executable fixtures. Create new programs under `tests/<feature>.nif` mirroring the naming pattern in `tests/hello.nif`. Assemble them with the freshly built `nifasm` binary and inspect the emitted machine code or run the resulting programs under a debugger. When adding optimizer features, include before/after `.nif` snippets plus brief notes in the PR so reviewers can reproduce the scenario.

## Commit & Pull Request Guidelines
Existing history favors short, imperative summaries (e.g., "code cleanup", "make register bindings super picky"). Keep subject lines under ~60 characters, describe user-visible impact in the body, and reference issues when applicable. Pull requests should state the affected modules (`src/nifasm/assembler.nim`, `tools/gen_tags.nim`, etc.), list reproduction steps or test commands you ran, and include screenshots or logs if behavior changes. Mention any generated files and confirm you reran the appropriate tool so reviewers can diff the source rather than the artifacts.
