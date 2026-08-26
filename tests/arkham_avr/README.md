# `tests/arkham_avr` — the AVR Leng corpus

Each fixture compiles with `arkham -a:avr`, assembles with `nifasm`, and runs
under AVRtest with the exit code in its `.exitcode` file.

It is deliberately tiny. The AVR backend compiles the spine — the program walk,
the proc signature, the ABI clobber list and the entry proc's exit path — and
refuses everything else BY NAME rather than emitting it wrongly. The corpus grows
with M4c; see `doc/internals/avr.md` for what is missing and why.

The refusals are tested too, in `tester.nim`'s `arkhamAvrRejections`: a partial
backend is only safe to ship if its gap is a diagnostic, so the diagnostic is
what the tests pin.
