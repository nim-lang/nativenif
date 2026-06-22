#
#           Shared foreign-module loader for the nifcore backends
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## This loader was promoted into nimony (`nimony/src/lib/foreignmodules.nim`) so
## nimony's lengc and the nativenif tools (arkham, nifasm) share ONE
## implementation. This file now just re-exports it, keeping the `nifmodules`
## import name stable for arkham/nifasm. nimony's `src/lib` is already on our
## `--path` (see arkham/nifasm `nim.cfg`), the same arrangement used for
## `nifcore`/`nifreader`.

import foreignmodules
export foreignmodules
