# The board layout file

`arkham --layout:board.nif` describes the part an image is built for: where its
memory is, which region each section lives in, what its console is, and where the
stacks and the heap go.

It replaces a command-line namespace that could not have grown into this. Regions
are a **list**; a stack slot has a size *and* a count *and* a thread-local
reservation; a board may have three RAMs and put `.data` in one of them. None of
that survives being flattened into `--flag:value` pairs.

## One reader

arkham parses the file and **forwards it into the asm-NIF** as a `(memmap …)`
declaration. nifasm — which needs the regions to place segments — reads that tree
rather than opening the file a second time.

Two parsers of one file is two chances to disagree about what a region means, and
the disagreement would not be a diagnostic: it would be an image that loads at the
wrong address. The forward is also **normalized to bytes**, so the unit arithmetic
happens exactly once.

The file is written in nifasm's own tag vocabulary (`doc/instructions.md`), which
is what makes that forwarding a splice rather than a translation.

## Shape

```
(.nif27)
(memmap
 (region flash rom (origin 134217728) (megabytes 1))
 (region sram  ram (origin 536870912) (kilobytes 128))

 (place text   flash)
 (place rodata flash)
 (place data   sram)
 (place bss    sram)

 (console uart (origin 1073758208))

 (stacks sram (slots 4) (kilobytes 8) (tls (bytes 512)))
 (heap   sram (kilobytes 32))
 (core 0))
```

**Sizes are tagged quantities.** NIF has no `4K` literal, and a bare number in a
layout file is exactly the place where a reader guesses the unit and is wrong. So
`(bytes N)`, `(kilobytes N)`, `(megabytes N)` — and an untagged number is an
error, not a byte count.

`(origin …)` is an address. Addresses and sizes are both plain integers in NIF, so
they are told apart by their tag rather than by position.

## Regions and placement

A region is `rom` (holds what the image ships with) or `ram` (holds nothing at
reset). `text` must be placed in a `rom` region and `data`/`bss` in a `ram` one —
placing code in RAM would mean an image with nothing to copy it *from*.

`data`'s initializer image ships in the region `text` is placed in; the startup
copy is what puts it where `(place data …)` says. See `doc/cortex_m.md` M6a.

Today `data`, `bss`, the stacks and the heap must all name the **same** region:
the image emits one SRAM segment and the startup copy walks from one into the
other. A part with a separate CCM/DTCM is exactly why the file names regions
individually, and lifting that restriction is a change to the image writer rather
than to this vocabulary.

## Inside the RAM region

Placed by nifasm, in this order:

1. **globals** from the region base up — which is what every `movw`/`movt` site is
   already patched against.
2. **the heap**, 8-aligned above them.
3. **the stacks**, rounded up to the slot size.

The stacks go last because their alignment is the expensive one: rounding up
wastes whatever lies between them and the heap, and nothing after them pays for
it. An overflow of the region is a link-time error naming all four numbers.

## Stacks and thread-locals

`(slots N)` slots of one size, and **the slot size must be a power of two.**

That is not tidiness: a thread reaches its own thread-locals by *masking SP*.
`sp and not (slotSize-1)` is the base of the running thread's slot, in one
instruction, with no thread-ID register — ARMv7E-M has none, so the alternative is
a global the scheduler updates on every switch.

The reservation sits at the **top** of each slot, just below where SP starts, so
the stack grows *down and away* from it rather than into it. The accessor is the
mask plus a constant add.

Two consequences worth stating rather than discovering:

* every stack is the same size, because the size is baked into an instruction;
* the boot stack obeys the same rule — `(core N)` selects which slot *this* image
  starts on, and its SP is that slot's top minus the reservation.

`(core N)` is a constant because there is **one image per core**: M-profile has no
architectural core id (no `MPIDR`), so a symmetric image would need a
vendor-specific CPUID register that arkham cannot know.

Thread-locals are not reachable from an interrupt handler. Handlers run on MSP
while threads may run on PSP, so masking SP inside one yields the handler's slot,
not the interrupted thread's — and in the simple case where everything runs on MSP
it would *appear* to work and break the day PSP is adopted.

## Console

`(console semihosting)` traps to a debug agent; `(console uart (origin …))` writes
to a CMSDK APB UART and ends by parking the core. Giving a console here **and** on
the command line is refused — that is a contradiction, not a precedence question.

See `doc/cortex_m.md` M6e for what each one costs.
