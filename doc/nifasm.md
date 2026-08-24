# nifasm: Structured & Typed Assembler

Design goals:

- Make the development of native code generators almost as cheap as generating C++ or LLVM code.
- Complete control over the emitted binary. It is a real assembler, not an abstract machine!
- Compute what is "easy enough" directly in the assembler (object field offsets, stack offsets)
  so that it does not even have to be verified.
- Bring **structured programming** to assembler, the way nimony's Leng IR does, so that
  validation passes can be done extremely cheaply without complex fixpoint computations.
- Bring **type safety** to assembler so that code generator bugs can be found without even
  having to run the resulting programs.
- Keep the text format until linking! Only the linker needs to understand binary instruction encodings.
  This keeps things debuggable and readable until the very end. Linking these days is mostly text-processing
  anyway: Function names remain as strings in classical object files, sections are named and subject
  to garbage collection, etc. We just do the next step here and are honest about it: The linker operates
  on a set of text files. It can easily be made incremental.

Non goals:

- Abstract over instruction selection and register allocation. This remains to be the primary job of a code generator!
- Abstract over the ABI and calling conventions. Instead the `call` instruction is made checkable
  yet so flexible that any calling convention can be followed. If your PL has unique demands, no
  problem, `nifasm` naturally supports it!
- Compatibility with native object files and DWARF as an *input* interface. `nifasm` reads only
  NIF; it emits ELF, Mach-O and PE (with DWARF `.eh_frame` / `.pdata` unwind info, so ordinary
  debuggers work) purely as its final output.


## Type system

The assembler is unlike any other in that it keeps the control flow structured and every expression is typed. The type system is a simplification of Nimony's.

The type system's goal is not only type checking but also facilitates the computation of sizes, alignments and offsets. The idea is that both control flow as well as object field names can stay in the assembler so that everything is very readable. The architecture welcomes the idea that a programmer can optimize at the assembler level and yet everything stays as safe, readable and abstract as possible.

A key insight here is while assembler does not allow unnamed temporary expressions there is no reason it cannot keep field names instead of offsets (no control is lost). Likewise, structured control flow — `loop` and `ite` with forward-only `lab`/`jmp`, the shape Leng's Final IR already has — is easy enough to map to labels and offsets (no control is lost either).

Note on notation: this document shows the NIF text format. The complete tag vocabulary — every type, declaration,
addressing mode, register, flag and machine instruction of every target — is
[instructions.md](instructions.md). What follows is what those tags *mean*.


### Type atoms

Type atoms are `(bool)`, `(i N)` (signed integer of N bits), `(u N)` (unsigned integer of N bits), `(c N)` (character of N bits), `(f N)` (float of N bits) and `(void)`. Hardware flags are typically mapped to the type `(bool)`.


### Compound types

Compound types are `(ptr <ElementType>)`, `(aptr <ElementType>)`, `(array <ElementType> <count>)`, `(flexarray <ElementType>)` and finally `Symbol` where `Symbol` has been declared via a `type` construct:

```
(type :Name.0 (object (fld :Field.0 <Type 1>) ...) <optional_pragmas>)
(type :Name.1 (union (fld :Field.0 <Type 1>) ...) <optional_pragmas>)
(type :Name.2 (enum <BaseType> (efld :Field.0 <value>) ...))
(type :Name.3 (proctype (params (param :p.0 <Loc> <Type>) ...) (result :r.0 <Loc> <Type>)))
```

**Object vs Union:**
- `object`: Fields are laid out sequentially in memory. The size of an object is the sum of all field sizes. Each field has a different offset.
- `union`: All fields overlay each other at offset 0. The size of a union is the maximum size of all fields. Writing to one field can affect the values read from other fields since they share the same memory.

Calling conventions are not modelled via the type system; instead every function declaration is very explicit how it expects its parameter to be passed. Clobbered registers are part of this declaration! Custom calling conventions are an easy and effective way to get more speed from high level code. For example, an abort-like function should announce that no registers are clobbered so that the efficiency of the caller's register handling is not affected. This is a generalization of the idea that "leaf functions" can use registers more aggressively.

The difference between `ptr` and `aptr` is that `ptr` points to a single element and `aptr` to an array of elements of unspecified size. Pointer arithmetic is only allowed for the type `aptr`, not for `ptr`.


## Registers

Registers are typically not written directly, instead if they are used as local variables, a variable declaration attaches a name to the register. The assembler keeps track of the used registers and ensures that registers are not used inconsistently! For example, a register that is currently used for a local variable cannot be used as a function argument directly. Instead an `mov` instruction must be used regardless: `(mov (arg arg.0) my.local)`. The assembler elides the instruction if the registers are the same.


## Stack slots

Declarations are either bound to a register or to a stack slot. Instead of a register name the `(s)` tag is used then. The `(s)` tag explicitly indicates storage location (stack allocation), which is separate from the type information. Since we know the type of every declaration the slot's offset is computed by `nifasm`. Again, this keeps the code more readable. An instruction can use the tag `(ssize)` to access the maximum required stack size. This is typically used in function prologs and epilogs.

Stack-allocated variables can have compound types (arrays, objects). When a variable name bound to a stack slot is used in an address expression (`(dot ...)`, `(at ...)`), it stands for the *address* of the stack-allocated value — the frame base plus the computed offset — so arrays and objects on the stack are accessed by name, with no explicit address computation. The targets spell the frame base differently: x86-64 wants it as an operand of its own, while both Arm targets take it from the slot.

Note: The `(s)` tag is required for clarity - it explicitly separates storage location from type. For example, `(var :arr.0 (s) (array (i 32) 6))` makes it clear that `(s)` is about where the variable is stored (stack), while `(array (i 32) 6)` is about its type (array of 6 int32s). A slot can also demand a stricter alignment than its type implies, as `(s (align 16))`.

```
(var :arr.0 (s) (array (i 32) 6))  # stack array of 6 int32s
(var :p.0 (s) Point.0)             # stack object of type Point.0

# x86-64: the frame base register is written out
(mov (rax) (mem (at (rsp) arr.0 (rcx))))  # loads arr[rcx] - [rsp+offset+rcx*4]
(mov (rbx) (mem (dot (rsp) p.0 x.0)))     # loads p.x    - [rsp+offset+field_offset]

# AArch64: the slot carries its own frame base, so it is left implicit
(mov (x0) (mem (at arr.0 (x9))))
(mov (x1) (mem (dot p.0 x.0)))
```

`(ssize)` is the frame size the assembler computed for the current proc; the prologue and
epilogue use it (`(sub (rsp) (ssize))` / `(add (rsp) (ssize))`). Slots declared inside a
`(scope ...)` block are reclaimed at the end of that block, so sibling scopes share frame
space.



## Proc calls

In `nifasm` every callsite is type-checked, a proc declaration looks like:

```
(proc :foo.0
  (params
    (param :arg.0 (rax) (i 64))
    (param :arg.1 (rcx) (u 8))
  )
  (result :ret.0 (rax) (i 64))
  (clobber
    (rdi) (rbx)
  )
  (stmts ...)
)
```

The four sections are positional and all four are present even when empty:
`(params)`, `(result)` (a proc returning nothing has an empty one), `(clobber)`, and the
body, which is a `(stmts ...)` block. A result that is returned in more than one register
uses `(regs (rax) (rdx))` in place of the single register.

### Stack parameters

Parameters can also be passed on the stack instead of in registers. Use `(s)` or `(s N)` instead of a register name to indicate a stack-passed parameter:

```
(proc :bar.0
  (params
    (param :arg.0 (rdi) (i 64))         # register parameter
    (param :arg.1 (rsi) (i 64))         # register parameter
    (param :arg.2 (s 8) (i 64))         # first stack param at base offset 8
    (param :arg.3 (s) (i 64))           # next stack param (offset computed)
    (param :arg.4 (s) Point.0)          # next stack param (offset computed)
  )
  (result :ret.0 (rax) (i 64))
  (clobber (r10))
  (stmts ...)
)
```

The `(s N)` syntax specifies the base offset for the first stack parameter. Common values:
- `(s 8)` - after return address (x86-64 without frame pointer)
- `(s 16)` - after return address and saved rbp (x86-64 with frame pointer)

Subsequent `(s)` parameters without an explicit offset are computed from:
- The offset of the preceding `(s)` parameter
- The size of the preceding parameter
- Alignment requirements of the current parameter's type

This is consistent with how `(s)` is used for local stack-allocated variables.

### Accessing stack parameters in the proc body

Within the proc body, stack parameters are accessed using `(mem <base> <name>)` where the base register is explicitly provided and the assembler uses the offset from the parameter declaration. The base register must be specified - no implicit register usage.

```
(proc :bar.0
  (params
    (param :arg.0 (rdi) (i 64))         # register parameter
    (param :arg.1 (s 8) (i 64))         # stack param at offset 8
    (param :arg.2 (s) (i 64))           # stack param at offset 16 (computed)
  )
  (result :ret.0 (rax) (i 64))
  (clobber)
  (stmts
    # Register parameter: use the variable name directly
    (mov (rax) arg.0)

    # Stack parameters: explicit base register + parameter name for offset
    (mov (rbx) (mem (rsp) arg.1))       # load from [rsp + 8]
    (mov (rcx) (mem (rsp) arg.2))       # load from [rsp + 16]

    # With frame pointer (offsets would be declared differently):
    (mov (rbx) (mem (rbp) arg.1))       # load from [rbp + offset_of_arg.1]

    # To get the address of a stack parameter:
    (lea (rdx) (mem (rsp) arg.1))       # compute rsp + 8 into rdx
  )
)
```

The parameter name provides the declared/computed offset, but the base register (`rsp`, `rbp`, or any other) must always be explicit. The parameter's type is preserved for type checking.

## Call instruction

The `call` instruction differs more so from a traditional assembler than the other instructions. The reason is that `nifasm` checks for parameter passing consistencies. Every parameter must be named. This way the control over scheduling decisions remains, in other words it is possible to evaluate the expression that is passed to parameter 3 before the expression that is passed to parameter 1. This might not be overly useful, but machine code naturally allows for this flexibility.

Before a call can be performed the arguments must be prepared.

For example:

```
(prepare foo.0
  (mov (arg arg.0) 56)
  (mov (arg arg.1) 1)
  (call)
  (mov my.local (res ret.0))
)
```

A call to a proc imported from a dynamic library (declared with `(extproc :name.0 "_name")`)
uses `(extcall)` in place of `(call)`; a tail call uses `(tailcall)`.

### Stack arguments with `(csize)`

When a proc has stack parameters, the caller must explicitly manage the stack. The `(csize)` builtin computes the total stack space required for the current call's stack arguments (analogous to `(ssize)` for function entry points).

For register parameters, `(arg name)` refers to the register. For stack parameters, `(arg name)` provides only the computed offset - the base register must be explicit:

```
(prepare bar.0
  (sub (rsp) (csize))                       # reserve stack space for args
  (mov (arg arg.0) 56)                      # register arg: (arg arg.0) is the register
  (mov (arg arg.1) 78)                      # register arg: (arg arg.1) is the register
  (mov (mem (rsp) (arg arg.2)) 123)         # stack arg: explicit [rsp + offset]
  (mov (mem (rsp) (arg arg.3)) 456)         # stack arg: explicit [rsp + offset]
  (call)
  (mov my.local (res ret.0))
  (add (rsp) (csize))                       # explicit cleanup
)
```

The assembler verifies that:
- Every register argument is assigned exactly once via `(mov (arg name) value)`
- Every stack argument is assigned exactly once via `(mov (mem (rsp) (arg name)) value)`
- The types of assigned values are compatible with the parameter types
- Stack management is explicit - no implicit code is generated

A code generator does not have to move the stack pointer per call, and arkham does not:
it sizes the frame once in the prologue to include the largest outgoing argument area any
call in the body needs, so the `(sub (rsp) (csize))` / `(add (rsp) (csize))` bracket
disappears and the stack arguments are written straight into the reserved region. See
[../src/arkham/design.md](../src/arkham/design.md).

### Return values

Return values are declared in a proc's `(result ...)` section and must be bound at
each call site as well. After the `(call)` marker, use `(res name)` to access
the result value:

```
(prepare foo.0
  (mov (arg arg.0) 56)
  (call)
  (mov myResult (res ret.0))
)
```

Within a `prepare` block:
- Before `(call)`: Named arguments are accessed via `(arg name)`
- After `(call)`: Named results are accessed via `(res name)`

It is checked that every argument is assigned a value exactly once, and every result is bound exactly once.


## Local variables

Since local variables are described precisely, it is possible to detect code generation bugs at translation time. Consider:

```
(var :my.local (rdi) (i 64))
(prepare foo.0
  (mov (arg arg.0) 56)
  (mov (arg arg.1) 1)
  (call)
)
(mov (rax) my.local) # bug detected: foo.0 clobbers register rdi!
```

A local's register binding can also be changed explicitly: `(rebind :tmp.0 (i 64) (x9))`
binds a physical register to a typed name, killing whatever name it held before,
`(withreg ...)` does the same for the extent of a block, and `(kill name)` ends a binding
early. Every read of a register that is currently bound to a name must go through the
name — naming the register directly is an error, which is what makes an accidental
clobber a translation-time failure rather than a wrong answer at run time.


## Control flow

Control flow is `(ite ...)` (if-then-else), `(loop ...)`, and `(lab ...)` /
`(jmp ...)` — **forward** jumps only. Every backward edge is a `loop`, which is
what lets the assembler see the control flow structurally, with no fixpoint.

That set is not nifasm's invention. It is the shape of Leng's **Final IR**
(nimony's [doc/final_ir.md](https://github.com/nim-lang/nimony/blob/master/doc/final_ir.md)),
which lowers `if`/`elif`/`and`/`or`/`break` to exactly `loop`/`ite`/`lab`/`jmp`
with forward-only, scoped jumps — so a merge point is one shared `(lab)` that
several `(jmp)`s target, rather than a nest of bracketing regions. Arkham
receives that and emits the same three constructs.

### Labels and jumps

```
(lab :done.0)       # define a label
(jmp done.0)        # jump to it — the target must be defined LATER
(je done.0)         # ...or conditionally, on a flag
```

A `(jmp ...)` whose target is defined earlier is not legal: that is a back edge,
and a back edge is a `loop`.

### Testing hardware flags

The `ite` construct tests hardware flags directly:

```
(ite (of) # test overflow flag
  (stmts
    (mov (rax) 1)
  )
  (stmts
    (mov (rbx) 3)
  )
)
```

The flags are `(zf)` zero, `(of)` overflow, `(cf)` carry, `(sf)` sign and `(pf)` parity, each with a negated form: `(nz)`, `(no)`, `(nc)`, `(ns)`, `(np)`. There is deliberately no *signed comparison* flag — that is not one bit of the flags register — so a signed `>` is a `(jg ...)` jump, a `(setg ...)`, or a `(cmovg ...)`.

### Loop construct

A loop is an *infinite* loop over a single statement block:

```
(loop
  (stmts ...)   # the body
)
```

The back edge is emitted by the assembler, so it never appears in the input: the
body carries a forward `jmp` to a label defined **after** the loop, and that is
the exit. A `while` is therefore the condition test plus a conditional forward
jump at the top of the body — which is also exactly what Final IR's "a `loop`
has no condition slot" rule produces:

```
(mov (rcx) 3)
(loop
  (stmts
    (cmp (rcx) 0)
    (ite (zf) (stmts (jmp done.0)) (stmts))
    (dec (rcx))))
(lab :done.0)
```

This is what keeps "every `jmp` is forward, every back edge is a `loop`" true of
the whole input, which in turn is what makes the assembler's validation passes
cheap.

### Control flow variables (legacy)

**Nothing generates these any more.** `cfvar`/`jtrue` are the older *no-jumps*
mechanism: a merge was named by a boolean variable that could only be set, never
cleared, instead of by a label. Leng's Final IR replaced it with `lab`/`jmp`
(see above) — arkham has never emitted a `cfvar`, and neither does any other
Leng producer. nifasm still accepts them, and the rest of this section describes
what they mean, but a new code generator should use labels.

A control flow variable is declared as

```
(cfvar :name.0)
```

It is always of type `(bool)` and always initialized to `false`. No type
annotation or initializer is given. It can only be set to `true`, by `jtrue`:

```
(jtrue cfvar1.0)
(jtrue cfvar1.0 cfvar2.0 cfvar3.0)  # can set several at once
```

Once `true` it stays `true`. A cfvar is **always virtual**: it is never
materialized into a register or memory, because `jtrue` is always lowered to an
unconditional jump, whose target the surrounding control-flow structure
determines.

Used as an `ite` condition, a cfvar therefore evaluates nothing at all:

```
(ite cfvar.0
  (stmts
    # "then" — reached if cfvar.0 was set to true
    (mov (rax) 1)
  )
  (stmts
    # "else" — reached if cfvar.0 is still false
    (mov (rbx) 3)
  )
)
```

Unlike a flag or a register condition, there is no test here: the control flow
was already decided by the preceding `jtrue`s. Putting it together, `if cond1 or
cond2` becomes:

```
(cfvar :tmp.0)
(cmp (rax) 0)
(ite (zf)
  (stmts
    (jtrue tmp.0)  # cond1 held: set tmp and jump
  )
  (stmts
    (cmp (rbx) 0)
    (ite (zf)
      (stmts
        (jtrue tmp.0)  # cond2 held: set tmp and jump
      )
      (stmts)
    )
  )
)
(ite tmp.0
  (stmts
    # body — reached if tmp.0 was set
  )
  (stmts
    # otherwise
  )
)
```

The `jtrue`s become jumps into the appropriate branch of the outer `ite tmp.0`,
with `tmp.0` never occupying a register. Compare the `lab`/`jmp` form, where the
same merge is one label several branches jump to and no variable is invented for
it.

## Addressing modes

Memory addressing in `nifasm` prefers high-level constructs that preserve semantic information. Field names and array element types are kept in the assembler until linking, making the code readable while allowing the assembler to compute offsets automatically.

All addressing mode constructs (`(dot ...)`, `(at ...)`, and `(mem ...)`) produce typed expressions. The type system ensures that:
- Address expressions have pointer types (`ptr` or `aptr`)
- Memory operations dereference pointer types to their element types
- Only `aptr` types allow pointer arithmetic (array indexing)

### Object field access

The `(dot <base> <fieldname>)` construct computes the address of an object field by name. The assembler computes the field offset from the type information.

**Type rules:**
- If `base` has type `(ptr Type)` where `Type` is an object type with field `fieldname` of type `T`, then `(dot base fieldname)` has type `(ptr T)` - a pointer to the field's type.
- A **stack slot** is addressed relative to the frame, so its base is two operands on x86-64 — `(dot <framereg> <slot> <fieldname>)` — and one on AArch64, where the slot carries its own base: `(dot <slot> <fieldname>)`. Either way the result is `(ptr T)`.
- If `base` has type `Type` directly (not a pointer and not a stack slot), then `(dot base fieldname)` is invalid.
- Example: If `p.0` has type `(ptr Point.0)` and `Point.0` has field `x.0` of type `(i 64)`, then `(dot p.0 x.0)` has type `(ptr (i 64))`.

To actually load from or store to this address, the `(mem ...)` construct must be used explicitly. This makes memory operations explicit and allows the assembler to distinguish between address computation (`lea`) and memory access (`mov`, `add`, etc.).

```
(type :Point.0 (object (fld :x.0 (i 64)) (fld :y.0 (i 64))))
(var :p.0 (rdi) (ptr Point.0))

(mov (rax) (mem (dot p.0 x.0)))   # loads p.x into rax
                                  # lowered to: mov rax, [rdi+0]
(mov (rbx) (mem (dot p.0 y.0)))   # loads p.y into rbx
                                  # lowered to: mov rbx, [rdi+8]

# Address computation (without loading):
(lea (rax) (dot p.0 x.0))         # computes address of p.x into rax
                                  # lowered to: lea rax, [rdi+0]

# The same, for a stack-allocated Point on x86-64:
(var :q.0 (s) Point.0)
(mov (rax) (mem (dot (rsp) q.0 x.0)))
```

### Array indexing

The `(at <base> <index>)` construct computes the address of an array element. The base must be an `aptr` (array pointer) type, and the assembler uses the element type's size to compute the scale factor. Like `(dot ...)`, this produces an address expression that must be wrapped in `(mem ...)` to perform a memory operation.

**Type rules:**
- If `base` has type `(aptr T)` and `index` has an integer type, then `(at base index)` has type `(ptr T)` - a pointer to a single element.
- A stack slot of type `(array T <count>)` is indexed the same way its fields are selected: `(at <framereg> <slot> <index>)` on x86-64, `(at <slot> <index>)` on AArch64. The result is `(ptr T)`.
- Note: `(at ...)` requires either `aptr` or a stack-allocated array type, not `ptr` to a single element. This enforces that pointer arithmetic (indexing) is only allowed on array pointers or stack arrays, not single-element pointers.
- Example: If `arr.0` has type `(aptr (i 32))`, then `(at arr.0 index)` has type `(ptr (i 32))`.

```
(var :arr.0 (rsi) (aptr (i 32)))  # array pointer to int32s

(mov (rax) (mem (at arr.0 (rcx))))  # loads arr[rcx] into rax
                                    # lowered to: mov rax, [rsi+rcx*4]
                                    # (element size 4 bytes used as scale)

# Address computation (without loading):
(lea (rax) (at arr.0 (rcx)))        # computes address of arr[rcx] into rax
                                    # lowered to: lea rax, [rsi+rcx*4]

# A stack-allocated array on x86-64:
(var :buf.0 (s) (array (i 32) 6))
(mov (rax) (mem (at (rsp) buf.0 (rcx))))
```

An immediate index folds into the displacement for any element size. A **register** index has to become a scale factor in the addressing mode, and every target accepts the same four: 1, 2, 4 and 8 (x86-64's SIB scale, AArch64's and Thumb-2's shifted register offset). Anything else needs a multiply into a temporary — and managing temporaries is not the assembler's job, so it will not invent one. Either the code generator supplies it, as a third operand:

```
(mov (rax) (mem (at points.0 (rcx) (rdx))))   # rdx = scratch: rdx = points + rcx*16
```

or the assembler rejects the program. The scratch must not be the base register (it is written before the base is read); being the same register as the index is fine and is allowed on purpose, because under register pressure it may be the only free choice.

### Combined addressing

These constructs can be nested to access fields of array elements or arrays within structs. Remember that `(dot ...)` and `(at ...)` produce address expressions, so `(mem ...)` is still required for memory operations:

```
(type :Point.0 (object (fld :x.0 (i 64)) (fld :y.0 (i 64))))
(var :points.0 (rdi) (aptr Point.0))  # array pointer to Points

(mov (rax) (mem (dot (at points.0 (rcx) (rdx)) x.0)))  # loads points[rcx].x
```

`Point.0` is 16 bytes, which is not a legal scale, so this one needs the scratch register
described above; with a 4- or 8-byte element the two-operand `(at points.0 (rcx))` folds
into the addressing mode directly.

### Explicit addressing

For cases where high-level constructs are insufficient (e.g., pointer arithmetic, manual offset calculations, or compatibility with existing code), explicit memory addressing is available. However, this forfeits some of the type safety benefits:

```
(mem <base> <offset>)                        # [base + offset]
(mem <base> <index> <scale>)                 # [base + index * scale]
(mem <base> <index> <scale> <offset>)        # [base + index * scale + offset]
```

The explicit addressing modes use immediate values for offsets and scale factors. When possible, prefer `(dot)` and `(at)` constructs as they are type-checked and more readable.

Note that `(mem ...)` is required for all memory operations. It can wrap address expressions like `(dot ...)` and `(at ...)`, or it can be used directly with registers and immediate offsets for low-level operations.

**Type rules for `(mem ...)`:**
- If `address` has type `(ptr T)` or `(aptr T)`, then `(mem address)` has type `T` - it dereferences the pointer to get the pointed-to type.
- Example: `(mem (dot p.0 x.0))` where `(dot p.0 x.0)` is `(ptr (i 64))` has type `(i 64)`.
- Example: `(mem (at arr.0 index))` where `(at arr.0 index)` is `(ptr (i 32))` has type `(i 32)`.
- `(cast T <memoperand>)` retypes an access, and thereby sizes it.
- Memory operations require explicit `(mem ...)` - address expressions are not automatically dereferenced.


## Instructions

The complete instruction set of every target — mnemonic, operand shape and meaning — is
[instructions.md](instructions.md), which is also the file the enums are generated from.
It is the authoritative list; there is deliberately no second copy of it here.

What is worth knowing about it in prose:

- Instructions follow the pattern `(instr <dest> <src>)`, or `(instr <operand>)` for unary
  ones, unless the table says otherwise. Two-operand forms read and write `dest`, and
  AArch64's three-operand forms are spelled with a `3` suffix (`add3`, `mul3`, …).
- The `Enums` column says which target a tag belongs to: `X64Inst` (x86-64), `A64Inst`
  (AArch64), `MInst` (Thumb-2 / Cortex-M). A row naming more than one is the
  *cross-target* vocabulary — `mov`, `lea`, `add`, `sub`, `cmp`, `call`, `ret`, `lab`,
  `ite`, `loop`, `stmts`, `scope`, `kill`, `rebind` — and it is what lets most of a code
  generator stay platform independent.
- Instructions whose register operands are fixed by the hardware still name them
  explicitly: `(div (rdx) (rax) <src>)` and `(idiv (rdx) (rax) <src>)` spell out the
  dividend/quotient/remainder registers even though the encoding has no choice, so the
  type checker can see the clobber.
- Memory operands always go through `(mem ...)`, as described under *Addressing modes*.
- `(ite ...)` and `(loop ...)` are lowered to conditional and unconditional jumps by the
  assembler.
- x86-64 atomics are the `(lock <instr>)` prefix over a memory-modifying instruction, plus
  the inherently atomic `xchg`/`xadd`/`cmpxchg`/`cmpxchg8b` and the `mfence`/`sfence`/
  `lfence`/`pause` fences. AArch64 uses the exclusive-monitor pairs `ldaxr`/`stlxr`, the
  acquire/release `ldar`/`stlr`, and `dmb`/`clrex`.
- `(syscall)` (x86-64) and `(svc)` (AArch64) issue a raw kernel trap; `(syproc ...)`
  declares a proc as one, so a call site is type-checked like any other.


## Generic register names

It turns out that for a code generator targeting `nifasm` most of its logic can be kept platform independent; the most interesting instruction set (ARM, x86, ...) specific aspect is the number of available registers. Dedicated names like `(rax)` are an obstacle to the reusability of a code generator. Thus x86-64's first eight registers also answer to numeric names:

| register name | alias for |
|---------------|-----------|
| `(r0)`        | `(rax)`   |
| `(r1)`        | `(rbx)`   |
| `(r2)`        | `(rcx)`   |
| `(r3)`        | `(rdx)`   |
| `(r4)`        | `(rsi)`   |
| `(r5)`        | `(rdi)`   |
| `(r6)`        | `(rbp)`   |
| `(r7)`        | `(rsp)`   |
| `(r8)`..`(r15)` | already numeric |

The number of available registers varies by platform: x86-64 provides 16 general-purpose registers, while AArch64 provides 31 (`(x0)`..`(x30)`, with `(w0)`..`(w30)` naming their 32-bit halves, plus `(sp)`, `(xzr)` and the aliases `(fp)` = x29 and `(lr)` = x30). Code generators should be aware of the target platform's register count when making allocation decisions.

In practice a code generator abstracts over the register *file* anyway — arkham does it with a `MachineDesc` per target rather than by leaning on the numeric aliases — so this is a convenience, not the portability mechanism.


## Reserved registers

Some architectures have limited immediate value ranges for memory addressing. When an offset the assembler computed exceeds the encodable limit, the assembler must use a scratch register to compute the address. It takes one without asking:

| Architecture | Assembler scratch | Immediate limit |
|--------------|-------------------|-----------------|
| x86-64 | (none needed) | ±2GB — 32-bit displacements always suffice |
| AArch64 | x17, and x16 for the macOS TLV thunk | ±4KB / ±512B |

On AArch64 the ABI already reserves `x16` (IP0) and `x17` (IP1) for linker-generated code — veneers for long branches, PLT entries — so any call may corrupt them and no code can rely on them across one anyway. nifasm exploits exactly that.

**Implications for code generators:**

- Do not allocate variables to x16/x17, and do not expect a value put there to survive the next instruction the assembler expands. (This is a contract, not a check: nifasm does *not* reject code that names them. arkham keeps them out of its pools — `ReservedRegs` in `src/arkham/machine.nim`.)
- Everything else is yours.
- You do not have to account for large frame offsets. The assembler synthesizes the address through its scratch register when needed, with the type checking intact.


## Module System

nifasm's module system is based on NIF's symbol syntactic structure, which uses module suffixes to identify symbols from different modules. This enables separate compilation, dead code elimination, and generic instance deduplication.

### NIF Symbol Structure

NIF symbols follow a structured naming convention that encodes module information:

```
<basename>.<id>.<dedup-key>.<module-suffix>
```

Where:
- `<basename>` is the symbol's base name (e.g., `foo`, `bar`)
- `<id>` is a unique identifier (typically `0` for the first occurrence)
- `<dedup-key>` is an optional generic instance key (for deduplication)
- `<module-suffix>` is the module name (empty for main module)

**Examples:**
- `foo.0` - Local symbol in the current module (no module suffix)
- `bar.0.mymodule` - Symbol `bar.0` from module `mymodule`
- `baz.0.key1.mymodule` - Generic instance with dedup key `baz.0.key1` from `mymodule`. Note how the dedup key is everything before the module suffix, not just the `key1` part!

### Module Suffix Rules

1. **Current Module**: Symbols without a module suffix belong to the **current module** being parsed. When parsing the main module file, symbols without suffixes belong to the main module. When parsing a foreign module file, symbols without suffixes belong to that foreign module.

2. **Foreign Modules**: Foreign modules are introduced by using a symbol from them. These symbols have a different module suffix. The module suffix is everything after the last dot in a symbol name (if there are at least 2 dots). When a symbol has a module suffix, it explicitly identifies which module it belongs to, regardless of which file it's defined in.

3. **Symbol Lookup**: Symbols with module suffixes and symbols without module suffixes are **different symbols**, not aliases:
   - `foo.0` is a **local symbol** in the current module
   - `foo.0.mymodule` is a **global symbol** from module `mymodule`
   - These are distinct symbols - `foo.0` in module A is different from `foo.0` in module B, and both are different from `foo.0.mymodule`
   - When looking up a symbol with a module suffix (e.g., `foo.0.mymodule`), nifasm:
     1. Extracts the module name from the suffix
     2. Loads that foreign module if needed
     3. Looks up the basename (`foo.0`) in that module's scope
   - Foreign symbols are stored in the scope using their basename (without module suffix) for lookup purposes

### Foreign Module Loading

Foreign modules are loaded **on-demand** when their symbols are first referenced:

1. When a symbol lookup fails in the current scope, nifasm checks if the symbol name contains a module suffix
2. If a module suffix is detected, nifasm attempts to load the foreign module:
   - First tries `<module-name>.asm.nif` (what arkham writes)
   - Falls back to `<module-name>.nif`
   - Searches in the same directory as the main module file
3. "Loading" means reading the module's embedded NIF `.index` (symbol → byte offset) and keeping the stream open. **No declaration is parsed at this point.** A foreign module without that index is rejected — it is what makes the loading lazy, so a hand-written module has to be run through a NIF indexer before it can be imported
4. Each declaration is parsed the first time its own name is followed, and code is generated for it only if it is actually reachable (see *Dead Code Elimination* below)

**Example:**

```nifasm
# main.nif
(stmts
  (type :Point.0 (object (fld :x.0 (i 64)) (fld :y.0 (i 64))))
  (proc :main.0
    (params)
    (result :ret.0 (rax) (i 64))
    (clobber (rax))
    (stmts
      (prepare foo.0.othermodule
        (call)
        (mov (rax) (res ret.0))
      )
      (ret)
    )
  )
)
```

```nifasm
# othermodule.nif
(stmts
  (proc :foo.0.othermodule
    (params)
    (result :ret.0 (rax) (i 64))
    (clobber)
    (stmts
      (mov (rax) 42)
      (ret)
    )
  )
)
```

When `main.nif` references `foo.0.othermodule`, nifasm automatically loads `othermodule.nif` — provided that file carries its `(.index)`, as everything arkham writes does.

### Dead Code Elimination

The module system enables dead code elimination for both main module and foreign modules:

1. **Entry Point**: The entry point can be either:
   - Top-level instructions (not declarations) in the main module - these are generated immediately
   - A proc named `_start` or `main.0` - these procs are generated immediately as the entry point
   - If both exist, top-level instructions take precedence

2. **Symbol Marking**: When symbols are referenced via `lookupWithAutoImport` (during code generation), they are marked as used and added to a pending list for code generation.

3. **On-Demand Generation**: Both main module and foreign module symbols are subject to dead code elimination:
   - Main module procs (except `_start`), rodata, gvars, etc. are only generated if they are referenced from the entry point or other reachable code
   - Foreign module symbols are only generated if they are referenced

4. **Lazy Code Generation**: After the entry point is processed, nifasm generates code for all pending symbols (both main module and foreign) that were actually referenced, following the dependency chain.

This means unused functions, types, and globals from both the main module and foreign modules are never generated, reducing binary size.

### Module File Resolution

When loading a foreign module, nifasm searches for module files in the following order:

1. `<base-dir>/<module-name>.asm.nif` - what arkham writes (preferred)
2. `<base-dir>/<module-name>.nif` - fallback

Where `<base-dir>` is the directory containing the main module file being assembled.

If neither file is found, nifasm reports an error: `"Foreign module file not found: <module-name>"`.


## Generic Instance Deduplication

nifasm automatically deduplicates generic instances across modules to avoid generating duplicate code for the same generic instantiation — the job a COMDAT section does in a classical object format. Every module that needs an instantiation emits its own copy, and the copies must collapse onto one definition. This is based on extracting a deduplication key from the symbol's structure.

### Deduplication Key Extraction

The deduplication key is the symbol name **minus its module suffix**. Dropping the module is sound exactly when what remains means the same thing in every module, and that is a property of the name's *shape*, which the [NIF spec](https://github.com/nim-lang/nifspec/blob/master/doc/nif-spec.md) defines. A global symbol is

```
<ident>.<disamb>.<module>            # no key: this symbol belongs to this module
<ident>.<disamb>.<key>.<module>      # keyed: `key` is a generic instantiation
```

The **key slot** answers *which* instantiation of `<ident>.<disamb>` this is. Every importing module derives the same key independently, so `<ident>.<disamb>.<key>` is a cross-module identity — which is precisely what makes the copies mergeable:

- `foo.0` → no dedup key (local symbol)
- `foo.0.mymodule` → no dedup key (module suffix only)
- `foo.0.Iabcdefgh.mymodule` → dedup key: `foo.0.Iabcdefgh`

nifasm does not decide on its own which names occupy that slot. It calls `symparser.isInstantiation`, the toolchain's single implementation of the rule, shared with nimony (whose DCE and `lengcgen` key on the same one). A name that names a role private to one module — a closure environment, a vtable, a coroutine frame — never reaches this test, because the mint site keeps the tag *inside the identifier* (`` outer`env.0 ``, `symparser.derivedName`) rather than putting it in the key slot where it would promise a cross-module identity it does not have.

### Deduplication Process

1. **First Occurrence**: When a symbol with a dedup key is first encountered:
   - The dedup key is registered in the deduplication table
   - The symbol's full name becomes the **canonical** name for that key
   - The symbol is added to the pending list for code generation

2. **Subsequent Occurrences**: When another symbol with the same dedup key is encountered:
   - The deduplication table is checked
   - If the key exists, the new symbol is **merged** with the canonical one
   - The new symbol is **not** added to the pending list
   - All references to the new symbol resolve to the canonical symbol

3. **Code Generation**: Only the canonical symbol is generated, even if multiple modules reference the same generic instance.

### Example: Generic Function Deduplication

Consider a generic `max` function instantiated for `int64` in two modules; `Ii64` stands in for the key nimony actually mints, a hash of the instantiated arguments:

**Module A (`moduleA.nif`):**
```nifasm
(stmts
  (proc :max.0.Ii64.moduleA
    (params
      (param :a.0 (rdi) (i 64))
      (param :b.0 (rsi) (i 64))
    )
    (result :ret.0 (rax) (i 64))
    (clobber)
    (stmts
      (cmp a.0 b.0)
      (mov (rax) b.0)
      (cmovg (rax) a.0)
      (ret)
    )
  )
)
```

**Module B (`moduleB.nif`):**
```nifasm
(stmts
  (proc :max.0.Ii64.moduleB
    (params
      (param :a.0 (rdi) (i 64))
      (param :b.0 (rsi) (i 64))
    )
    (result :ret.0 (rax) (i 64))
    (clobber)
    (stmts
      (cmp a.0 b.0)
      (mov (rax) b.0)
      (cmovg (rax) a.0)
      (ret)
    )
  )
)
```

**Main Module (`main.nif`):**
```nifasm
(stmts
  (proc :main.0
    (params)
    (result :ret.0 (rax) (i 64))
    (clobber (rdi) (rsi) (rax))
    (stmts
      (prepare max.0.Ii64.moduleA
        (mov (arg a.0) 10)
        (mov (arg b.0) 20)
        (call)
        (mov (rbx) (res ret.0))
      )
      (prepare max.0.Ii64.moduleB
        (mov (arg a.0) 30)
        (mov (arg b.0) 40)
        (call)
        (mov (rcx) (res ret.0))
      )
      (mov (rax) 0)
      (ret)
    )
  )
)
```

**Deduplication Behavior:**

1. When `max.0.Ii64.moduleA` is first referenced:
   - Dedup key `max.0.Ii64` is extracted
   - `max.0.Ii64.moduleA` becomes the canonical name
   - Symbol is added to pending list

2. When `max.0.Ii64.moduleB` is referenced:
   - Same dedup key `max.0.Ii64` is extracted
   - Key already exists in dedup table
   - `max.0.Ii64.moduleB` is merged with `max.0.Ii64.moduleA`
   - **Only one instance** of the function is generated (the canonical one)

3. Both call sites resolve to the same generated function, avoiding code duplication.

### Benefits

1. **Code Size Reduction**: Generic instances are generated only once, even when used from multiple modules
2. **Consistency**: All modules using the same generic instance get the same code
3. **Automatic**: No manual intervention required - deduplication happens transparently
4. **Link-Time Optimization**: Works across module boundaries without requiring whole-program analysis

### Limitations

- Deduplication only works for symbols with a key segment (see *Deduplication Key Extraction*)
- Local symbols and plain module-qualified symbols are not deduplicated
- The canonical symbol is determined by the **first occurrence** encountered during assembly
- Modules must be available at assembly time (not link time) for deduplication to work

