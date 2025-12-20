# nifasm: Structured & Typed Assembler

Design goals:

- Make the development of native code generators almost as cheap as generating C++ or LLVM code.
- Complete control over the emitted binary. It is a real assembler, not an abstract machine!
- Compute what is "easy enough" directly in the assembler (object field offsets, stack offsets)
  so that it does not even have to be verified.
- Bring **structured programming** as NJVL does it to assembler so that validation passes can
  be done extremely cheaply without complex fixpoint computations.
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
- Compatibility with native object files and DWARF. Instead `nifasm` will eventually ship its own
  debugger. Thanks to NIF we always have column precise source code information for every instruction!


## Type system

The assembler is unlike any other in that it keeps the control flow structured and every expression is typed. The type system is a simplification of Nimony's.

The type system's goal is not only type checking but also facilitates the computation of sizes, alignments and offsets. The idea is that both control flow as well as object field names can stay in the assembler so that everything is very readable. The architecture welcomes the idea that a programmer can optimize at the assembler level and yet everything stays as safe, readable and abstract as possible.

A key insight here is while assembler does not allow unnamed temporary expressions there is no reason it cannot keep field names instead of offsets (no control is lost). Likewise thanks to the ideas of the NJ IR ("no jumps IR") structured control flow is easy enough to map to labels and offsets (no control is lost either).


### Type atoms

Type atoms are `(bool)`, `(i N)` (signed integer of N bits), `(u N)` (unsigned integer of N bits), `(f N)` (float of N bits). Hardware flags are typically mapped to the type `(bool)`.


### Compound types

Compound types are `(ptr <ElementType>)`, `(aptr <ElementType>)`, `(array <ElementType> <count>)` and finally `Symbol` where `Symbol` has been declared via a `type` construct:

```
(type :Name.0 (object (fld :Field.0 <Type 1>) ...) <optional_pragmas>)
(type :Name.1 (union (fld :Field.0 <Type 1>) ...) <optional_pragmas>)
(type :Name.2 (proc <ReturnType> <Type 1> <Type 2> ...))
```

**Object vs Union:**
- `object`: Fields are laid out sequentially in memory. The size of an object is the sum of all field sizes. Each field has a different offset.
- `union`: All fields overlay each other at offset 0. The size of a union is the maximum size of all fields. Writing to one field can affect the values read from other fields since they share the same memory.

Calling conventions are not modelled via the type system; instead every function declaration is very explicit how it expects its parameter to be passed. Clobbered registers are part of this declaration! Custom calling conventions are an easy and effective way to get more speed from high level code. For example, an abort-like function should announce that no registers are clobbered so that the efficiency of the caller's register handling is not affected. This is a generalization of the idea that "leaf functions" can use registers more aggressively.

The difference between `ptr` and `aptr` is that `ptr` points to a single element and `aptr` to an array of elements of unspecified size. Pointer arithmetic is only allowed for the type `aptr`, not for `ptr`.


## Registers

Registers are typically not written directly, instead if they are used as local variables, a variable declaration attaches a name to the register. The assembler keeps track of the used registers and ensures that registers are not used inconsistently! For example, a register that is currently used for a local variable cannot be used as a function argument directly. Instead a `mov` instruction must be used regardless: `(mov arg.0 my.local)`. The assembler elides the instruction if the registers are the same.


## Stack slots

Declarations are either bound to a register or to a stack slot. Instead of a register name the `(s)` tag is used then. The `(s)` tag explicitly indicates storage location (stack allocation), which is separate from the type information. Since we know the type of every declaration the slot's offset is computed by `nifasm`. Again, this keeps the code more readable. An instruction can use the tag `(ssize)` to access the maximum required stack size. This is typically used in function prologs and epilogs.

Stack-allocated variables can have compound types (arrays, objects). When a variable name bound to a stack slot is used in address expressions (`(dot ...)`, `(at ...)`), the assembler treats the variable name as representing the address of the stack-allocated value (i.e., the stack pointer plus the computed offset). This allows natural access to stack-allocated arrays and objects without requiring explicit address computation.

Note: The `(s)` tag is required for clarity - it explicitly separates storage location from type. For example, `(var :arr (s) (array (i +32) +6))` makes it clear that `(s)` is about where the variable is stored (stack), while `(array (i +32) +6)` is about its type (array of 6 int32s).

```
(var :arr (s) (array (i +32) +6))  # stack array of 6 int32s
(var :p (s) Point)                 # stack object of type Point

(mov (rax) (mem (at arr (rcx))))  # loads arr[index] - uses [rsp+offset+index*4]
(mov (rbx) (mem (dot p x)))       # loads p.x - uses [rsp+offset+field_offset]
```



## Proc calls

In `nifasm` every callsite is type-checked, a proc declaration looks like:

```
(proc :foo.0 
  (params
    (param :arg.0 (rax) (i +64))
    (param :arg.1 (rcx) (u +1))
  )
  (ret :ret.0 (rax) (i +64))
  (clobber
    (rdi) (rbx)
  )
  (body ...)
)
```

## Call instruction

The `call` instruction differs more so from a traditional assembler than the other instructions. The reason is that `nifasm` checks for parameter passing consistencies. Every parameter must be named. This way the control over scheduling decisions remains, in other words it is possible to evaluate the expression that is passed to parameter 3 before the expression that is passed to parameter 1. This might not be overly useful, but machine code naturally allows for this flexibility.

For example:

```

(call foo.0
  (mov arg.0 +56)
  (mov arg.1 +1)
)
```

Return values are declared in a proc's `(result ...)` section and must be bound at
each call site as well. Use another `mov` inside the `call` block with the
result name as the source and a register-backed destination (plain registers or
register-allocated variables). Stack slots are rejected and every result must be
bound exactly once. If the destination register differs from the callee's return
register, `nifasm` inserts the move automatically:

```
(call foo.0
  (mov arg.0 +56)
  (mov ret.0 myResult)
)
```

Within a `call` the named arguments are put into the scope and have to be used to make parameter passing explicit and checkable! It is checked that every argument is assigned a value and only once.


## Local variables

Since local variables are described precisely, it is possible to detect code generation bugs at translation time. Consider:

```
(var :my.local (rdi) (i +64))
(call foo.0
  (mov arg.0 +56)
  (mov arg.1 +1)
)
(use my.local) # bug detected: foo.0 clobbers register rdi!
```


## Control flow

As in NJVL the control flow consists of `(loop)` and `(ite)` (if-then-else) constructs. Control flow variables are also supported via the `cfvar` and `jtrue` tags.

### Control flow variables

Control flow variables (`cfvar`) are special boolean variables used to represent control flow in a structured way. They bridge the gap between high-level structured control flow and low-level jumps.

**Declaration:**

```
(cfvar :name.0)
```

Declares a control flow variable named `name.0`. Control flow variables are always implicitly of type `(bool)` and implicitly initialized to `false`. No type annotation or initializer should be provided.

**Properties:**
- Always initialized to `false`
- Can only be set to `true` via the `jtrue` instruction
- Have monotonic behavior: once set to `true`, they stay `true`
- Are **always virtual** in nifasm: they are never materialized into actual registers or memory
- The assembler always maps them to jumps

### The `jtrue` instruction

The `jtrue` instruction sets one or more control flow variables to `true`:

```
(jtrue cfvar1.0)
(jtrue cfvar1.0 cfvar2.0 cfvar3.0)  # Can set multiple cfvars at once
```

**Semantics:**
- Sets the specified control flow variable(s) to `true`
- In nifasm, `jtrue` is **always lowered to an unconditional jump** to the appropriate target
- The jump target is determined by the control flow structure containing the `jtrue`

### Using `cfvar` with `ite`

When a control flow variable is used as the condition in an `ite` construct, it has **special semantics** - it does not produce or evaluate a condition at all! Instead:

```
(ite cfvar.0
  (stmts
    # "then" branch - executed if cfvar.0 was set to true
    (mov (rax) +1)
  )
  (stmts
    # "else" branch - executed if cfvar.0 is still false
    (mov (rbx) +3)
  )
)
```

**Behavior:**
- If `cfvar.0` was set to `true` (via `jtrue`), the "then" branch executes
- If `cfvar.0` is still `false`, the "then" branch is skipped and the "else" branch executes
- The assembler recognizes this pattern and generates appropriate jump instructions

This is different from using a hardware flag or register as a condition. With a cfvar, there is no condition evaluation - the control flow was already determined by previous `jtrue` instructions.

### Testing hardware flags

The `ite` construct can also test hardware flags directly:

```
(ite (of) # test overflow flag
  (stmts
    (mov (rax) +1)
  )
  (stmts
    (mov (rbx) +3)
  )
)
```

Common flags include:
- `(zf)` - zero flag
- `(of)` - overflow flag
- `(cf)` - carry flag
- `(sf)` - sign flag
- `(pf)` - parity flag

### Loop construct

Loops follow the same pattern as in NJVL:

```
(loop
  (stmts ...) # before the condition
  (zf) # condition (can be a flag or cfvar)
  (stmts ...) # body - executed when condition is true
  (stmts ...) # after - executed when loop exits
)
```

A `loop` always has 4 sections: setup, condition, body, and after.

### Example: Control flow variable usage

Here's how `cfvar` and `jtrue` work together:

```
# Translate: if cond1 or cond2: body else: otherwise

(cfvar :tmp.0)
(cmp (rax) +0)
(ite (zf)
  (stmts
    (jtrue tmp.0)  # If cond1 is true, set tmp and jump
  )
  (stmts
    (cmp (rbx) +0)
    (ite (zf)
      (stmts
        (jtrue tmp.0)  # If cond2 is true, set tmp and jump
      )
      (stmts)
    )
  )
)
(ite tmp.0  # Special case: test cfvar without condition
  (stmts
    # body - executed if tmp.0 was set to true
  )
  (stmts
    # otherwise - executed if tmp.0 is still false
  )
)
```

The `jtrue` instructions are lowered to jumps that skip to the appropriate branch of the outer `ite tmp.0`. The assembler ensures this happens without materializing `tmp.0` into any register.

## Addressing modes

Memory addressing in `nifasm` prefers high-level constructs that preserve semantic information. Field names and array element types are kept in the assembler until linking, making the code readable while allowing the assembler to compute offsets automatically.

All addressing mode constructs (`(dot ...)`, `(at ...)`, and `(mem ...)`) produce typed expressions. The type system ensures that:
- Address expressions have pointer types (`ptr` or `aptr`)
- Memory operations dereference pointer types to their element types
- Only `aptr` types allow pointer arithmetic (array indexing)

### Object field access

The `(dot <base> <fieldname>)` construct computes the address of an object field by name. The base can be a register, a variable name, or another addressing mode. The assembler computes the field offset from the type information.

**Type rules:**
- If `base` has type `(ptr Type)` where `Type` is an object type with field `fieldname` of type `T`, then `(dot base fieldname)` has type `(ptr T)` - a pointer to the field's type.
- If `base` is a variable name bound to a stack slot with type `Type` (where `Type` is an object type), then `(dot base fieldname)` has type `(ptr T)`. The variable name is treated as representing the address of the stack-allocated object.
- If `base` has type `Type` directly (not a pointer and not a stack variable), then `(dot base fieldname)` is invalid.
- Example: If `p` has type `(ptr Point)` and `Point` has field `x` of type `(i +64)`, then `(dot p :x)` has type `(ptr (i +64))`.
- Example: If `p` is a stack variable `(var :p (s) Point)`, then `(dot p x)` has type `(ptr (i +64))` and is lowered to `rsp+offset+field_offset`.

To actually load from or store to this address, the `(mem ...)` construct must be used explicitly. This makes memory operations explicit and allows the assembler to distinguish between address computation (`lea`) and memory access (`mov`, `add`, etc.).

```
(type :Point (object (fld :x (i +64)) (fld :y (i +64))))
(var :p (rdi) (ptr :Point))

(mov (rax) (mem (dot p :x)))   # loads p.x into rax
                               # lowered to: mov rax, [rdi+0]
(mov (rbx) (mem (dot p :y)))   # loads p.y into rbx  
                               # lowered to: mov rbx, [rdi+8]

# Address computation (without loading):
(lea (rax) (dot p :x))         # computes address of p.x into rax
                               # lowered to: lea rax, [rdi+0]
```

### Array indexing

The `(at <base> <index>)` construct computes the address of an array element. The base must be an `aptr` (array pointer) type, and the assembler uses the element type's size to compute the scale factor. Like `(dot ...)`, this produces an address expression that must be wrapped in `(mem ...)` to perform a memory operation.

**Type rules:**
- If `base` has type `(aptr T)` and `index` has an integer type, then `(at base index)` has type `(ptr T)` - a pointer to a single element.
- If `base` is a variable name bound to a stack slot with type `(array T <count>)`, then `(at base index)` has type `(ptr T)`. The variable name is treated as representing the address of the stack-allocated array.
- Note: `(at ...)` requires either `aptr` or a stack-allocated array type, not `ptr` to a single element. This enforces that pointer arithmetic (indexing) is only allowed on array pointers or stack arrays, not single-element pointers.
- Example: If `arr` has type `(aptr (i +32))`, then `(at arr index)` has type `(ptr (i +32))`.
- Example: If `:arr` is a stack variable `(var :arr (s) (array (i +32) +6))`, then `(at :arr index)` has type `(ptr (i +32))` and is lowered to `[rsp+offset+index*4]`.

```
(var :arr (rsi) (aptr (i +32)))  # array pointer to int32s

(mov (rax) (mem (at arr (rcx))))  # loads arr[cx] into rax
                                  # lowered to: mov rax, [rsi+rcx*4]
                                  # (element size 4 bytes used as scale)

# Address computation (without loading):
(lea (rax) (at arr (rcx)))        # computes address of arr[cx] into rax
                                  # lowered to: lea rax, [rsi+rcx*4]
```

The index must be a register or variable. If the element size is not a power of two (or exceeds the maximum scale factor), the assembler rejects the program. It is not able to materialize the offset computation into a temporary register as the management of temporaries is not its job.

Note that different architectures have different scale factor limitations. For example, ARM64 supports scales of 1, 2, 4, 8, or 16 (implemented as left shift operations), while x86-64 supports scales of 1, 2, 4, or 8. The assembler enforces these constraints for the target platform.

### Combined addressing

These constructs can be nested to access fields of array elements or arrays within structs. Remember that `(dot ...)` and `(at ...)` produce address expressions, so `(mem ...)` is still required for memory operations:

```
(type :Point (object (fld :x (i +64)) (fld :y (i +64))))
(var :points (rdi) (aptr :Point))  # array pointer to Points

(mov (rax) (mem (dot (at points (rcx)) :x)))  # loads points[i].x
                                              # lowered to: mov rax, [rdi+rcx*16+0]
```

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
- Example: `(mem (dot p :x))` where `(dot p :x)` is `(ptr (i +64))` has type `(i +64)`.
- Example: `(mem (at arr index))` where `(at arr index)` is `(ptr (i +32))` has type `(i +32)`.
- Memory operations require explicit `(mem ...)` - address expressions are not automatically dereferenced.


## Instructions (x86-64)

`nifasm` supports the following instruction categories needed by a typical code generator. All instructions follow the pattern `(instr <dest> <src>)` or `(instr <operand>)` for unary operations, unless otherwise noted.

### Data movement

- `(mov <dest> <src>)` - Move/copy data between registers, memory, and immediates
- `(lea <dest> <address>)` - Load effective address (compute address without accessing memory)
- `(movapd <dest> <src>)` - Move aligned packed double-precision floating-point (XMM register to XMM register)
- `(movsd <dest> <src>)` - Move scalar double-precision floating-point

### Arithmetic operations

**Integer:**
- `(add <dest> <src>)` - Add
- `(sub <dest> <src>)` - Subtract
- `(mul <src>)` - Unsigned multiply (dest is implicit: rax, result in rdx:rax)
- `(imul <dest> <src>)` - Signed multiply
- `(div (rdx) (rax) <src>)` - Unsigned divide. Dividend is taken from rdx:rax (concatenated as 128-bit value). Quotient is stored in rax, remainder in rdx. The target registers must be explicitly specified even though they are fixed.
- `(idiv (rdx) (rax) <src>)` - Signed divide. Dividend is taken from rdx:rax (concatenated as 128-bit value). Quotient is stored in rax, remainder in rdx. The target registers must be explicitly specified even though they are fixed.

**Floating-point:**
- `(addsd <dest> <src>)` - Add scalar double-precision
- `(subsd <dest> <src>)` - Subtract scalar double-precision
- `(mulsd <dest> <src>)` - Multiply scalar double-precision
- `(divsd <dest> <src>)` - Divide scalar double-precision

### Bitwise operations

- `(and <dest> <src>)` - Bitwise AND
- `(or <dest> <src>)` - Bitwise OR
- `(xor <dest> <src>)` - Bitwise XOR
- `(shl <dest> <src>)` - Shift left (logical)
- `(shr <dest> <src>)` - Shift right (logical)
- `(sal <dest> <src>)` - Shift arithmetic left (alias for shl)
- `(sar <dest> <src>)` - Shift arithmetic right (signed)

### Unary operations

- `(inc <operand>)` - Increment by 1
- `(dec <operand>)` - Decrement by 1
- `(neg <operand>)` - Two's complement negation
- `(not <operand>)` - Bitwise NOT

### Comparison

- `(cmp <dest> <src>)` - Compare and set flags (subtract without storing result)
- `(test <dest> <src>)` - Logical AND and set flags (without storing result)

### Conditional set

These instructions set a byte register or memory location to 0 or 1 based on CPU flags from a previous `cmp` or `test`:

- `(sete <dest>)` / `(setz <dest>)` - Set if equal/zero (ZF = 1)
- `(setne <dest>)` / `(setnz <dest>)` - Set if not equal/not zero (ZF = 0)
- `(seta <dest>)` / `(setnbe <dest>)` - Set if above (unsigned >, CF=0 and ZF=0)
- `(setae <dest>)` / `(setnb <dest>)` / `(setnc <dest>)` - Set if above or equal (unsigned >=, CF=0)
- `(setb <dest>)` / `(setnae <dest>)` / `(setc <dest>)` - Set if below (unsigned <, CF=1)
- `(setbe <dest>)` / `(setna <dest>)` - Set if below or equal (unsigned <=, CF=1 or ZF=1)
- `(setg <dest>)` / `(setnle <dest>)` - Set if greater (signed >, ZF=0 and SF=OF)
- `(setge <dest>)` / `(setnl <dest>)` - Set if greater or equal (signed >=, SF=OF)
- `(setl <dest>)` / `(setnge <dest>)` - Set if less (signed <, SF≠OF)
- `(setle <dest>)` / `(setng <dest>)` - Set if less or equal (signed <=, ZF=1 or SF≠OF)
- `(seto <dest>)` - Set if overflow (OF=1)
- `(sets <dest>)` - Set if sign (SF=1)
- `(setp <dest>)` - Set if parity (PF=1)

### Conditional moves

These instructions move data if the condition is met. `dest` must be a register.

- `(cmove <dest> <src>)` / `(cmovz ...)` - Move if equal/zero
- `(cmovne <dest> <src>)` / `(cmovnz ...)` - Move if not equal/not zero
- `(cmova <dest> <src>)` / `(cmovnbe ...)` - Move if above
- `(cmovae <dest> <src>)` / `(cmovnb ...)` / `(cmovnc ...)` - Move if above or equal
- `(cmovb <dest> <src>)` / `(cmovnae ...)` / `(cmovc ...)` - Move if below
- `(cmovbe <dest> <src>)` / `(cmovna ...)` - Move if below or equal
- `(cmovg <dest> <src>)` / `(cmovnle ...)` - Move if greater
- `(cmovge <dest> <src>)` / `(cmovnl ...)` - Move if greater or equal
- `(cmovl <dest> <src>)` / `(cmovnge ...)` - Move if less
- `(cmovle <dest> <src>)` / `(cmovng ...)` - Move if less or equal
- `(cmovo <dest> <src>)` - Move if overflow
- `(cmovno <dest> <src>)` - Move if not overflow
- `(cmovs <dest> <src>)` - Move if sign
- `(cmovns <dest> <src>)` - Move if not sign
- `(cmovp <dest> <src>)` / `(cmovpe ...)` - Move if parity
- `(cmovnp <dest> <src>)` / `(cmovpo ...)` - Move if not parity

### Control flow

**Unconditional jumps:**
- `(jmp <label>)` - Jump to label

**Conditional jumps:**
- `(je <label>)` / `(jz <label>)` - Jump if equal/zero
- `(jne <label>)` / `(jnz <label>)` - Jump if not equal/not zero
- `(jg <label>)` - Jump if greater (signed)
- `(jng <label>)` - Jump if not greater (signed)
- `(jge <label>)` - Jump if greater or equal (signed)
- `(jnge <label>)` - Jump if not greater or equal (signed)
- `(ja <label>)` - Jump if above (unsigned)
- `(jna <label>)` - Jump if not above (unsigned)
- `(jae <label>)` - Jump if above or equal (unsigned)
- `(jnae <label>)` - Jump if not above or equal (unsigned)

**Function calls and returns:**
- `(call <target>)` - Call function (target can be label or register)
- `(ret)` - Return from function

### Stack operations

- `(push <operand>)` - Push onto stack
- `(pop <operand>)` - Pop from stack

### Atomic operations

Atomic operations on x86 are typically achieved by prefixing instructions with `(lock)`. This prefix is only valid for instructions that modify memory.

- `(lock (add <mem> <reg>))` - Atomic add
- `(lock (sub <mem> <reg>))` - Atomic subtract
- `(lock (inc <mem>))` - Atomic increment
- `(lock (dec <mem>))` - Atomic decrement
- `(lock (not <mem>))` - Atomic bitwise not
- `(lock (neg <mem>))` - Atomic negate
- `(lock (and <mem> <reg>))` - Atomic and
- `(lock (or <mem> <reg>))` - Atomic or
- `(lock (xor <mem> <reg>))` - Atomic xor

In addition, some instructions are inherently atomic or support atomic behavior:

- `(xchg <dest> <src>)` - Exchange. Atomic if one operand is memory.
- `(xadd <dest> <src>)` - Exchange and Add.
- `(cmpxchg <dest> <src>)` - Compare and Exchange.
- `(cmpxchg8b <mem>)` - Compare and Exchange 8 bytes.

Memory barriers and cache control:

- `(mfence)` - Memory Fence
- `(sfence)` - Store Fence
- `(lfence)` - Load Fence
- `(pause)` - Pause (for spin loops)
- `(clflush <addr>)` - Flush Cache Line
- `(prefetcht0 <addr>)` - Prefetch to all cache levels
- `(prefetchnta <addr>)` - Prefetch non-temporal

### Special

- `(nop)` - No operation
- `(syscall)` - System call
- `(lab <label>)` - Define label

### Notes

- Memory operands require the `(mem ...)` construct as described in the Addressing modes section
- Instructions operate on typed operands; the assembler verifies type compatibility
- The structured control flow constructs `(ite)` and `(loop)` are lowered to conditional jumps by the assembler


## Generic register names

It turns out that for a code generator targeting `nifasm` most of its logic can be kept platform independent; the most interesting instruction set (ARM, x86, ...) specific aspect is the number of available registers. Dedicated names like `(rax)` are an obstacle to the reusability of a code generator. Thus these aliases exist:

The number of available registers varies by platform: x86-64 provides 16 general-purpose registers (r0-r15), while ARM64 provides 31 (r0-r30). Code generators should be aware of the target platform's register count when making allocation decisions. The generic naming scheme allows the same code generator logic to work across platforms with minimal changes.

|----------------|-----------|
| register name  | alias for |
|----------------|-----------|
| r0             | rax       |
| r1             | rbx       |
| r2             | rcx       |
| r3             | rdx       |
| r4             | rsi       |
| r5             | rdi       |
| r6             | rbp       |
| r7             | rsp       |
| r8..r15        | already have the proper names |
|----------------|-----------|

