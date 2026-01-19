# NJ - "No jumps"

NJ ("No jumps") is the intermediate representation used by nativenif for native code generation. It serves as a general purpose IR that nativenif exposes to compiler frontends, providing a high-level yet efficient way to represent computations and control flow for direct translation to machine code.

## Relationship to NIF and Nimony

NJ is built on top of NIF-26 (Nim Intermediate Format) and is the result of the NJ phase of the NJVL transformation pipeline.

## Overview

NJ is part of the NJVL ("No jumps, versioned locations") transformation pipeline. NJ simplifies control flow by eliminating unstructured jumps like `return` and `break`, replacing them with control flow variables (`cfvar`) and guards. This restores the inherent tree-like structure of control flow.

NJ incorporates phase-dependent versioned locations (VL) transformations. The VL step, which handles versioned location operations and optimizations, is now integrated into the compilation phases rather than being a separate pass. This allows for more adaptive optimization based on the current compilation context.

NJ focuses on control flow abstractions, making it suitable for exposing to compiler frontends that need to generate native code. It provides a structured way to represent:

- Expressions and operations
- Control flow constructs (conditionals, loops)
- Type information
- Variable and memory management
- Procedure calls and declarations

## Pipeline

The nativenif compilation pipeline processes NJ code through several phases:

1. **Type Checking and Validation**: NJ code is first type-checked and undergoes general validation checks that prove `requires` annotations and ensure correctness.

2. **Optimization**: An optimizer runs on the validated NJ code, consisting of:
   - **(Partial) Inliner**: Inlines procedures marked with `inline` and performs cost-based inlining decisions
   - **Copy Propagation**: Eliminates unnecessary variable copies by replacing uses with their definitions
   - **CSE (Common Subexpression Elimination)**: Identifies and eliminates redundant computations
   - **Induction Variable Analysis**: Optimizes loop variables and enables strength reduction

The optimizer works on NJ and produces NJ code, running it is optional though recommended.

3. **Code Generation**: The optimized NJ code is translated to nifasm (Native NIF Assembly), a low-level assembly language with static type checking.

4. **Assembly and Linking**: The nifasm assembler generates machine code and performs linking, producing the final executable.


## Expressions

Expressions in NJ represent computations that yield values. They include:

### Basic Operations
- `(at X Y)` - Array indexing: `X[Y]`
- `(deref X)` - Pointer dereference: `*X`
- `(dot X Y)` - Object field access: `X.Y`
- `(pat X Y)` - Pointer indexing: `X[Y]` (for pointer arithmetic)
- `(addr X)` - Address of operation: `&X`

### Literals and Constants
- `(nil T?)` - Nil pointer value of type T
- `(inf T?)` - Positive infinity for floating point type T
- `(neginf T?)` - Negative infinity for floating point type T
- `(nan T?)` - NaN value for floating point type T
- `(false)` - Boolean false
- `(true)` - Boolean true

### Arithmetic and Logical Operations
- `(add T X Y)` - Addition of X and Y with type T
- `(sub T X Y)` - Subtraction
- `(mul T X Y)` - Multiplication
- `(div T X Y)` - Division
- `(mod T X Y)` - Modulo
- `(neg X)` - Negation
- `(not X)` - Boolean negation
- `(bitand T X Y)` - Bitwise AND
- `(bitor T X Y)` - Bitwise OR
- `(bitxor T X Y)` - Bitwise XOR
- `(bitnot T X)` - Bitwise NOT
- `(shl T X Y)` - Left shift
- `(shr T X Y)` - Right shift (logical)
- `(ashr T X Y)` - Arithmetic right shift

### Comparison Operations
- `(eq T X Y)` - Equal
- `(neq T X Y)` - Not equal
- `(lt T X Y)` - Less than
- `(le T X Y)` - Less than or equal
- `(gt T X Y)` - Greater than (derived)
- `(ge T X Y)` - Greater than or equal (derived)

### Type Operations
- `(cast T X)` - Cast X to type T
- `(conv T X)` - Type conversion from X to T
- `(sizeof T)` - Size of type T
- `(alignof T)` - Alignment of type T
- `(offsetof T Y)` - Offset of field Y in type T

### Constructors
- `(oconstr T (kv Y X)*)` - Object constructor with key-value pairs
- `(aconstr T X*)` - Array constructor with elements

### Special Expressions
- `(ovf)` - Access overflow flag
- `(v X INT_LIT)` - Versioned location (for SSA-like representations)
- `(baseobj T INTLIT X)` - Object conversion to base type

## Statements

Statements represent actions and control flow:

### Variable Management
- `(var D P T X)` - Variable declaration with initializer
- `(gvar D P T X)` - Global variable declaration
- `(tvar D P T X)` - Thread-local variable declaration
- `(const D P T)` - Constant declaration
- `(result D P T X)` - Result variable declaration
- `(store X Y)` - Assignment: `X = Y` (note reversed operands for evaluation order)
- `(unknown X)` - Mark location X as having unknown contents

### Control Flow
- `(ite X S1 S2 S3?)` - If-then-else with optional join information
- `(itec X S1 S2 S3?)` - If-then-else that was originally a case statement
- `(loop S1 X S2 S3)` - Loop with (before-cond, cond, loop-body, after)
- `(stmts S*)` - Sequence of statements

### Procedure Calls
- `(call X X*)` - Procedure call with arguments

### Special Statements
- `(jtrue Y+)` - Set control flow variables to true (jump hint)
- `(cfvar D)` - Declare control flow variable (bool, initialized to false)
- `(kill Y)` - Mark variable Y as going out of scope
- `(keepovf X Y)` - Keep overflow flag from operation
- `(assume X)` - Assumption for optimization
- `(assert X)` - Assertion
- `(asm X+)` - Inline assembly

## Types

NJ includes type declarations and type constructors:

### Basic Types
- `(i INTLIT)` - Signed integer of specified bit width
- `(u INTLIT)` - Unsigned integer of specified bit width
- `(f INTLIT)` - Floating point of specified bit width
- `(c INTLIT)` - Character type of specified bit width
- `(bool)` - Boolean type
- `(void)` - Void return type
- `(pointer)` - Generic pointer type

### Composite Types
- `(ptr T)` - Pointer to type T
- `(array T X)` - Array of type T with size X
- `(flexarray T)` - Flexible array of type T
- `(aptr T TQC*)` - Pointer to array of T with qualifiers
- `(object .T (fld ...)*)` - Object type with fields
- `(union (fld ...)*)` - Union type with fields
- `(proctype . (params...) T P)` - Procedure type with parameters, return type, and pragmas

### Type Qualifiers
- `(atomic)` - Atomic qualifier
- `(ro)` - Read-only (const)
- `(restrict)` - Restrict qualifier
- `(cppref)` - C++ reference

## Declarations

- `(proc D ...)` - Procedure declaration
- `(type D ...)` - Type declaration
- `(param D P T)` - Parameter declaration
- `(fld D P T)` - Field declaration

## Pragmas and Annotations

Pragmas provide additional metadata:

- `(inline)` - Inline procedure
- `(noinline)` - Do not inline
- `(varargs)` - Variable arguments
- `(cdecl)`, `(stdcall)`, etc. - Calling conventions
- `(exportc X)` - Export with C name
- `(dynlib X)` - Dynamic library import
- `(threadvar)` - Thread-local variable
- `(noreturn)` - Procedure doesn't return
- `(noinit)` - No initialization
- `(packed)` - Packed structure
- `(align X)` - Alignment specification
- `(bits X)` - Bit field size
- `(was STR)` - Original name
- `(requires X)` - Precondition
- `(ensures X)` - Postcondition

## Control Flow Abstraction

The key innovation in NJ is its control flow abstraction, which provides a high-level representation of control flow that can be efficiently translated to machine code. This includes:

- **Control Flow Variables**: `(cfvar D)` declares boolean variables that represent control flow state, replacing unstructured jumps
- **Jump Hints**: `(jtrue Y+)` sets control flow variables to true, providing hints for jump generation
- **Join Points**: `(join Y INT_LIT INT_LIT INT_LIT)` handles control flow merges
- **Versioned Locations**: `(v X INT_LIT)` allows SSA-like representations for optimization
- **Phase-Dependent VL**: The versioned locations transformations are now integrated into compilation phases, allowing adaptive optimization

This abstraction makes NJ suitable for exposing to compiler frontends, as it provides the necessary control flow constructs while remaining close to the machine level for efficient code generation.

