apply to all files in the repository

# You are working on \*\*ShadowStrike\*\*, a serious, enterprise-grade NGAV platform.

# 

# This is NOT a demo, NOT a toy, NOT a hobby project.

# 

# ShadowStrike is built to meet the standards set by enterprise security leaders in the NGAV/EDR space.

# 

# Every line of code must reflect \*\*enterprise, mission-critical quality\*\*.

# 

# ---

# 

# \## 1. Absolute Rules (Read First)

# 

# \- Write \*\*production-quality, enterprise-grade C++\*\*

# \- Assume code is:

# &nbsp; - audited

# &nbsp; - fuzzed

# &nbsp; - stress-tested

# &nbsp; - deployed on millions of endpoints

# \- No example code

# \- No placeholders

# \- No “simplified” logic

# 

# If something is unclear: \*\*search and read the codebase first\*\*.

# 

# ---

# 

# \## 2. Mandatory Codebase Awareness (NO GUESSING)

# 

# Before implementing \*\*any\*\* `.cpp` file:

# 

# 1\. Search the repository

# 2\. Read related `.hpp` and `.cpp` files

# 3\. Understand naming, ownership, and lifetimes

# 4\. Reuse existing infrastructure

# 

# ❌ Guessing variable names, class names, or function signatures is FORBIDDEN  

# ❌ Code that causes dozens of compiler errors due to guessing is unacceptable

# 

# If unsure: STOP and search.

# 

# ---

# 

# \## 3. Mandatory Infrastructure Reuse

# 

# You MUST inspect and reuse existing modules when applicable:

# 

# \- `Utils/`

# \- `HashStore/`

# \- `PatternStore/`

# \- `SignatureStore/`

# \- `ThreatIntel/`

# \- `Database/`

# \- `Whitelist/`

# 

# Rules:

# \- Do NOT reimplement hashing if `HashStore` exists

# \- Do NOT reimplement signatures if `SignatureStore` exists

# \- Do NOT create new helpers if `Utils` already provides them

# \- Always read headers AND implementations before using a module

# 

# Code reuse is \*\*enterprise discipline\*\*, not laziness.

# 

# ---

# 

# \## 4. Core Architectural Decisions (Non-Negotiable)

# 

# \### Singleton

# \- Use \*\*Meyers’ Singleton\*\*

# \- No globals

# \- No double-checked locking

# 

# \### PIMPL

# \- Required for complex classes

# \- Preserve ABI stability

# \- No implementation details in headers

# 

# \### RAII

# \- Every resource must clean itself automatically

# \- No manual lock/unlock

# \- No manual memory management

# 

# \### Thread Safety

# \- Always assume multi-threaded execution

# \- Prefer `std::shared\_mutex`

# \- Reads may be concurrent, writes exclusive

# 

# ---

# 

# \## 5. C++ Standards

# 

# \- C++20 is mandatory

# \- Prefer:

# &nbsp; - `std::unique\_ptr`

# &nbsp; - `std::shared\_ptr` only when ownership is shared

# &nbsp; - `std::span<>` for zero-copy views

# &nbsp; - `std::optional<>` instead of null pointers

# &nbsp; - `std::atomic<>` for counters

# \- No raw `new` / `delete`

# 

# Use `\[\[nodiscard]]` whenever ignoring a return value would be a bug.

# 

# ---

# 

# \## 6. Error Handling \& Logging

# 

# \- Never fail silently

# \- Always use existing logging infrastructure

# \- Errors must be:

# &nbsp; - explicit

# &nbsp; - actionable

# &nbsp; - traceable

# 

# Avoid vague logs like:

# \- “Failed”

# \- “Something went wrong”

# 

# ---

# 

# \## 7. Security Mindset

# 

# Assume:

# \- hostile input

# \- malformed files

# \- evasion attempts

# 

# Requirements:

# \- Validate all input

# \- Cap allocations

# \- Never trust file size, paths, or external data

# \- Never log sensitive material

# 

# ShadowStrike is a \*\*security product\*\*, not classroom code.

# 

# ---

# 

# \## 8. Performance Discipline

# 

# \- Avoid unnecessary allocations

# \- Do not degrade hot paths

# \- Prefer existing caches and indices

# \- Correctness > Performance > Cleverness

# 

# If a tradeoff exists, document it.

# 

# ---

# 

# \## 9. Output Expectations

# 

# When asked to implement a `.cpp` file:

# 

# \- Produce \*\*complete, compilable code\*\*

# \- No pseudocode

# \- No TODO stubs unless explicitly requested

# \- Code must integrate cleanly with the existing system

# 

# ---

# 

# \## Final Reminder

# 

# You are not writing “some C++ code”.

# 

# You are implementing a component of a \*\*real NGAV engine\*\* that must:

# \- detect real threats

# \- resist bypass attempts

# \- survive hostile environments

# 

# Act accordingly.

