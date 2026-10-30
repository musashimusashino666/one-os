# CR3 Write-Site Inventory

## Purpose and invariant

The source gate pins the reviewed CR3 writer functions and rejects new or relocated assembly-macro sites unless their inventory is explicitly updated and reviewed. The three reviewed writers are in **kernel/src/address_space.rs**:

- activate_supervisor_kernel_root
- switch_address_space
- switch_address_space_flush_local_tlb

This code-site gate is defense in depth. It does not prove that every bootloader mapping or physical alias has been classified.

## Source inventory and allowlist

CI scans Rust source under **kernel/** and **crates/oneos-core/**, excluding only generated target directories and VCS metadata. Symlinks, build.rs, custom package.build scripts, and native assembly inputs (.S, .s, .asm, .sx) fail closed.

The checked-in allowlist pins the current asm! call-site count per source file. global_asm! is allowed only at four reviewed sites in kernel/src/main.rs. naked_asm! is not allowed. The current macro_rules! definition count is also pinned for the two files that define local declarative macros. Adding, relocating, or removing sites fails CI until the allowlist and review are updated together.

The kernel package's resolved Cargo dependency closure is inspected with `cargo metadata --all-features --locked`; local path/workspace packages are allowed only when their resolved manifest is in the explicit source inventory or the reviewed `crates/oneos-core` package. This catches `workspace = true` dependencies and transitive local path crates instead of comparing manifest strings. Patch/replace tables and unreviewed custom Cargo targets are rejected. The only target rustflag permitted by `.cargo/config.toml` is `-C relocation-model=pic`. Compiler/linker wrappers, environment overrides, and alternate native/build-script inputs are rejected.

The resolved graph is not a source scan of every dependency. Registry packages are traversed as graph nodes so that local path crates anywhere below them are still detected, but registry package Rust files are not scanned by this policy. Assembly or CR3 writes originating in registry code are therefore outside the source gate's guarantee. The companion linked-ELF gate in PR #76 checks actual CR3-writing instructions in the normal linked kernel artifact; it does not retroactively make PR #73's source scan cover registry crates.

## Alias and source-loading deny rules

The inventory does not attempt general Rust namespace resolution or macro expansion. Instead, it denies source forms that could hide an assembly call or load code outside the inventory:

- Imports of asm!/global_asm! are accepted only through the explicit per-file import allowlist. Unreviewed import paths, aliases, public re-exports, qualified assembly-macro paths, wildcard imports, aliases of core::arch, and aliases of trusted macro roots are rejected.
- include!, #[macro_use], macro metavariable forwarding, and concat! are rejected.
- Assembly template arguments must be direct ordinary or raw string literals. Although Rust's inline-assembly grammar permits a macro invocation as a format string, the inventory rejects macro-expanded or computed templates so directive and CR3-writer checks always inspect the actual source text.
- `#[path = "..."]` and `#[cfg_attr(..., path = "...")]` module redirection attributes are rejected in every inventoried Rust source file; they could otherwise load code from outside the scanned package trees.
- Declarations that shadow core, std, alloc, or bootloader_api are rejected.
- Hexadecimal and Unicode escapes are rejected inside `asm!` and `global_asm!` template strings. Cooked and raw Rust template strings are decoded, then every statement is checked after newline, carriage-return, semicolon, and tab separators; an allowlist-external directive is rejected regardless of its position in the template. Unrelated Rust strings, including binary-format markers, remain valid.

Macro-call discovery uses a shared Rust-aware lexical scanner rather than regular expressions. It treats line comments and nested block comments as whitespace, ignores macro-like text inside comments and string/character literals, recognizes comments between an identifier and `!`, and balances parenthesis, bracket, and brace token trees. It is deliberately not a Rust name resolver or macro expander; unsupported or ambiguous assembly-template forms fail closed.

## Assembler directive policy

Every decoded assembler statement is checked. Statements beginning with a dot are rejected unless they are a non-emitting `.global` symbol export or a local `.L...:` label. In particular, `.reloc`, `.byte`, `.insn`, section switches, include directives, and assembler macro directives are not allowed in the source inventory. Indirect x86 `jmp` and `call` forms (AT&T `*operand` and Intel register/memory operands) are rejected because the source gate cannot prove their targets. Direct symbol calls and direct local-label branches remain permitted. This is a default-deny policy: unknown directive or control-flow forms must not be assumed harmless.

## CR3 root and optimized assembly checks

The focused CR3 checker verifies the source-level writer contract: exactly three CR3-writing asm! blocks, one in each reviewed function; expected signatures and root-handle types; checked root provenance; error handling and validation order before each write. It also verifies that CR3 templates bind directly to the reviewed source operands and preserve compiler ordering (no nomem).

CI separately validates optimized assembly for the reviewed CR3/PGE switch sequence, including CR4/PGE ordering and the required memory barrier. The final linked-ELF inspection lives in a separate PR so source and linked-artifact checks can be reviewed independently.

## Limits

This is a narrow code-site/source-loading gate, not a proof of whole-program macro expansion or registry dependencies' internals. The separate linked-ELF gate is required to detect instructions introduced after source assembly. Neither gate establishes global frame-wide W^X, complete root-registry coverage, or that every bootloader-created mapping is expected. Issues #46 and #26 remain open until their broader mapping-source and physical-alias criteria are independently verified.
