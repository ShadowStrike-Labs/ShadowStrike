# Rebuilding the vendored libyara

`libyara.lib` is YARA 4.5.4 built through vcpkg. It is vendored rather than built
in-tree, but it must stay reproducible: an auditable security product cannot ship
a binary dependency nobody can regenerate.

## Recipe

```powershell
vcpkg install yara[dotnet]:x64-windows
# then copy installed/x64-windows/lib/libyara.lib over vendor/yara_lib/libyara.lib
```

The `dotnet` feature is the reason this is not the stock `yara:x64-windows`
build. vcpkg leaves that module out by default, and a single unknown module in a
rule pack's import block fails the *entire* pack rather than only the rules that
use it - so one missing module can cost thousands of rules.

## Constraints the result must satisfy

The rest of the tree links against this, so a replacement must match:

- x64, Release, `/MD` (`MultiThreadedDLL`) - every project's Release CRT.
- Built against OpenSSL 3.x, because we link `libcrypto.lib` / `libssl.lib`
  import libraries for `libcrypto-3-x64.dll`. This is what makes the `hash`
  module and the PE authenticode parser work.
- Version in step with `include/YARA/yara/libyara.h` (4.5.4).

## Module availability (verified empirically, not from build logs)

Compile a one-line rule per module; `phantom-sigbuild` reports
`unknown module "<name>"` when one is absent:

```
import "<module>"
rule probe { condition: false }
```

| Module | State |
|---|---|
| `pe` `math` `hash` `console` `string` `time` `dotnet` | available |
| `elf` | NOT available |
| `magic` `cuckoo` | NOT available (need libmagic / jansson) |

### Why `elf` is still missing

vcpkg patches the elf module out and comments its sources out of the port,
citing a dependency on tlshc and upstream PR 1624. tlshc does ship inside the
YARA source tree, so re-enabling it looked straightforward - but building
`libyara/tlshc/tlsh.c` fails under MSVC with a cluster of C2057/C2065/C2133/
C2229/C2466 errors, the signature of a missing build define producing a
zero-sized array. That was not chased further because the payoff is small and
platform-inapplicable: in Yara-Forge's full pack only 26 of 11,716 rules use
`elf.`, and they match Linux ELF binaries on a Windows-only endpoint product.

This is a known, quantified gap rather than a silent one. Revisit if a rule set
we care about depends on elf, or once PR 1624 lands upstream.
