# Build-time detection content

`phantom-sigbuild` compiles everything here into a single `signatures.sdb`.
Three subdirectories, by convention rather than a manifest, so the tree is
self-describing:

- `hashes/`   - `*.txt`, `*.hashes`, `*.csv`  (`TYPE:HASH:NAME:LEVEL`)
- `patterns/` - `*.txt`, `*.patterns`
- `yara/`     - `*.yar`, `*.yara`

```powershell
bin\Release\phantom-sigbuild.exe --out signatures.sdb --content content --overwrite
```

## The aggregated YARA package is not committed

`yara_forge_rules_*.yar` is deliberately gitignored. It is an 18 MB aggregate of
40+ upstream repositories, and roughly 640 of its rules carry no licence grant at
all - committing it would mean redistributing content we have no permission to
redistribute, which is precisely what the build-time filter exists to prevent.

Download it from the YARA-Forge releases page and drop it in `yara/`:

  https://github.com/YARAHQ/yara-forge/releases

The `full` package is what these figures were measured against. `phantom-sigbuild`
withholds any section without a licence grant, reports every exclusion by source
and count, and writes `THIRD-PARTY-RULES.md` next to the database to satisfy the
attribution that the Detection Rule License and CC BY-SA require.

Hand-written rule files in `yara/` are left completely alone - the filter only
engages on a recognised aggregated package.
