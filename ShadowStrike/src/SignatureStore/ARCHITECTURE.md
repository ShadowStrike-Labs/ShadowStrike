# ShadowStrike SignatureStore Module - Architecture Documentation

## ?? Table of Contents
- [Overview](#overview)
- [Performance Targets](#performance-targets)
- [Module Structure](#module-structure)
- [Data Flow](#data-flow)
- [Memory Architecture](#memory-architecture)
- [Implementation Roadmap](#implementation-roadmap)

---

## ?? Overview

The SignatureStore module is an **enterprise-grade, ultra-high-performance signature database system** designed for real-time malware detection. Built from scratch without SQLite dependencies, it leverages memory-mapped I/O for zero-copy operations and achieves sub-microsecond hash lookups.

### Design Philosophy
- **Performance First**: Every millisecond counts in antivirus operations
- **Memory-Mapped I/O**: Zero-copy reads, instant database loading
- **Lock-Free Reads**: Concurrent queries without blocking
- **Cache-Aware**: Optimized for modern CPU cache hierarchies
- **Windows-Only**: Leverages Windows API for maximum performance

---

## ? Performance Targets

| Operation | Target Time | Notes |
|-----------|-------------|-------|
| Hash Lookup | < 1?s | Sub-microsecond using B+Tree |
| Pattern Scan (10MB) | < 10ms | 10,000 patterns, SIMD-accelerated |
| YARA Scan (10MB, 1K rules) | < 50ms | Precompiled bytecode |
| Combined Scan | < 60ms | All methods parallel |
| Database Load Time | < 100ms | Memory-mapped instant loading |

---

## ?? Module Structure

### Core Components

```
SignatureStore/
??? SignatureFormat.hpp         # Binary format definitions
??? SignatureIndex.hpp          # B+Tree & Trie indexing
??? HashStore.hpp              # Hash database (MD5/SHA256/etc.)
??? PatternStore.hpp           # Byte pattern matcher
??? YaraRuleStore.hpp          # YARA rule engine
??? SignatureBuilder.hpp        # Database compilation
??? SignatureStore.hpp          # Main facade
```

### 1. **SignatureFormat.hpp**
Binary format definitions for the memory-mapped database.

**Key Structures:**
- `SignatureDatabaseHeader` - 4KB header with magic, version, section offsets
- `HashValue` - Fixed-size hash storage (MD5/SHA1/SHA256/SHA512)
- `PatternEntry` - Pattern metadata with mode (exact/wildcard/regex)
- `YaraRuleEntry` - YARA rule metadata and bytecode offsets
- `BPlusTreeNode` - Cache-aligned B+Tree nodes for indexing

**Features:**
- Page-aligned sections (4KB boundaries)
- Cache-line aligned hot data (64 bytes)
- Zero-copy data structures (packed, no pointers)
- SHA-256 database checksum

### 2. **SignatureIndex.hpp**
High-performance indexing structures.

**Components:**
- `SignatureIndex` - B+Tree index for O(log N) hash lookups
  - Lock-free concurrent reads
  - Copy-on-write updates
  - Node caching (LRU, 1024 hot nodes)
  - Leaf node linked list for range queries

- `PatternIndex` - Trie index for byte pattern matching
  - 256-way fanout (full byte range)
  - Depth-first search optimization
  - Hit count tracking for heatmap

**Target:** < 500ns average B+Tree lookup

### 3. **HashStore.hpp**
Lightning-fast hash database.

**Architecture:**
```
HashStore
??? Bloom Filter (false positive filter)
??? Hash Type Buckets (MD5, SHA1, SHA256, etc.)
?   ??? B+Tree Index per bucket
??? Query Result Cache (LRU, 10K entries)
```

**Features:**
- Bloom filter for instant negative lookups
- Segregated hash types for better locality
- Batch lookup optimization
- Fuzzy hash matching (SSDEEP, TLSH)
- Import/export (JSON, CSV, text)

**Target:** < 1?s hash lookup

### 4. **PatternStore.hpp**
High-speed byte pattern matching.

**Algorithms:**
- **Aho-Corasick Automaton** - Multi-pattern matching
- **Boyer-Moore-Horspool** - Single pattern with wildcards
- **SIMD Matcher** - AVX2/AVX-512 for exact patterns

**Pattern Types:**
- Exact byte sequences
- Wildcard patterns (`48 8B ?? ?? C3`)
- Byte masks (`XX & MASK == VALUE`)
- Limited regex support

**Features:**
- Pattern compiler (hex string ? binary)
- Entropy-based optimization
- Hit frequency heatmap
- Incremental streaming scan

**Target:** < 10ms for 10MB file with 10,000 patterns

### 5. **YaraRuleStore.hpp**
YARA rule engine integration.

**Architecture:**
- Precompiled YARA bytecode (avoid runtime compilation)
- Memory-mapped rule storage
- Multi-threaded scanning
- Rule dependency resolution

**Features:**
- Compile from source or load precompiled
- Namespace management
- Tag-based filtering
- Process memory scanning
- Metadata extraction

**Target:** < 50ms for 10MB file with 1,000 rules

### 6. **SignatureBuilder.hpp**
Database compilation and optimization.

**Build Pipeline:**
```
1. Input Sources ? 2. Deduplication ? 3. Optimization
     ?                      ?                  ?
4. Index Construction ? 5. Layout ? 6. Serialization
     ?
7. Integrity Check (SHA-256)
```

**Optimizations:**
- Entropy-based pattern sorting
- Frequency-based ordering (hot signatures first)
- Cache-line alignment for hot data
- Duplicate elimination

**Features:**
- Import from multiple formats (JSON, CSV, YARA, ClamAV)
- Parallel compilation
- Incremental updates
- Database merging

### 7. **SignatureStore.hpp**
Main unified facade.

**Responsibilities:**
- Orchestrate all sub-stores
- Intelligent query routing
- Result merging and deduplication
- Query/result caching
- Performance monitoring

**Scan Methods:**
- `ScanBuffer()` - In-memory scan
- `ScanFile()` - File scan (memory-mapped)
- `ScanDirectory()` - Recursive directory scan
- `ScanProcess()` - Process memory scan
- `CreateStreamScanner()` - Incremental streaming

---

## ?? Data Flow

### Query Path (Read Operations)

```
User Query
    ?
SignatureStore::ScanFile()
    ?
Check Query Cache ??? [Cache Hit] ??? Return Cached Result
    ? [Cache Miss]
Parallel Execution:
    ??? HashStore::LookupHash() ??? Bloom Filter ??? B+Tree ??? Result
    ??? PatternStore::Scan() ??? Aho-Corasick ??? SIMD ??? Result
    ??? YaraRuleStore::ScanFile() ??? YARA Engine ??? Result
    ?
Merge Results ??? Apply Filters ??? Update Statistics
    ?
Add to Cache ??? Return to User
```

### Build Path (Database Creation)

```
SignatureBuilder::AddHash/Pattern/Yara()
    ?
Validation Stage
    ?
Deduplication Stage
    ?
Optimization Stage
    ??? Sort by entropy
    ??? Sort by frequency
    ??? Align hot data
    ?
Index Construction
    ??? Build B+Tree (hashes)
    ??? Build Trie (patterns)
    ??? Compile YARA
    ?
Serialization
    ??? Write Header (4KB)
    ??? Write Hash Index
    ??? Write Pattern Index
    ??? Write YARA Rules
    ??? Write Metadata
    ?
Compute SHA-256 Checksum
    ?
Database Ready
```

---

## ?? Memory Architecture

### Database File Layout

```
Offset 0x0000
??????????????????????????????????????????????
? File Header (4KB)                          ?
? - Magic: 0x53535344 ('SSSD')             ?
? - Version: 1.0                            ?
? - Section offsets & sizes                 ?
? - Statistics                              ?
? - SHA-256 checksum                        ?
?????????????????????????????????????????????? 0x1000
? Hash Index Section (B+Tree)               ?
? - Cache-aligned nodes (128-order)         ?
? - Leaf linked list                        ?
?????????????????????????????????????????????? Variable
? Pattern Index Section (Trie)              ?
? - 256-way fanout nodes                    ?
? - Pattern data pool                       ?
?????????????????????????????????????????????? Variable
? YARA Rules Section                         ?
? - Compiled bytecode                       ?
? - Rule metadata                           ?
?????????????????????????????????????????????? Variable
? Metadata Section (JSON)                    ?
? - Signature descriptions                  ?
? - Tags, authors, references               ?
?????????????????????????????????????????????? Variable
? String Pool                                ?
? - Null-terminated strings                 ?
? - Offset-based references                 ?
??????????????????????????????????????????????
```

### Memory Mapping Strategy

```cpp
CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, ...)
    ?
CreateFileMappingW(file, ..., PAGE_READONLY, ...)
    ?
MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)
    ?
Base Address ? Typed Pointer Casts (zero-copy)
    ?
const SignatureDatabaseHeader* header = 
    static_cast<const SignatureDatabaseHeader*>(baseAddress);
```

**Benefits:**
- No explicit I/O operations
- OS-managed page cache
- Shared memory across processes
- Copy-on-write for updates

---

## ?? Implementation Roadmap

### Phase 1: Core Infrastructure (Week 1-2)
- [x] SignatureFormat.hpp - Binary format definitions
- [ ] SignatureFormat.cpp - Format validation utilities
- [ ] Memory-mapped file wrapper implementation
- [ ] Error handling infrastructure

### Phase 2: Indexing Layer (Week 3-4)
- [ ] SignatureIndex.cpp - B+Tree implementation
  - [ ] Node allocation/deallocation
  - [ ] Insert/delete operations
  - [ ] Lookup with caching
  - [ ] COW transaction support
- [ ] PatternIndex implementation (Trie)
- [ ] Unit tests for indexing

### Phase 3: Hash Store (Week 5-6)
- [ ] HashStore.cpp - Hash database
  - [ ] Bloom filter implementation
  - [ ] Hash bucket management
  - [ ] Batch operations
  - [ ] Import/export
- [ ] Hash computation utilities (MD5/SHA256/etc.)
- [ ] Integration tests

### Phase 4: Pattern Store (Week 7-8)
- [ ] PatternStore.cpp - Pattern matcher
  - [ ] Aho-Corasick automaton
  - [ ] Boyer-Moore matcher
  - [ ] SIMD implementations (AVX2/AVX-512)
- [ ] Pattern compiler
- [ ] Performance benchmarks

### Phase 5: YARA Integration (Week 9-10)
- [ ] YaraRuleStore.cpp - YARA engine
  - [ ] Compiler wrapper
  - [ ] Rule management
  - [ ] Scanning operations
- [ ] YARA library integration
- [ ] Rule validation

### Phase 6: Builder (Week 11-12)
- [ ] SignatureBuilder.cpp - Database builder
  - [ ] Input validation
  - [ ] Deduplication
  - [ ] Optimization algorithms
  - [ ] Serialization
- [ ] Import parsers (JSON, CSV, ClamAV)
- [ ] Build tests

### Phase 7: Main Facade (Week 13-14)
- [ ] SignatureStore.cpp - Unified interface
  - [ ] Query routing
  - [ ] Result merging
  - [ ] Caching layer
  - [ ] Statistics
- [ ] End-to-end tests
- [ ] Performance profiling

### Phase 8: Optimization & Polish (Week 15-16)
- [ ] Performance tuning
- [ ] Memory leak detection (Valgrind/ASAN)
- [ ] Stress testing
- [ ] Documentation
- [ ] Final benchmarks

---

## ?? Key Implementation Notes

### 1. Thread Safety
- **Reads**: Lock-free, concurrent (RCU-like)
- **Writes**: Exclusive lock (std::shared_mutex)
- **Updates**: Copy-on-write (MVCC)

### 2. Error Handling
- Use `StoreError` struct with Win32 error codes
- No exceptions in hot paths
- Logging via `SS_LOG_*` macros

### 3. Performance Monitoring
```cpp
LARGE_INTEGER start, end, freq;
QueryPerformanceFrequency(&freq);
QueryPerformanceCounter(&start);
// ... operation ...
QueryPerformanceCounter(&end);
uint64_t microseconds = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;
```

### 4. Cache Optimization
- Align hot data to cache lines (64 bytes)
- Use `alignas(64)` for frequently accessed structures
- Batch operations for better spatial locality

### 5. SIMD Usage
```cpp
#ifdef __AVX2__
    __m256i pattern = _mm256_set1_epi8(needle);
    // ... SIMD search ...
#endif
```

---

## ?? Expected Performance Metrics

### Database Sizes (Estimates)
| Signatures | Hash Index | Pattern Index | YARA Rules | Total Size |
|-----------|-----------|---------------|-----------|-----------|
| 100K | 8 MB | 50 MB | 100 MB | ~160 MB |
| 1M | 80 MB | 500 MB | 1 GB | ~1.6 GB |
| 10M | 800 MB | 5 GB | 10 GB | ~16 GB |

### Memory Usage (Runtime)
- Base: ~50 MB (code + data structures)
- Node cache: ~128 MB (2K nodes × 64 KB)
- Query cache: ~100 MB (10K results)
- **Total**: ~300 MB base + mapped database

### Throughput (Theoretical)
- Hash lookups: 1,000,000/sec (1?s each)
- Pattern scans: 1 GB/sec (100 MB/s per pattern)
- YARA scans: 200 MB/sec

---

## ?? References

### Academic Papers
- "Modern B-Tree Techniques" - Goetz Graefe
- "Aho-Corasick Algorithm" - Original paper
- "Fast Pattern Matching in Strings" - Boyer-Moore

### Industry Standards
- YARA Documentation: https://yara.readthedocs.io/
- ClamAV Signature Format
- Sophos/CrowdStrike architectural patterns

### Windows API
- Memory-Mapped Files: https://docs.microsoft.com/en-us/windows/win32/memory/file-mapping
- High-Resolution Timers: QueryPerformanceCounter

---

**Status**: ? All header files completed
**Next Step**: Begin Phase 1 implementation (.cpp files)
**Estimated Total Time**: 16 weeks (4 months)

---

*Document Version: 1.0*  
*Last Updated: 2026-01-XX*  
*Architect: ShadowStrike Team*
