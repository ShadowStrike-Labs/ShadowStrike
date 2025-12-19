# ShadowStrike - DETALLI MODÜL ÖÐRETÝ

## ?? "NEDEN AYNIÞEYLERI YAPAN 5 BÝLMEM KAÇ DOSYA VAR?" SORUNUNUN CEVABI

**ÇÜNKÜ HER MODÜLÜN FARKLI BÝR ÝÞÝ VAR, SADECE BENZERLÝKLERÝ ÇOK ÝLGÝ ÇEKÝYOR!**

---

# MODÜL 1: HashStore (Hash Lookup)

## ?? Amacý
Bir dosya hash'ýný al (MD5, SHA256, vb) ? **veritabanýnda 1 mikrosaniye içinde ara** ? "Bu hash kötü mü?" sorusunu cevapla.

## ?? Dosya Haritasý

```
src/HashStore/
??? HashStore.hpp              ? PUBLIC INTERFACE (dýþarýdan kullaným)
??? HashStore.cpp              ? Ana sýnýf, Initialize/Close/Constructor
?
??? HashStore_query_operations.cpp
?   ?? LookupHash()           ? Tek hash ara
?   ?? BatchLookup()          ? 1000 hash ayný anda ara
?   ?? FuzzyMatch()           ? Benzer hash ara (SSDEEP, TLSH)
?
??? HashStore_import_export.cpp
?   ?? ImportFromFile()       ? Dýþ dosyadan hash oku
?   ?? ImportFromJson()       ? JSON'dan hash oku
?   ?? ExportToFile()         ? Hash'larý dosyaya yazLEt
?   ?? ExportToJson()         ? JSON olarak dýþ çýkart
?
??? HashStore_mgnmnt.cpp      (Management)
?   ?? Rebuild()              ? Tüm index'leri yeniden oluþtur
?   ?? Compact()              ? Boþ alanlarý temizle
?   ?? Verify()               ? Veri bütünlüðü kontrol et
?   ?? Flush()                ? Disk'e yaz
?
??? HashBucket_impl.cpp
?   ?? HashBucket sýnýfý      ? Her hash tipi için 1 bucket
?       ?? m_index (B+Tree)   ? Hýzlý arama yapýsý
?       ?? m_bloomFilter      ? Hýzlý "yok" testi
?       ?? GetStatistics()    ? Performans metrikleri
?
??? BloomFilter_impl.cpp
    ?? BloomFilter sýnýfý      ? Probabilistic data structure
        ?? Add()              ? Hash'ý filter'a ekle
        ?? MightContain()     ? "Bu hash OLABILIR mi?" (1bit)
        ?? EstimatedFillRate() ? Doluluk yüzdesi
```

## ?? Veri Akýþý

```
USER: "C:\\file.exe'nin hash'ý kötü mü?"
  ?
  ?? 1) SHA256("C:\\file.exe") ? "a1b2c3d4..."
  ?
  ?? 2) HashStore::LookupHash()
  ?   ?
  ?   ?? 2a) Bloom Filter ? "Tamam, BU hash veri tabanýnda OLABILIR"
  ?   ?     (Veya "Kesinlikle YOK" ? Sonuç: null)
  ?   ?
  ?   ?? 2b) Eðer "olabilir" ise ? HashBucket::Lookup()
  ?       ?
  ?       ?? B+Tree Binary Search
  ?           ?? Root'u bul
  ?           ?? Leaf'e iner
  ?           ?? Hash'ý bul (O(log N))
  ?
  ?? RESULT: DetectionResult { name: "Trojan.Win32", severity: High }
```

## ?? Bellekte Yapý

```cpp
HashStore
?? m_buckets[7]               ? 7 hash tipi (MD5, SHA1, SHA256, SHA512, IMPHASH, SSDEEP, TLSH)
?  ?
?  ?? [0] = MD5 Bucket
?  ?  ?? m_index: SignatureIndex (B+Tree)
?  ?  ?  ?? m_rootOffset: 0x1000
?  ?  ?  ?? m_baseAddress: 0x12345678
?  ?  ?  ?? m_treeHeight: 4
?  ?  ?
?  ?  ?? m_bloomFilter: BloomFilter
?  ?     ?? m_bits: vector<uint64_t> (10 milyon hash için 80MB)
?  ?     ?? m_numHashes: 7 (hash fonksiyon sayýsý)
?  ?
?  ?? [1] = SHA1 Bucket (ayný yapý)
?  ?? [2] = SHA256 Bucket (ayný yapý)
?
?? m_queryCache[10000]        ? Son 10000 arama'nýn sonucu (cache)
   ?? SeqLock: lock-free reads
```

## ? Performans

| Ýþlem | Zaman |
|-------|-------|
| Bloom Filter check | < 1ns |
| B+Tree traversal | < 1µs |
| Cache hit | < 50ns |
| Batch lookup (1000 items) | < 1ms |

---

# MODÜL 2: PatternStore (Byte Pattern Matching)

## ?? Amacý
10MB dosya içinde 10,000 tane "48 8B 05 ?? ?? ??" gibi assembly pattern'ý ara ? **10 millisecond içinde** tümünü bul.

## ?? Dosya Haritasý

```
src/PatternStore/
??? PatternStore.hpp           ? PUBLIC INTERFACE
??? PatternStore.cpp           ? Constructor, lifecycle, main ScanFile()
?
??? PatternIndex.cpp
?   ?? PatternIndex sýnýfý     ? Trie (aðaç) data structure
?       ?? Build()             ? Pattern trie'yi diskten oku
?       ?? Search()            ? Buffer'da tüm pattern'leri ara
?       ?? m_root: TrieNode   ? Aðacýn kökü
?
??? aho_corasick_impl.cpp
?   ?? AhoCorasickAutomaton
?       ?? AddPattern()        ? Pattern ekle (test aþamasý)
?       ?? Compile()           ? Trie'yi inþa et + failure links
?       ?? Search()            ? **N pattern'i 1 geçiþle ara**
?       ?? m_nodes: vector<ACNode>
?
??? boyer_moore_impl.cpp
?   ?? BoyerMooreMatcher      ? Tek pattern, wildcard destekli
?       ?? BuildBadCharTable() ? Kaç karakter atla?
?       ?? BuildGoodSuffixTable()
?       ?? FindFirst()         ? Ýlk eþleþmeyi bul
?
??? SIMD_matcher_impl.cpp
    ?? SIMDMatcher
        ?? SearchAVX2()       ? 32 byte paralel ara (AVX2)
        ?? SearchAVX512()     ? 64 byte paralel ara (AVX-512)
        ?? SearchMultiple()   ? 4-5 pattern ayný anda SIMD
```

## ?? Veri Akýþý

```
USER: "C:\\malware.bin dosyasýnda pattern ara"
  ?
  ?? 1) PatternStore::ScanFile()
  ?   ?
  ?   ?? 1a) Memory map file (10MB dosya)
  ?   ?
  ?   ?? 1b) PatternIndex::Search()
  ?       ?
  ?       ?? 1b1) AhoCorasickAutomaton::Search()
  ?       ?      ?
  ?       ?      ?? 1 Pass: trie içinde tüm 10,000 pattern'ý ara
  ?       ?      ?? Eþleþmeleri bul ve offset'lerini topla
  ?       ?
  ?       ?? 1b2) Eðer SIMD enabled ise:
  ?              ?? SIMDMatcher::SearchAVX2()
  ?                 ?? 32 byte'ý paralel kontrol
  ?                 ?? Remaining bytes tek tek
  ?
  ?? RESULT: vector<DetectionResult> {
       { pattern_id: 5, offset: 0x1234, name: "Suspicious_Shellcode" },
       { pattern_id: 12, offset: 0x5678, name: "CryptLocker_Marker" },
       ...
     }
```

## ?? Bellekte Yapý

```cpp
PatternStore
?? m_automaton: AhoCorasickAutomaton
?  ?? m_nodes[10000]           ? 10,000 pattern için Trie nodes
?  ?  ?? ACNode {
?  ?     ?? children[256]      ? Her byte için child pointer
?  ?     ?? failureLink        ? Aho-Corasick failure link
?  ?     ?? outputs: vector    ? "Bu node'da hangi pattern'ler biter?"
?  ?  }
?  ?
?  ?? m_compiled: bool         ? Failure links hesaplandý mý?
?
?? m_patternCache[10000]      ? Pattern metadata (ad, tehdit seviyesi, vb)
?  ?? {
?     ?? signatureId: 5
?     ?? name: "Trojan_Marker"
?     ?? threatLevel: Critical
?     ?? pattern: vector<uint8_t>
?  }
?
?? m_statistics
   ?? totalPatterns: 10000
   ?? totalScans: 1000000
   ?? totalMatches: 5432
```

## ? Performans

| Ýþlem | Zaman |
|-------|-------|
| Pattern trie build | 100ms (ilk kez) |
| 10MB file scan (1000 pattern) | 10ms |
| Aho-Corasick single pass | O(N + Z) |
| SIMD scan (AVX2) | 5x hýzlý |

---

# MODÜL 3: YaraRuleStore (YARA Rules)

## ?? Amacý
Önceden derlenmiþ YARA rules'leri çalýþtýr ? Kompleks pattern'ler ve logic'i kontrol et.

```
YARA nedir?
- "if x > 100 and contains 'MZ' then evil"
- Kombinatoriyal logic'i destekler
- Zararlý yazýlým araþtýrmacýlarýnýn standart aracý
```

## ?? Dosya Haritasý

```
src/SignatureStore/
??? YaraRuleStore.hpp          ? PUBLIC INTERFACE
??? YaraRuleStore.cpp          ? Main implementation
?
??? [Ýçinde bölümlenmemiþ ama mantýksal bölümler:]
    ?? Initialize() / CreateNew()
    ?? AddRulesFromFile()
    ?? ScanBuffer() / ScanFile()
    ?? Import/Export
    ?? Maintenance
```

## ?? Veri Akýþý

```
USER: "C:\\suspect.exe için YARA scan yap"
  ?
  ?? 1) YaraStore::ScanFile()
  ?   ?
  ?   ?? 1a) Memory map file
  ?   ?
  ?   ?? 1b) yr_rules_scan() (libyara kütüphanesi)
  ?       ?
  ?       ?? 1b1) Tüm compiled rules'u execute et
  ?       ?? 1b2) String matches'i topla
  ?       ?? 1b3) Conditions'ý test et
  ?       ?? 1b4) Matched rules'u döndür
  ?
  ?? RESULT: vector<YaraMatch> {
       { ruleName: "Trojan_APT_1", tags: ["APT", "Banking"], ... },
       ...
     }
```

---

# MODÜL 4: SignatureStore (THE CONDUCTOR - ORKESTRA ÞEFÝ!)

## ?? Amacý
**HashStore + PatternStore + YaraRuleStore'u bir arada koordine ederek çalýþtýr.**

## ?? Dosya Haritasý

```
src/SignatureStore/
??? SignatureStore.hpp         ? PUBLIC INTERFACE (her þey burada)
??? SignatureStore.cpp         ? Constructor, lifecycle, Initialize/Close
?
??? SignatureStore_scan.cpp
?   ?? ScanBuffer()           ? Buffer'ý hash+pattern+YARA ile tara
?   ?? ScanFile()             ? Dosyayý memory-map'le ve tara
?   ?? ScanProcess()          ? Live process memory'yi tara
?   ?? ExecuteParallelScan()  ? Hash, Pattern, YARA **paralel** çalýþtýr
?
??? SignatureStore_Query.cpp
?   ?? LookupHash()           ? Doðrudan HashStore'u çaðýr
?   ?? LookupHashString()     ? String'i parse et, lookup()
?   ?? LookupFileHash()       ? Dosya hash'ýný hesapla + lookup
?
??? SignatureStore_mngmnt.cpp  (Management)
?   ?? Rebuild()              ? HashStore.Rebuild() + PatternStore.Rebuild() + YaraStore.Recompile()
?   ?? Compact()              ? Tüm modülleri compact et
?   ?? Verify()               ? Tüm modülleri verify et
?   ?? OptimizeByUsage()      ? Hit statistics'e göre optimize et
?
??? Ýçinde 3 tane member:
    ?? m_hashStore        (HashStore instance)
    ?? m_patternStore     (PatternStore instance)
    ?? m_yaraStore        (YaraRuleStore instance)
```

## ?? PARALEL VERI AKIÞI (En Önemli Kýsým!)

```
USER: store.ScanFile("C:\\suspect.exe")
  ?
  ?? ExecuteParallelScan() // Paralel baþlat!
  ?  ?
  ?  ?? THREAD 1: HashStore?LookupHash()
  ?  ?  ?? Dosya hash'ý hesapla (MD5, SHA256)
  ?  ?     ? B+Tree'de ara
  ?  ?     ? Sonuç: "Trojan.A" ÜRETÝLER
  ?  ?
  ?  ?? THREAD 2: PatternStore?ScanFile()
  ?  ?  ?? 10,000 assembly pattern'ý ara
  ?  ?     ? Aho-Corasick automaton
  ?  ?     ? Sonuç: "Suspicious_Shellcode" @0x1000, "API_Hook" @0x2000
  ?  ?
  ?  ?? THREAD 3: YaraStore?ScanFile()
  ?     ?? Compiled YARA rules koþ
  ?        ? Sonuç: "APT_Trojan", "Ransomware_Behavior"
  ?
  ?? MERGE RESULTS
  ?  ?? ScanResult::detections = all_three_combined
  ?
  ?? RETURN ScanResult {
       detections: [
         { name: "Trojan.A", source: "HashStore", severity: CRITICAL },
         { name: "Suspicious_Shellcode", source: "PatternStore", offset: 0x1000 },
         { name: "API_Hook", source: "PatternStore", offset: 0x2000 },
         { name: "APT_Trojan", source: "YaraStore" },
         { name: "Ransomware_Behavior", source: "YaraStore" }
       ],
       totalTime: 25ms
     }
```

## ?? Bellekte Yapý

```cpp
SignatureStore
?? m_hashStore: unique_ptr<HashStore>
?  ?? (Hash lookup functionality)
?
?? m_patternStore: unique_ptr<PatternStore>
?  ?? (Pattern scanning functionality)
?
?? m_yaraStore: unique_ptr<YaraRuleStore>
?  ?? (YARA rules execution)
?
?? m_queryCache[1000]
?  ?? Son 1000 arama sonucunu cache et
?
?? m_statistics
   ?? totalScans: 100000
   ?? totalDetections: 50000
   ?? averageScanTime: 25ms
   ?? cacheHitRate: 85%
```

---

# ?? "NEDEN 5 FARKLI SCAN VAR?" CEVABI

```
Scan #1: HashStore::LookupHash()
         ?? Neden: Hýzlý (< 1µs), hash lookup için specializ
         ?? Dosya: HashStore_query_operations.cpp

Scan #2: PatternStore::ScanFile()
         ?? Neden: Byte pattern'leri ara, wildcard/SIMD destekli
         ?? Dosya: PatternStore.cpp + aho_corasick_impl.cpp

Scan #3: YaraStore::ScanFile()
         ?? Neden: Kompleks logic rules, libyara integration
         ?? Dosya: YaraRuleStore.cpp

Scan #4: SignatureStore::ScanFile()
         ?? Neden: Meta-orchestration (tüm 3'ü coordinate et)
         ?? Dosya: SignatureStore_scan.cpp

Scan #5: SignatureIndex::ForEach() / Search()
         ?? Neden: B+Tree üzerinde iteration (internal)
         ?? Dosya: SignatureIndex_Query.cpp
```

**FAKAT HEPSI FARKLI SEVIYELERDE ÇALIÞIYOR!**
- Level 1: User calls SignatureStore::ScanFile()
- Level 2: SignatureStore calls HashStore/PatternStore/YaraStore
- Level 3: Each Store calls their own internal structures
- Level 4: Index operations (B+Tree, Trie) happen

---

# ?? QUICK MEMORY MAP

```
DISK
?? hashes.db        ? HashStore data
?  ?? B+Tree nodes
?  ?? Bloom filter
?
?? patterns.db      ? PatternStore data
?  ?? Aho-Corasick trie
?  ?? Pattern metadata
?
?? yara.db          ? YaraRuleStore data
?  ?? Compiled YARA bytecode
?
?? metadata.json    ? SignatureStore metadata

MEMORY (Runtime)
?? HashStore instance (10-100MB)
?  ?? Bloom filter bits (memory-mapped)
?  ?? B+Tree node cache
?
?? PatternStore instance (5-50MB)
?  ?? Trie nodes cache
?  ?? Pattern metadata
?
?? YaraRuleStore instance (1-10MB)
?  ?? Compiled rules
?  ?? Rule metadata
?
?? SignatureStore instance (5-20MB)
   ?? Query result cache
   ?? Statistics
```

---

# ?? BAÞLANGIC OKUMA SIRASý

1. **SignatureStore.hpp** (Interface'i anla - neyi dýþarýya sunuyor?)
2. **SignatureStore_scan.cpp** (Nasýl çalýþýyor? 3 modülü kimiz çaðýrýyor?)
3. **HashStore_query_operations.cpp** (Hash lookup nasýl hýzlý?)
4. **aho_corasick_impl.cpp** (10,000 pattern nasýl 1 geçiþle ara?)
5. **SignatureIndex.cpp** (B+Tree nasýl O(log N) saðlýyor?)

**SONRA SEN HER ÞEYÝ ANLARSSIN!**

---

Bu belgeyi okudu mu? Þimdi istediðin modülü söyle, BEN SANA DETAYLI ANA AKIÞINI GÖSTERECEK BÝR DAHA YAZIRIM! ??
