# ShadowStrike Signature Store Architecture - Türkçe Rehber

## ?? EN ÖNEMLÝ 3 MODÜL

Butun sistem bu 3 ana modülden oluþuyor. Hepsini birbirinden ayrý düþün:

---

## 1?? HASHSTORE (Hash Veritabaný) ??

### NE YAPAR?
- **MD5, SHA1, SHA256, SHA512** gibi hash deðerlerini tutar
- Dosya hashini alýr, veriye karþý 1 mikrosaniye içinde bak: "Bu hash kötü mü?"
- **B+Tree** ile hýzlý arama (< 1 mikrosaniye)
- **Bloom Filter** ile false positive'leri azaltýr

### DOSYA YAPISI

```
HashStore.hpp / HashStore.cpp
??? HashStore.cpp (Ana facade/arayüz)
??? HashStore_query_operations.cpp (Lookup iþlemleri)
??? HashStore_import_export.cpp (Ýçeri-dýþarý veri taþýma)
??? HashStore_mgnmnt.cpp (Bakým, rebuild, compact)
?
??? HashBucket_impl.cpp (Hash tipi baþýna 1 bucket)
?   - MD5 bucket
?   - SHA256 bucket
?   - IMPHASH bucket
?   - vb...
?
??? BloomFilter_impl.cpp (Hýzlý "bu hash YOK" testi)
```

### KULLANANA GÖRÜNÜÞ

```cpp
// Bir dosyanýn hash'ý kötü mü kontrol et?
HashStore store;
store.Initialize("hashes.db");

HashValue md5Hash = {...};  // Dosyadan hesaplanan MD5
auto result = store.LookupHash(md5Hash);

if (result.has_value()) {
    std::cout << "KÖTÜ HASH BULUNDU: " << result->signatureName << std::endl;
}
```

### ÝÇERDEKÝ HANGÝ DOSYA NE YAPAR?

| Dosya | Görevi |
|-------|--------|
| **BloomFilter_impl.cpp** | 10 milyon hash'ý "var mý yok mu" 1 bit ile test et |
| **HashBucket_impl.cpp** | Her hash tipi için ayrý B+Tree index |
| **HashStore_query_operations.cpp** | `LookupHash()`, `BatchLookup()` gibi search iþlemleri |
| **HashStore_import_export.cpp** | JSON/CSV/Text'ten hash import et, export et |
| **HashStore_mgnmnt.cpp** | `Rebuild()`, `Compact()`, `Verify()` bakým iþleri |

---

## 2?? PATTERNSTORE (Byte Pattern Tarayýcý) ??

### NE YAPAR?
- **Bellek içinde byte pattern ara**: `48 8B 05 ?? ?? ?? ??` (Intel assembly pattern)
- 10MB dosyayý 10ms içinde 10,000 pattern ile tara
- **Aho-Corasick automaton** = multi-pattern ayný anda ara
- **SIMD (AVX2)** = CPU instruction parallelization

### DOSYA YAPISI

```
PatternStore.cpp / PatternStore.hpp
??? PatternStore.cpp (Ana facade)
?
??? aho_corasick_impl.cpp (Aho-Corasick automaton)
?   - Trie node building
?   - Failure link computation
?   - Multi-pattern simultaneous search
?
??? boyer_moore_impl.cpp (Single pattern matching)
?   - Skip table optimization
?   - Wildcard support (?)
?
??? SIMD_matcher_impl.cpp (SIMD hýzlandýrmasý)
?   - AVX2 pattern matching
?   - Bulk search optimization
?
??? PatternIndex.cpp (Compiled pattern index)
?   - Trie serialization
?   - Zero-copy memory mapped loading
?
??? PatternStore.cpp (Scanning & Management)
    - Memory buffer scanning
    - File scanning with chunking
    - Pattern addition/removal
```

### KULLANANA GÖRÜNÜÞ

```cpp
// Bellek içinde malware pattern ara
PatternStore store;
store.Initialize("patterns.db");

// "48 8B 05 ?? ?? ?? ??" pattern'ini ekle
store.AddPattern("48 8B 05 ?? ?? ?? ??", 
                 "Suspicious_Assembly",
                 ThreatLevel::High);

// Bir dosyayý tara
auto detections = store.ScanFile("C:\\malware_test.bin");

for (auto& det : detections) {
    std::cout << "PATTERN MATCH: " << det.signatureName 
              << " @ offset 0x" << std::hex << det.fileOffset << std::endl;
}
```

### ÝÇERDEKÝ DOSYALAR

| Dosya | Görevi |
|-------|--------|
| **aho_corasick_impl.cpp** | 1000'er pattern'i **ayný anda** ara (trie+automaton) |
| **boyer_moore_impl.cpp** | Tek pattern'i hýzlýca ara (skip tables) |
| **SIMD_matcher_impl.cpp** | AVX2 ile 32 byte paralel ara |
| **PatternIndex.cpp** | Pattern trie'yi disk'e yaz, memory-map'ten oku |
| **PatternStore.cpp** | `ScanFile()`, `ScanBuffer()`, `AddPattern()` |

---

## 3?? SIGNATURESTORE (Ana Orchestrator) ??

### NE YAPAR?
**HASHSTORE + PATTERNSTORE + YARA'yý bir arada çalýþtýrýr**

```
BÝR DOSYA TARAMA SÜRECI:
?
?? 1) HashStore ? Dosya hash'ýný al, malware DB'de ara (< 1µs)
?   ?? Bloom Filter ? Hýzlý "YOK" sonucu? Bitir
?   ?? B+Tree ? Gerçek hash var mý? Sonuç döndür
?
?? 2) PatternStore ? Dosya içinde byte pattern ara (< 10ms)
?   ?? Load file memory-mapped
?   ?? Aho-Corasick automaton ? 10,000 pattern ayný anda
?   ?? Matches bulundu mu? Döndür
?
?? 3) YaraStore ? YARA rules koþ (< 50ms)
?   ?? Compiled YARA bytecode execute
?
?? 4) MERGE ? Tüm sonuçlarý birleþtir
    ?? User: "Tehdit Seviyesi = CRITICAL" görsün
```

### DOSYA YAPISI

```
SignatureStore.cpp / SignatureStore.hpp
??? SignatureStore.hpp (Interface - public API)
?
??? SignatureStore.cpp (Constructor, lifecycle)
?   - Initialization / Close / Shutdown
?
??? SignatureStore_Query.cpp (Lookup operations)
?   - LookupHash()
?   - LookupHashString()
?   - FuzzyMatch()
?
??? SignatureStore_scan.cpp (Scanning engine)
?   - ScanBuffer() ? Hash + Pattern + YARA paralel
?   - ScanFile() ? Memory-mapped file scanning
?   - ScanProcess() ? Live process memory scan
?
??? SignatureStore_mngmnt.cpp (Maintenance)
?   - Rebuild() ? Tüm indices rebuild
?   - Compact() ? Database optimization
?   - Verify() ? Integrity check
?   - Optimize() ? Performance tuning
?
??? [Internal references to:]
    ??? HashStore (m_hashStore)
    ??? PatternStore (m_patternStore)
    ??? YaraRuleStore (m_yaraStore)
```

### KULLANANA GÖRÜNÜÞ

```cpp
// SignatureStore = "Hepsi bir arada"
SignatureStore store;
store.Initialize("signatures.db");

// BÝR KOMUTla her þey:
ScanOptions opts;
opts.enableHashLookup = true;      // HashStore
opts.enablePatternScan = true;     // PatternStore
opts.enableYaraScan = true;        // YaraRuleStore
opts.timeoutMilliseconds = 10000;  // 10 saniye

ScanResult result = store.ScanFile("C:\\suspect.exe", opts);

// Sonuç = Hash matches + Pattern matches + YARA matches
std::cout << "Toplam tehdit: " << result.GetDetectionCount() << std::endl;
for (auto& det : result.detections) {
    std::cout << " - " << det.signatureName << " (Level: " 
              << (int)det.threatLevel << ")" << std::endl;
}
```

---

## ?? ARALARINDA KIM KÝMÝ ÇAÐIRIYOR?

```
???????????????????????
?  USER APPLICATION   ?  (Senin antivirus programýn)
???????????????????????
           ?
           ? scan_file("C:\\test.exe")
           ?
???????????????????????????????????
?     SignatureStore              ?  ? MAIN FACADE (Sahne)
?  (3 modülü choreograph eder)    ?
???????????????????????????????????
           ?
    ??????????????????????????????
    ?      ?      ?              ?
    ?      ?      ?              ?
  Hash   Pattern YARA       Cache Manager
  Store  Store   Store      (Result caching)
    ?      ?      ?
    ?? B+Tree ??
    ?? Bloom ???
    ?? Buckets ?
    
    ?? Aho-Corasick Trie ??
    ?? SIMD (AVX2) ?????????
    ?? Pattern Index ???????
    
    ?? Compiled YARA Rules ??
    ?? Rule Metadata ?????????
```

---

## ?? ÖNEMLÝ FARK: Index vs Store

### "Index" nedir?
**Index** = **O(log N) hýzlý arama** yapýsý

```cpp
// SignatureIndex.cpp = B+Tree implementation
// - FindLeaf()        ? Hangi yapraða git?
// - BinarySearch()    ? Key'i bul
// - Insert/Remove     ? Node split/merge
// 
// DOSYA YAPISI:
// SignatureIndex.hpp (Header)
// SignatureIndex.cpp (Main logic)
// SignatureIndex_Query.cpp (Lookup)
// SignatureIndex_modification.cpp (Insert/Delete)
// SignatureIndex_COW.cpp (Copy-on-Write)
// SignatureIndex_Cache_mngmnt.cpp (Caching)
// SignatureIndex_stat_maintenance.cpp (Stats)
```

### "Store" nedir?
**Store** = **Facade** - "Dýþ arayüz"

```cpp
// HashStore.cpp = "Hash'larý tut, user'a interface saðla"
// - Initialize/CreateNew/Close
// - LookupHash()/BatchLookup()
// - AddHash()/RemoveHash()
// - Import/Export
//
// Ýçinde:
// - HashBucket'lar (her hash tipi için)
// - Her bucket'ýn kendi SignatureIndex'i var (B+Tree)
// - Bloom Filter hýzlandýrmasý
```

**ANALOJI:**
- **Index** = Motor (nasýl çalýþtýðý)
- **Store** = Araba (kullanýcýya sunulan arayüz)

---

## ?? KAPÞON AÇTIÐINI ÝLK DEFA GÖRDÜÐÜ GÝBÝ

Sana sadece bu kadar söyle:
- **Hash lookup?** ? HashStore ? fast (< 1µs)
- **Byte pattern ara?** ? PatternStore ? medium (< 10ms)
- **YARA rule koþ?** ? YaraRuleStore ? slower (< 50ms)
- **Hepsini bir arada?** ? SignatureStore ? combines all 3

---

## ? QUICK REFERENCE: DOSYA ÖÐRENÝÞ SIRASý

Bu sýrada oku:
1. **SignatureStore.hpp** (public interface)
2. **SignatureStore.cpp** (lifecycle)
3. **SignatureStore_scan.cpp** (main logic)
4. **HashStore.hpp ? HashStore.cpp** (hash lookup deep dive)
5. **PatternStore.cpp** (pattern matching)
6. **SignatureIndex.hpp** (B+Tree structure)

---

Bu kadarýný anla, artýk "neden 5 scan var" sorusunun cevabý anlarsýn:
- 1 = HashStore'da scan (hash lookup)
- 1 = PatternStore'da scan (pattern matching)
- 1 = YaraStore'da scan (rule execution)
- 1 = SignatureStore'da orchestration scan (tüm 3'ü çalýþtýr)
- 1 = Streaming scan (chunk by chunk for large files)

**Hepsi YAÞAL, AYRI MODÜL, AYRI DOSYALAR.**

---

## ?? SONUÇ

SignatureStore = Mutfak þefi
?? HashStore = Sous chef (hýzlý arama)
?? PatternStore = Line cook (pattern matching)
?? YaraStore = Pastry chef (rules)

Þef (SignatureStore) hepsini koordine eder, hepsi ayný anda çalýþýr, sonuçlar birleþtirilir.

**BITTI. Þimdi sen gitmiþ, hashstore'un içine bak, signatureindex'in ne yaptýðýný anla.**
