# SignatureIndex - KOMPLÝ GÝDEL

## ?? AMACI

**SignatureIndex** = Hash'larý **O(log N)** hýzýnda ara ve ekle/sil iþlemleri yapan **B+Tree** implementasyonu.

```
Ne zaman kullanýlýr?
?? HashStore ? "Bu hash'ý veritabanýnda ara" (< 1µs)
?? PatternStore ? (Ýçinde pattern trie var ama kendi index'i yok)
?? SignatureStore ? (HashStore içinde SignatureIndex kullanýlýr)
```

---

## ?? DOSYA YAPISI (7 DOSYA)

### **#1. SignatureIndex.hpp** - HEADER / PUBLIC INTERFACE

**Ne yapar?**
- Sýnýf deklarasyonlarý
- Public method'lar (Lookup, Insert, Remove, etc.)
- Data member'lar (atomic, mutex, cache)

**Önemli yapýlar:**

```cpp
class SignatureIndex {
public:
    // INITIALIZATION
    StoreError Initialize(const MemoryMappedView& view, uint64_t offset, uint64_t size);
    StoreError CreateNew(void* baseAddr, uint64_t size, uint64_t& usedSize);
    
    // QUERY (hýzlý, lock-free reads)
    std::optional<uint64_t> Lookup(const HashValue& hash);
    std::optional<uint64_t> LookupByFastHash(uint64_t fastHash);
    std::vector<uint64_t> RangeQuery(uint64_t minHash, uint64_t maxHash);
    void BatchLookup(std::span<const HashValue> hashes, std::vector<...>& results);
    
    // MODIFICATION (yavaþ, exclusive lock)
    StoreError Insert(const HashValue& hash, uint64_t signatureOffset);
    StoreError Remove(const HashValue& hash);
    StoreError BatchInsert(std::span<const std::pair<HashValue, uint64_t>>);
    StoreError Update(const HashValue& hash, uint64_t newOffset);
    
    // TRAVERSAL
    void ForEach(std::function<bool(uint64_t fastHash, uint64_t offset)> callback);
    void ForEachIf(std::function<bool(uint64_t)> predicate, std::function<bool(...)> callback);
    
    // STATISTICS
    IndexStatistics GetStatistics();
    void ResetStatistics();
    
    // MAINTENANCE
    StoreError Rebuild();
    StoreError Compact();
    StoreError Flush();
    StoreError Verify();

private:
    // MEMORY
    const MemoryMappedView* m_view;
    void* m_baseAddress;
    uint64_t m_indexSize;
    
    // B+TREE ROOT
    std::atomic<uint32_t> m_rootOffset;      // Root node disk offset
    std::atomic<uint32_t> m_treeHeight;      // Tree depth
    
    // STATISTICS (atomic for lock-free reads)
    std::atomic<uint64_t> m_totalLookups;
    std::atomic<uint64_t> m_cacheHits;
    std::atomic<uint64_t> m_cacheMisses;
    
    // NODE CACHE (hot nodes cached in RAM)
    static constexpr size_t CACHE_SIZE = 1024;
    std::array<CachedNode, CACHE_SIZE> m_nodeCache;
    std::shared_mutex m_cacheLock;
    
    // COW (Copy-On-Write) FOR UPDATES
    std::vector<std::unique_ptr<BPlusTreeNode>> m_cowNodes;
    std::atomic<bool> m_inCOWTransaction;
    
    // SYNCHRONIZATION
    mutable std::shared_mutex m_rwLock;      // readers/writers lock
};
```

**Önemli atomics:**
- `m_rootOffset` ? Root node disk offset (publish/subscribe pattern)
- `m_treeHeight` ? Tree depth (readers read, writers update)
- `m_totalLookups` ? Lookup count (stats only, no sync needed)

---

### **#2. SignatureIndex.cpp** - MAIN IMPLEMENTATION

**Ne yapar?**
- Constructor/Destructor
- `Initialize()` ? Diskten mmap'den load et
- `CreateNew()` ? Yeni boþ index oluþtur
- `Verify()` ? B+Tree invariantlarýný kontrol et
- `ForEach()` ? Tüm nodes'u traverse et
- `ForEachIf()` ? Predicate ile filtered traversal
- Helper methods: `BinarySearch()`, `GetCurrentTimeNs()`, `HashNodeOffset()`

**Kritik fonksiyonlar:**

```cpp
// Initialize - Diskten yükleme
StoreError SignatureIndex::Initialize(
    const MemoryMappedView& view,
    uint64_t indexOffset,
    uint64_t indexSize
) {
    // 1. Extensive validation (memory view, alignment, bounds)
    // 2. Load root offset from disk
    // 3. Initialize atomic state
    // 4. Clear cache
    // 5. Initialize performance counters
}

// CreateNew - Yeni index oluþtur (boþ)
StoreError SignatureIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) {
    // 1. Allocate root node at baseAddress[0]
    // 2. Initialize as empty leaf node
    // 3. Set m_rootOffset = 0
    // 4. Return usedSize (typically one page: 4KB)
}

// Verify - B+Tree kontrolü
StoreError SignatureIndex::Verify() {
    // Checks:
    // - Root exists and is in bounds
    // - All nodes have keyCount <= MAX_KEYS
    // - Keys are strictly ordered
    // - Tree height is reasonable (0-64)
}

// ForEach - Leaf linked list traverse
void SignatureIndex::ForEach(
    std::function<bool(uint64_t fastHash, uint64_t offset)> callback
) {
    // 1. Navigate to leftmost leaf (in-order)
    // 2. Follow leaf linked list (nextLeaf pointers)
    // 3. Call callback for each entry
    // 4. Timeout/iteration limits for DoS protection
}
```

**Önemli:**
- `ForEach()` **leaf linked list**'i kullanýr ? O(N) traversal
- Cycle detection var (sonsuz loop'a karþý)
- Timeout protection var

---

### **#3. SignatureIndex_Query.cpp** - LOOKUP OPERATIONS

**Ne yapar?**
- `Lookup()` ? Single hash lookup
- `LookupByFastHash()` ? Pre-computed fast-hash ile lookup
- `RangeQuery()` ? [min, max] range içinde hepsi ara
- `BatchLookup()` ? 1000'er hash'ý paralel ara

**Lookup algoritmasý:**

```cpp
std::optional<uint64_t> SignatureIndex::Lookup(const HashValue& hash) {
    // 1. Compute fast-hash: hash.FastHash() = uint64_t
    // 2. FindLeaf(fastHash) ? Doðru leaf node'u bul
    //    ?? Start at root
    //    ?? Binary search keys in each node
    //    ?? Follow child pointers down
    // 3. SearchInLeaf(leaf, fastHash) ? Leaf'te binary search
    // 4. Return signature offset (uint64_t) VEYA nullopt
}

// Performance: O(log N) tree height + binary searches
// Average: < 500ns (1 microsecond target)
```

**FindLeaf() nasýl çalýþýr:**

```
Root Node (internal)
?? keys: [100, 200, 300]
?? children: [ptr0, ptr1, ptr2, ptr3]
?
Aranan hash = 150 olsa:
?? 150 < 200? YES ? children[1]'e git
?
?? Leaf Node (A)
?  ?? keys: [110, 120, 130, 140, 145, 150, 155]
?  ?? children (offsets): [off1, off2, ..., off7]
?
Leaf'te 150'yi binary search ? index 5 bulur
return children[5] ? Signature offset
```

**BatchLookup:**

```cpp
void SignatureIndex::BatchLookup(
    std::span<const HashValue> hashes,
    std::vector<std::optional<uint64_t>>& results
) {
    // Parallelized version of Lookup()
    // std::execution::par ile her hash paralel iþlen
    // Cache locality için sorted order tercih edilir
}
```

---

### **#4. SignatureIndex_modification.cpp** - INSERT/REMOVE/UPDATE

**Ne yapar?**
- `Insert()` ? Yeni entry ekle (tree büyüse node split et)
- `Remove()` ? Entry sil (node küçülürse merge et)
- `Update()` ? Var olan entry'yi güncelle
- `BatchInsert()` ? Bulk insert
- `SplitNode()` ? Node dolu ise ikiye böl
- `MergeNodes()` ? Node boþalýrsa birleþtir

**Insert algoritmasý:**

```cpp
StoreError SignatureIndex::Insert(const HashValue& hash, uint64_t offset) {
    // 1. Acquire EXCLUSIVE lock (m_rwLock)
    // 2. FindLeaf(hash.FastHash())
    // 3. FindInsertionPoint() ? Hangi pozisyona insert et?
    // 4. Check if already exists (duplicate detection)
    // 5. Insert into leaf
    // 6. If leaf.keyCount > MAX_KEYS:
    //    ?? SplitNode(leaf)
    //       ?? Create new sibling node
    //       ?? Move upper half keys to sibling
    //       ?? Update parent with split key
    //       ?? Recursively split parent if needed (up to root)
    // 7. Update m_treeHeight if root split
    // 8. Release lock
}

// Performance: O(log N) for traversal + O(MAX_KEYS) for insert
// Average node: < 1000ns
```

**Node Split örneði:**

```
BEFORE: Leaf keyCount = 128 (MAX_KEYS)
?? keys: [1, 2, ..., 128]
?? children: [off1, off2, ..., off129]

SplitNode():
?? midPoint = 64
?? splitKey = keys[64]
?? Create new sibling
?? Copy keys[64..128] to sibling
?? Update parent with splitKey

AFTER:
Left Leaf:
?? keys: [1, 2, ..., 63]
?? children: [off1, ..., off64]

Right Leaf (new):
?? keys: [65, 66, ..., 128]
?? children: [off65, ..., off129]

Parent now has:
?? Old key pointing to left
?? NEW KEY = 64 (split point)
?? New pointer to right
```

**Remove algoritmasý:**

```cpp
StoreError SignatureIndex::Remove(const HashValue& hash) {
    // 1. Acquire EXCLUSIVE lock
    // 2. FindLeaf(hash.FastHash())
    // 3. Find and remove key
    // 4. If leaf.keyCount < MIN_KEYS:
    //    ?? Try to borrow from sibling
    //    ?? If borrow fails, MERGE nodes
    // 5. Recursively handle parent underflow
    // 6. Update m_treeHeight if root merged (height decreased)
    // 7. Release lock
}
```

---

### **#5. SignatureIndex_Query.cpp** vs **SignatureIndex_modification.cpp**

**Fark:**

| Operasyon | Lock | Speed | Neden? |
|-----------|------|-------|--------|
| **Lookup** | Shared (read) | < 1µs | Hýzlý, concurrent okuma |
| **Insert** | Exclusive (write) | ~ 1-10µs | Node split yapýlabilir |
| **Remove** | Exclusive (write) | ~ 1-10µs | Node merge yapýlabilir |
| **ForEach** | Shared (read) | O(N) | Tüm nodes traverse |

```cpp
// QUERY - hýzlý, lock-free read path
{
    std::shared_lock<std::shared_mutex> lock(m_rwLock); // Shared
    // Readers don't block each other
}

// MODIFICATION - yavaþ, exclusive write path
{
    std::unique_lock<std::shared_mutex> lock(m_rwLock); // Exclusive
    // Only one writer at a time
}
```

---

### **#6. SignatureIndex_Cache_mngmnt.cpp** - NODE CACHE

**Ne yapar?**
- `GetNode(offset)` ? Cache'den node al, miss ise diskten oku
- `InvalidateCacheEntry()` ? Cache entry'yi sil
- `ClearCache()` ? Tüm cache temizle

**Cache stratejisi:**

```cpp
struct CachedNode {
    const BPlusTreeNode* node;      // Diskten okunan node pointer
    uint64_t accessCount;           // Kaç kez eriþildi
    uint64_t lastAccessTime;        // Son eriþim zamaný (ns)
};

// CACHE_SIZE = 1024 hot nodes
// LRU eviction: least recently used node'lar çýkarýlýr

// GetNode implementation:
const BPlusTreeNode* SignatureIndex::GetNode(uint32_t offset) {
    // 1. Hash offset to cache index
    size_t cacheIdx = HashNodeOffset(offset) % CACHE_SIZE
    
    // 2. Check cache
    if (m_nodeCache[cacheIdx].node && m_nodeCache[cacheIdx].offset == offset) {
        // CACHE HIT
        m_cacheHits++;
        return m_nodeCache[cacheIdx].node;
    }
    
    // CACHE MISS - load from disk
    m_cacheMisses++;
    const BPlusTreeNode* diskNode = m_baseAddress + offset;
    
    // Update cache
    m_nodeCache[cacheIdx].node = diskNode;
    m_nodeCache[cacheIdx].offset = offset;
    m_nodeCache[cacheIdx].accessCount = 0;
    m_nodeCache[cacheIdx].lastAccessTime = GetCurrentTimeNs();
    
    return diskNode;
}
```

**Cache hit target:**
- Tipik workload: ~90% cache hit rate
- Hot nodes: root + 10-20 most accessed nodes

---

### **#7. SignatureIndex_COW.cpp** - COPY-ON-WRITE (Updates)

**Ne yapar?**
- `CloneNode()` ? Node'u kopyala (modification için)
- `CommitCOW()` ? Changes'i apply et
- `RollbackCOW()` ? Changes'i discard et
- COW transaction management

**Neden COW?**

```
PROBLEM (Naive approach):
?? Modify diskten okunan node directly
?? Node kýsmen written ise corruption
?? Reader bozuk data okuyabilir

SOLUTION (Copy-On-Write):
?? CloneNode() ? In-memory copy oluþtur
?? Kopyaya modify et
?? CommitCOW() ? Atomic olarak disk'e yaz
?? Reader hep consistent data okur
```

**COW flow:**

```cpp
StoreError SignatureIndex::Insert(...) {
    // 1. BeginCOWTransaction
    m_inCOWTransaction = true;
    
    // 2. During traversal, if node must be modified:
    BPlusTreeNode* nodeCopy = CloneNode(diskNode);
    m_cowNodes.push_back(std::move(nodeCopy));
    
    // 3. Modify copies, not originals
    nodeCopy->keys[pos] = newKey;
    
    // 4. Commit atomically
    CommitCOW(); // Write all copies to disk in correct order
    
    // OR Rollback
    RollbackCOW(); // Discard all copies
}
```

---

### **#8. SignatureIndex_stat_maintenance.cpp** - STATISTICS & REBUILD

**Ne yapar?**
- `GetStatistics()` ? Performance metrics
- `ResetStatistics()` ? Clear counters
- `Rebuild()` ? Re-optimize tree
- `Compact()` ? Remove fragmentation
- `Flush()` ? Write to disk

**Statistics:**

```cpp
struct IndexStatistics {
    uint64_t totalEntries;              // Kaç entry
    uint64_t totalNodes;                // Kaç node
    uint32_t treeHeight;                // Tree depth
    double averageFillRate;             // Node utilization %
    
    // Performance metrics
    uint64_t totalLookups;              // Toplam lookup
    uint64_t cacheHits;                 // Cache hit count
    uint64_t cacheMisses;               // Cache miss count
    uint64_t averageLookupNanoseconds;
};
```

**Rebuild ne zaman yapýlýr:**

```
TRIGGER: After many deletes
?? Problem: Node'lar underutilized
?? Solution: Rebuild tree with better balance
?? Process:
   1. ForEach() ? Tüm entries oku
   2. Sort by fast-hash
   3. Rebuild tree from scratch
   4. Better locality
   5. Higher fill rate
```

---

## ?? B+TREE YAPISI

```
DISK LAYOUT:

[Root Node]
?? isLeaf: false
?? keyCount: 3
?? keys: [100, 200, 300]
?? children: [ptr_to_node1, ptr_to_node2, ptr_to_node3, ptr_to_node4]

[Internal Node 1]
?? isLeaf: false
?? keys: [50, 75]
?? children: [ptr_leaf1, ptr_leaf2, ptr_leaf3]

[Internal Node 2]
?? isLeaf: false
?? keys: [125, 150, 175]
?? children: [ptr_leaf4, ptr_leaf5, ptr_leaf6, ptr_leaf7]

[Leaf Node 1]
?? isLeaf: true
?? keys: [1, 2, 3, ..., 50]
?? children: [off1, off2, off3, ..., off50]
?? nextLeaf: ptr_to_leaf2
?? prevLeaf: nullptr

[Leaf Node 2]
?? isLeaf: true
?? keys: [51, 52, ..., 100]
?? children: [off51, ...]
?? nextLeaf: ptr_to_leaf3
?? prevLeaf: ptr_to_leaf1
```

**Önemli özellikler:**
1. **Leaf linked list** ? ForEach() için O(N) traversal
2. **Balansý** ? Root'dan leaf'e distance = treeHeight
3. **Node size** ? Tipik 128 keys per node (cache-friendly)
4. **Fill rate** ? 50-100% (node split/merge sonrasý)

---

## ?? PERFORMANS HEDEFLERÝ

```
Operation          Target     Typical    Worst Case
Lookup             < 500ns    < 200ns    < 2µs
Insert             < 1µs      < 500ns    < 10µs (split)
Remove             < 1µs      < 500ns    < 10µs (merge)
RangeQuery(1K)     < 10µs     < 5µs      < 50µs
ForEach (1M)       < 1ms      < 500µs    < 10ms
BatchLookup(1K)    < 1µs      < 500ns    < 10µs
```

---

## ?? THREAD SAFETY

```
LOCK HIERARCHY:
1. m_rwLock (shared_mutex)
   ?? Readers: std::shared_lock (many concurrent)
   ?? Writers: std::unique_lock (exclusive)

2. m_cacheLock (shared_mutex for cache)
   ?? Read hits: lock-free access
   ?? Misses: exclusive write

NO DEADLOCK because:
?? Always acquire m_rwLock FIRST
?? Never hold lock during I/O
?? Timeout protection on all locks
```

---

## ?? QUICK REFERENCE

**Lookup (hýzlý):**
```cpp
auto result = index.Lookup(hash);
if (result) {
    uint64_t signatureOffset = *result;
}
```

**Insert (yavaþ):**
```cpp
StoreError err = index.Insert(hash, signatureOffset);
if (!err.IsSuccess()) {
    // Handle duplicate or error
}
```

**Traverse (çok yavaþ):**
```cpp
size_t count = 0;
index.ForEach([&count](uint64_t fastHash, uint64_t offset) {
    count++;
    return true; // continue
});
```

**Statistics:**
```cpp
auto stats = index.GetStatistics();
std::cout << "Total entries: " << stats.totalEntries << std::endl;
std::cout << "Cache hit rate: " << (100.0 * stats.cacheHits / (stats.cacheHits + stats.cacheMisses)) << "%" << std::endl;
```

---

## ?? ÖZET TABLO

| Dosya | Amaç | Ana Fonksyon |
|-------|------|--------------|
| **SignatureIndex.hpp** | Header/Interface | Class definition |
| **SignatureIndex.cpp** | Core impl | Initialize, CreateNew, Verify, ForEach |
| **SignatureIndex_Query.cpp** | Lookups | Lookup, LookupByFastHash, RangeQuery, BatchLookup |
| **SignatureIndex_modification.cpp** | Insert/Remove/Update | Insert, Remove, Update, SplitNode, MergeNodes |
| **SignatureIndex_Cache_mngmnt.cpp** | Caching | GetNode, ClearCache, LRU eviction |
| **SignatureIndex_COW.cpp** | Atomic updates | CloneNode, CommitCOW, RollbackCOW |
| **SignatureIndex_stat_maintenance.cpp** | Stats/Rebuild | GetStatistics, Rebuild, Compact, Flush |

---

**ÞÝMDÝ HER ÞEYÝ ANLADIN DEÐÝL MÝ? Sorun varsa sor!** ??
