// ====================================================
// pragma_pack.h - Platform agnostic struct packing
// ====================================================

#ifndef PRAGMA_PACK_H
#define PRAGMA_PACK_H

//unified macros for struct packing and alignment

#ifdef _MSC_VER
    // MSVC: #pragma pack + __declspec(align)
#define PACK_BEGIN(n) \
        __pragma(pack(push, n))

#define PACK_END \
        __pragma(pack(pop))

#define PACKED_STRUCT(name) \
        __declspec(align(1)) struct name

#define ALIGNED_STRUCT(name, align_val) \
        __declspec(align(align_val)) struct name

#elif defined(__GNUC__)
    // GCC/Clang: __attribute__((packed))
#define PACK_BEGIN(n)

#define PACK_END

#define PACKED_STRUCT(name) \
        struct __attribute__((packed)) name

#define ALIGNED_STRUCT(name, align_val) \
        struct __attribute__((aligned(align_val))) name

#else
	// Fallback (unknown compiler)
#define PACK_BEGIN(n)
#define PACK_END
#define PACKED_STRUCT(name) struct name
#define ALIGNED_STRUCT(name, align_val) struct name
#endif

#endif // PRAGMA_PACK_H

