/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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

