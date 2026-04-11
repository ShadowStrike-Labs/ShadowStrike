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
#pragma once
/**
 * @file Types.hpp
 * @brief Core type definitions for the PhantomDisassembler x86-64 engine.
 *
 * This header defines all enumerations, flags, and type aliases used by the
 * PhantomDisassembler. It is entirely self-contained: no external dependencies
 * beyond the C++20 standard library are required.
 *
 * Design invariants:
 *   - Every enum is a scoped enum (enum class) with an explicit underlying type.
 *   - Lookup tables are constexpr; no runtime initialisation cost.
 *   - The MOVSD / CMPSD ambiguity is resolved via _STR / _SSE / _CMP suffixes.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Phantom::Disasm {

// ============================================================================
// Section 1 – Machine Mode
// ============================================================================

enum class MachineMode : uint8_t {
    Long64,           // 64-bit long mode (x86-64)
    LongCompat32,     // 32-bit compatibility mode (under x86-64)
    Legacy32,         // 32-bit legacy protected mode
    Real16,           // 16-bit real mode
};

// ============================================================================
// Section 2 – Mnemonic
// ============================================================================

enum class Mnemonic : uint16_t {
    // --- General-purpose integer ---
    ADD, ADC, SUB, SBB, XOR, AND, OR, CMP, TEST, INC, DEC, NOT, NEG, DIV, IDIV, MUL, IMUL,

    // --- Data transfer ---
    MOV, MOVZX, MOVSX, MOVSXD, LEA, XCHG, PUSH, POP, PUSHA, PUSHAD, POPA, POPAD,

    // --- Shift / rotate ---
    SHL, SHR, SAR, SAL, ROL, ROR, RCL, RCR, SHLD, SHRD,

    // --- Control flow ---
    JMP, CALL, RET, RETF, LOOP, LOOPE, LOOPNE,

    // --- Conditional jumps ---
    JZ, JNZ, JO, JNO, JP, JNP, JS, JNS,
    JB, JBE, JL, JLE, JNB, JNBE, JNL, JNLE,
    JCXZ, JECXZ, JRCXZ,

    // --- String operations ---
    MOVSB, MOVSW, MOVSD_STR, MOVSQ,
    LODSB, LODSW, LODSD, LODSQ,
    STOSB, STOSW, STOSD, STOSQ,
    SCASB, SCASW, SCASD, SCASQ,
    CMPSB, CMPSW, CMPSD_STR, CMPSQ,

    // --- Interrupts ---
    INT, INT1, INT3, INTO, IRET, IRETD, IRETQ,

    // --- System / privileged ---
    SYSCALL, SYSENTER, SYSEXIT, SYSRET,
    RDTSC, RDTSCP, RDPMC, CPUID, HLT,
    IN_INST, OUT_INST, INS_INST, OUTS_INST,

    // --- Flags ---
    PUSHF, PUSHFQ, PUSHFD, POPF, POPFQ, POPFD,
    CLC, STC, CLI, STI, CLD, STD, CMC, LAHF, SAHF,

    // --- Descriptor table ---
    SGDT, SIDT, SLDT, STR, LGDT, LIDT, LLDT, LTR, LMSW, SMSW,
    LAR, LSL, VERR, VERW,

    // --- Atomic / compare-exchange ---
    CMPXCHG, CMPXCHG8B, CMPXCHG16B, XADD, LOCK_PREFIX,

    // --- Undefined / NOP / CET ---
    UD0, UD1, UD2, NOP, PAUSE, ENDBR32, ENDBR64,
    INCSSPD, INCSSPQ, RDSSPD, RDSSPQ,
    SAVEPREVSSP, RSTORSSP, SETSSBSY, CLRSSBSY,
    WRSSD, WRSSQ, WRUSSD, WRUSSQ,

    // --- AMX (Advanced Matrix Extensions) ---
    LDTILECFG, STTILECFG, TILELOADD, TILESTORED,
    TILEZERO, TILERELEASE,
    TDPBSSD, TDPBSUD, TDPBUSD, TDPBUUD,
    TDPBF16PS, TDPFP16PS,

    // --- Conversion ---
    CBW, CWDE, CDQE, CWD, CDQ, CQO,

    // --- Stack frame ---
    ENTER, LEAVE,

    // --- Bit manipulation ---
    BT, BTS, BTR, BTC, BSF, BSR, POPCNT, LZCNT, TZCNT,

    // --- Byte-swap / move-be ---
    BSWAP, MOVBE,

    // --- Conditional move ---
    CMOVZ, CMOVNZ, CMOVB, CMOVNB, CMOVBE, CMOVNBE,
    CMOVL, CMOVNL, CMOVLE, CMOVNLE,
    CMOVO, CMOVNO, CMOVS, CMOVNS, CMOVP, CMOVNP,

    // --- Setcc ---
    SETZ, SETNZ, SETB, SETNB, SETBE, SETNBE,
    SETL, SETNL, SETLE, SETNLE,
    SETO, SETNO, SETS, SETNS, SETP, SETNP,

    // --- MSR / PID ---
    RDMSR, WRMSR, RDPID,

    // --- Cache / TLB ---
    CLTS, INVD, WBINVD, INVLPG,

    // --- FS/GS base ---
    SWAPGS, WRFSBASE, WRGSBASE, RDFSBASE, RDGSBASE,

    // --- Fences / prefetch / cache-line ---
    MFENCE, SFENCE, LFENCE,
    PREFETCHT0, PREFETCHT1, PREFETCHT2, PREFETCHNTA,
    CLFLUSH, CLFLUSHOPT, CLWB,

    // --- XSAVE ---
    XGETBV, XSETBV, XSAVE, XRSTOR, XSAVEOPT, XSAVEC, XSAVES, XRSTORS,

    // --- FX save/restore ---
    FXSAVE, FXRSTOR,

    // --- Monitor / MWait ---
    MONITOR, MWAIT,

    // =========================================================================
    // SSE / SSE2 / SSE3 / SSSE3 / SSE4
    // =========================================================================

    // --- SSE moves ---
    MOVSS, MOVSD_SSE, MOVAPS, MOVUPS, MOVAPD, MOVUPD,
    MOVDQA, MOVDQU, MOVQ_SSE, MOVD_SSE,
    MOVLPS, MOVHPS, MOVLPD, MOVHPD, MOVLHPS, MOVHLPS,
    MOVNTPS, MOVNTPD, MOVNTI, MOVNTDQ, MOVNTDQA,

    // --- SSE arithmetic ---
    ADDSS, ADDSD, ADDPS, ADDPD, SUBSS, SUBSD, SUBPS, SUBPD,
    MULSS, MULSD, MULPS, MULPD, DIVSS, DIVSD, DIVPS, DIVPD,
    SQRTSS, SQRTSD, SQRTPS, SQRTPD, RSQRTSS, RSQRTPS, RCPSS, RCPPS,
    MAXSS, MAXSD, MAXPS, MAXPD, MINSS, MINSD, MINPS, MINPD,

    // --- SSE compare ---
    CMPSS, CMPSD_CMP, CMPPS, CMPPD,
    COMISS, COMISD, UCOMISS, UCOMISD,

    // --- SSE logic ---
    ANDPS, ANDPD, ANDNPS, ANDNPD, ORPS, ORPD, XORPS, XORPD,

    // --- SSE unpack / shuffle ---
    UNPCKLPS, UNPCKHPS, UNPCKLPD, UNPCKHPD, SHUFPS, SHUFPD,

    // --- SSE convert ---
    CVTSI2SS, CVTSI2SD, CVTSS2SD, CVTSD2SS,
    CVTSS2SI, CVTSD2SI, CVTTSS2SI, CVTTSD2SI,
    CVTDQ2PS, CVTDQ2PD, CVTPS2DQ, CVTPD2DQ,
    CVTTPS2DQ, CVTTPD2DQ, CVTPS2PD, CVTPD2PS,
    CVTPI2PS, CVTPI2PD, CVTPS2PI, CVTPD2PI, CVTTPS2PI, CVTTPD2PI,

    // --- SSE pack ---
    PACKUSWB, PACKSSWB, PACKSSDW, PACKUSDW,

    // --- SSE integer arithmetic ---
    PADDB, PADDW, PADDD, PADDQ, PSUBB, PSUBW, PSUBD, PSUBQ,
    PADDSB, PADDSW, PADDUSB, PADDUSW,
    PSUBSB, PSUBSW, PSUBUSB, PSUBUSW,
    PMULLW, PMULHW, PMULHUW, PMULUDQ, PMULLD, PMULDQ, PMADDWD, PMADDUBSW,
    PAVGB, PAVGW, PSADBW, PMULHRSW, PHMINPOSUW,

    // --- SSE compare (integer) ---
    PCMPEQB, PCMPEQW, PCMPEQD, PCMPEQQ,
    PCMPGTB, PCMPGTW, PCMPGTD, PCMPGTQ,

    // --- SSE min/max (integer) ---
    PMINUB, PMINUW, PMINUD, PMINSB, PMINSW, PMINSD,
    PMAXUB, PMAXUW, PMAXUD, PMAXSB, PMAXSW, PMAXSD,

    // --- SSE logic (integer) ---
    PAND, PANDN, POR, PXOR,

    // --- SSE shift (integer) ---
    PSLLW, PSLLD, PSLLQ, PSLLDQ, PSRLW, PSRLD, PSRLQ, PSRLDQ, PSRAW, PSRAD,

    // --- SSE shuffle / unpack (integer) ---
    PSHUFD, PSHUFB, PSHUFLW, PSHUFHW,
    PUNPCKLBW, PUNPCKLWD, PUNPCKLDQ, PUNPCKLQDQ,
    PUNPCKHBW, PUNPCKHWD, PUNPCKHDQ, PUNPCKHQDQ,

    // --- SSE insert / extract ---
    PINSRB, PINSRW, PINSRD, PINSRQ,
    PEXTRB, PEXTRW, PEXTRD, PEXTRQ,

    // --- SSE4 blend / align ---
    PALIGNR, PBLENDW, PBLENDVB, BLENDPS, BLENDPD, BLENDVPS, BLENDVPD,
    INSERTPS, EXTRACTPS,

    // --- SSE4 dot-product / SAD ---
    DPPS, DPPD, MPSADBW,

    // --- SSE4 round ---
    ROUNDSS, ROUNDSD, ROUNDPS, ROUNDPD,

    // --- SSE4.2 string compare ---
    PCMPISTRI, PCMPISTRM, PCMPESTRI, PCMPESTRM,

    // --- SSE mask ---
    PTEST, MOVMSKPS, MOVMSKPD, PMOVMSKB, MASKMOVDQU, MASKMOVQ,

    // --- MMX ---
    EMMS, MOVD_MMX, MOVQ_MMX,

    // --- MXCSR ---
    LDMXCSR, STMXCSR,

    // --- SSE3 horizontal ---
    HADDPS, HADDPD, HSUBPS, HSUBPD, ADDSUBPS, ADDSUBPD,
    LDDQU, MOVSLDUP, MOVSHDUP, MOVDDUP,

    // --- SSSE3 ---
    PABSB, PABSW, PABSD,
    PHADDW, PHADDD, PHADDSW, PHSUBW, PHSUBD, PHSUBSW,
    PSIGNB, PSIGNW, PSIGND,

    // --- SSE4 sign/zero extend (legacy encoding) ---
    PMOVSXBW, PMOVSXBD, PMOVSXBQ, PMOVSXWD, PMOVSXWQ, PMOVSXDQ,
    PMOVZXBW, PMOVZXBD, PMOVZXBQ, PMOVZXWD, PMOVZXWQ, PMOVZXDQ,

    // --- SSE4.2 CRC / POPCNT instruction-level ---
    CRC32_INST, POPCNT_INST,

    // =========================================================================
    // AVX / AVX2
    // =========================================================================

    // --- Arithmetic ---
    VADDPS, VADDPD, VADDSS, VADDSD, VSUBPS, VSUBPD, VSUBSS, VSUBSD,
    VMULPS, VMULPD, VMULSS, VMULSD, VDIVPS, VDIVPD, VDIVSS, VDIVSD,
    VSQRTPS, VSQRTPD, VSQRTSS, VSQRTSD,
    VRSQRTPS, VRSQRTSS, VRCPPS, VRCPSS,
    VMINPS, VMINPD, VMINSS, VMINSD, VMAXPS, VMAXPD, VMAXSS, VMAXSD,

    // --- Logic ---
    VANDPS, VANDPD, VANDNPS, VANDNPD,
    VORPS, VORPD, VXORPS, VXORPD,

    // --- Compare ---
    VCMPPS, VCMPPD, VCMPSS, VCMPSD_CMP,
    VUCOMISS, VUCOMISD, VCOMISS, VCOMISD,

    // --- Move ---
    VMOVAPS, VMOVUPS, VMOVAPD, VMOVUPD, VMOVDQA, VMOVDQU,
    VMOVSS, VMOVSD_AVX, VMOVD, VMOVQ,
    VMOVLPS, VMOVLPD, VMOVHPS, VMOVHPD,
    VMOVHLPS, VMOVLHPS,
    VMOVSLDUP, VMOVSHDUP, VMOVDDUP,
    VMOVNTPS, VMOVNTPD, VMOVNTDQ,
    VMOVMSKPS, VMOVMSKPD,

    // --- Unpack/Shuffle ---
    VUNPCKLPS, VUNPCKHPS, VUNPCKLPD, VUNPCKHPD,
    VSHUFPS, VSHUFPD,
    VPSHUFHW, VPSHUFLW,

    // --- Convert ---
    VCVTSI2SS, VCVTSI2SD,
    VCVTSS2SI, VCVTSD2SI, VCVTTSS2SI, VCVTTSD2SI,
    VCVTPS2PD, VCVTPD2PS, VCVTSS2SD, VCVTSD2SS,
    VCVTDQ2PS, VCVTPS2DQ, VCVTDQ2PD, VCVTPD2DQ,
    VCVTTPS2DQ, VCVTTPD2DQ,

    // --- Broadcast ---
    VBROADCASTSS, VBROADCASTSD, VBROADCASTF128, VBROADCASTI128,

    // --- Permute ---
    VPERM2F128, VPERM2I128, VPERMD, VPERMQ, VPERMPS, VPERMPD,
    VPERMILPS, VPERMILPD,

    // --- Integer packed logic ---
    VPAND, VPANDN, VPOR, VPXOR, VPTEST,

    // --- Integer packed arithmetic ---
    VPADDB, VPADDW, VPADDD, VPADDQ,
    VPSUBB, VPSUBW, VPSUBD, VPSUBQ,
    VPADDUSB, VPADDUSW, VPADDSB, VPADDSW,
    VPSUBUSB, VPSUBUSW, VPSUBSB, VPSUBSW,
    VPMULLW, VPMULLD, VPMULUDQ, VPMULDQ,
    VPMULHW, VPMULHUW, VPMULHRSW,
    VPMADDWD, VPMADDUBSW,
    VPSADBW,
    VPAVGB, VPAVGW,

    // --- Integer packed compare ---
    VPCMPEQB, VPCMPEQW, VPCMPEQD, VPCMPEQQ,
    VPCMPGTB, VPCMPGTW, VPCMPGTD, VPCMPGTQ,

    // --- Integer packed min/max ---
    VPMINUB, VPMINUW, VPMINUD, VPMINSB, VPMINSW, VPMINSD,
    VPMAXUB, VPMAXUW, VPMAXUD, VPMAXSB, VPMAXSW, VPMAXSD,

    // --- Integer packed shift ---
    VPSLLW, VPSLLD, VPSLLQ, VPSLLDQ, VPSRLW, VPSRLD, VPSRLQ, VPSRLDQ, VPSRAW, VPSRAD,
    VPSLLVD, VPSLLVQ, VPSRLVD, VPSRLVQ, VPSRAVD,

    // --- Integer shuffle / unpack ---
    VPSHUFD, VPSHUFB,
    VPUNPCKLBW, VPUNPCKLWD, VPUNPCKLDQ, VPUNPCKLQDQ,
    VPUNPCKHBW, VPUNPCKHWD, VPUNPCKHDQ, VPUNPCKHQDQ,
    VPACKSSWB, VPACKUSWB, VPACKSSDW, VPACKUSDW,
    VPALIGNR,

    // --- Integer blend / insert / extract ---
    VPBLENDW, VPBLENDVB, VPBLENDD, VBLENDPS, VBLENDPD,
    VBLENDVPS, VBLENDVPD,
    VPINSRB, VPINSRW, VPINSRD, VPINSRQ,
    VPEXTRB, VPEXTRW, VPEXTRD, VPEXTRQ,
    VINSERTPS, VEXTRACTPS,

    // --- Integer abs / sign / hadd ---
    VPABSB, VPABSW, VPABSD,
    VPHADDW, VPHADDD, VPHADDSW,
    VPHSUBW, VPHSUBD, VPHSUBSW,
    VPSIGNB, VPSIGNW, VPSIGND,
    VPHMINPOSUW,
    VPMOVMSKB,

    // --- Integer sign/zero extend ---
    VPMOVSXBW, VPMOVSXBD, VPMOVSXBQ, VPMOVSXWD, VPMOVSXWQ, VPMOVSXDQ,
    VPMOVZXBW, VPMOVZXBD, VPMOVZXBQ, VPMOVZXWD, VPMOVZXWQ, VPMOVZXDQ,

    // --- SSE3 horizontal ---
    VHADDPS, VHADDPD, VHSUBPS, VHSUBPD,
    VADDSUBPS, VADDSUBPD,
    VLDDQU,

    // --- SSE4 round / dot product ---
    VROUNDPS, VROUNDPD, VROUNDSS, VROUNDSD,
    VDPPS, VDPPD, VMPSADBW,

    // --- SSE4.2 string ---
    VPCMPESTRM, VPCMPESTRI, VPCMPISTRM, VPCMPISTRI,

    // --- AVX2 insert/extract 128/256 ---
    VINSERTF128, VINSERTF32X4, VINSERTI128, VINSERTI32X4,
    VEXTRACTF128, VEXTRACTF32X4, VEXTRACTI128, VEXTRACTI32X4,

    // --- AVX2 gather ---
    VPGATHERDD, VPGATHERDQ, VPGATHERQD, VPGATHERQQ,
    VGATHERDPS, VGATHERDPD, VGATHERQPS, VGATHERQPD,

    // --- AVX2 mask move ---
    VMASKMOVPS, VMASKMOVPD, VPMASKMOVD, VPMASKMOVQ,

    // --- AVX2 LDMXCSR/STMXCSR ---
    VLDMXCSR, VSTMXCSR,

    // --- FMA ---
    VFMADD132PS, VFMADD213PS, VFMADD231PS,
    VFMADD132PD, VFMADD213PD, VFMADD231PD,
    VFMADD132SS, VFMADD213SS, VFMADD231SS,
    VFMADD132SD, VFMADD213SD, VFMADD231SD,
    VFMSUB132PS, VFMSUB213PS, VFMSUB231PS,
    VFMSUB132PD, VFMSUB213PD, VFMSUB231PD,
    VFMSUB132SS, VFMSUB213SS, VFMSUB231SS,
    VFMSUB132SD, VFMSUB213SD, VFMSUB231SD,
    VFNMADD132PS, VFNMADD213PS, VFNMADD231PS,
    VFNMADD132PD, VFNMADD213PD, VFNMADD231PD,
    VFNMADD132SS, VFNMADD213SS, VFNMADD231SS,
    VFNMADD132SD, VFNMADD213SD, VFNMADD231SD,
    VFNMSUB132PS, VFNMSUB213PS, VFNMSUB231PS,
    VFNMSUB132PD, VFNMSUB213PD, VFNMSUB231PD,
    VFNMSUB132SS, VFNMSUB213SS, VFNMSUB231SS,
    VFNMSUB132SD, VFNMSUB213SD, VFNMSUB231SD,

    VZEROALL, VZEROUPPER,

    // =========================================================================
    // AES-NI
    // =========================================================================

    AESENC, AESENCLAST, AESDEC, AESDECLAST, AESIMC, AESKEYGENASSIST,
    VAESENC, VAESENCLAST, VAESDEC, VAESDECLAST, VAESIMC, VAESKEYGENASSIST,
    PCLMULQDQ, VPCLMULQDQ,

    // =========================================================================
    // SHA
    // =========================================================================

    SHA1RNDS4, SHA1NEXTE, SHA1MSG1, SHA1MSG2,
    SHA256RNDS2, SHA256MSG1, SHA256MSG2,

    // =========================================================================
    // BMI1 / BMI2
    // =========================================================================

    ANDN, BEXTR, BLSI, BLSMSK, BLSR,
    BZHI, MULX, PDEP, PEXT, RORX, SARX, SHLX, SHRX,

    // =========================================================================
    // ADX
    // =========================================================================

    ADCX, ADOX,

    // =========================================================================
    // x87 FPU
    // =========================================================================

    // --- Load / store ---
    FLD, FST, FSTP, FILD, FIST, FISTP,
    FLDZ, FLD1, FLDPI, FLDL2E, FLDL2T, FLDLN2, FLDLG2,

    // --- Arithmetic ---
    FADD, FADDP, FIADD, FSUB, FSUBP, FISUB, FSUBR, FSUBRP, FISUBR,
    FMUL, FMULP, FIMUL, FDIV, FDIVP, FIDIV, FDIVR, FDIVRP, FIDIVR,

    // --- Compare ---
    FCOM, FCOMP, FCOMPP, FCOMI, FCOMIP, FUCOMI, FUCOMIP,
    FUCOM, FUCOMP, FUCOMPP,
    FICOM, FICOMP,

    // --- Unary ---
    FABS, FCHS, FSQRT, FRNDINT, FSCALE, FPREM, FPREM1, FXTRACT,

    // --- Transcendental ---
    FSIN, FCOS, FSINCOS, FPTAN, FPATAN, F2XM1, FYL2X, FYL2XP1,

    // --- Stack / misc ---
    FXCH, FFREE, FINCSTP, FDECSTP,
    FNOP, FWAIT, FINIT, FNINIT, FCLEX, FNCLEX,

    // --- Control-word / environment ---
    FLDCW, FNSTCW, FSTCW, FNSTSW, FSTSW,
    FLDENV, FNSTENV, FSTENV, FRSTOR, FNSAVE, FSAVE,

    // =========================================================================
    // AVX-512 (representative subset)
    // =========================================================================

    VMOVDQA32, VMOVDQA64, VMOVDQU8, VMOVDQU16, VMOVDQU32, VMOVDQU64,

    VADDPS_Z, VSUBPS_Z, VMULPS_Z, VDIVPS_Z,

    VPCOMPRESSD, VPCOMPRESSQ, VPEXPANDD, VPEXPANDQ,
    VPTESTMD, VPTESTMQ, VPTESTNMD, VPTESTNMQ,
    VPTERNLOGD, VPTERNLOGQ,

    VCVTPS2PH, VCVTPH2PS,

    VPCONFLICTD, VPCONFLICTQ, VPLZCNTD, VPLZCNTQ,

    VSCALEFPS, VSCALEFPD, VSCALEFSS, VSCALEFSD,
    VRCP14PS, VRCP14PD, VRCP14SS, VRCP14SD,
    VRSQRT14PS, VRSQRT14PD, VRSQRT14SS, VRSQRT14SD,

    VFIXUPIMMPS, VFIXUPIMMPD, VFIXUPIMMSS, VFIXUPIMMSD,
    VGETEXPPS, VGETEXPPD, VGETEXPSS, VGETEXPSD,
    VGETMANTPS, VGETMANTPD, VGETMANTSS, VGETMANTSD,

    // =========================================================================
    // VMX / SVM Virtualization
    // =========================================================================

    VMCALL, VMLAUNCH, VMRESUME, VMXOFF,
    VMREAD, VMWRITE, VMPTRLD, VMPTRST, VMCLEAR, VMXON,
    INVEPT, INVVPID,

    // =========================================================================
    // MONITOR / MWAIT
    // =========================================================================

    MONITOR_INST, MWAIT_INST,

    // =========================================================================
    // AVX-512 additional
    // =========================================================================

    VADDPD_Z, VSUBPD_Z, VMULPD_Z, VDIVPD_Z,
    VANDPS_Z, VANDPD_Z, VORPS_Z, VORPD_Z, VXORPS_Z, VXORPD_Z,

    VPCMPB, VPCMPW, VPCMPD, VPCMPQ,
    VPCMPUB, VPCMPUW, VPCMPUD, VPCMPUQ,

    VPBROADCASTB, VPBROADCASTW, VPBROADCASTD, VPBROADCASTQ,

    VSCATTERDPS, VSCATTERDPD, VSCATTERQPS, VSCATTERQPD,
    VPSCATTERDD, VPSCATTERDQ, VPSCATTERQD, VPSCATTERQQ,

    VPROLD, VPROLQ, VPRORD, VPRORQ,
    VPROLVD, VPROLVQ, VPRORVD, VPRORVQ,

    VPANDD, VPANDQ, VPANDND, VPANDNQ,
    VPORD, VPORQ, VPXORD, VPXORQ,

    VCVTUDQ2PS, VCVTUDQ2PD, VCVTPS2UDQ, VCVTPD2UDQ,
    VCVTTPS2UDQ, VCVTTPD2UDQ,
    VCVTUSI2SS, VCVTUSI2SD, VCVTSS2USI, VCVTSD2USI,
    VCVTTSS2USI, VCVTTSD2USI,

    VPMOVB2M, VPMOVW2M, VPMOVD2M, VPMOVQ2M,
    VPMOVM2B, VPMOVM2W, VPMOVM2D, VPMOVM2Q,

    VPMOVDB, VPMOVDW, VPMOVQB, VPMOVQD, VPMOVQW, VPMOVWB,
    VPMOVSDB, VPMOVSDW, VPMOVSQB, VPMOVSQD, VPMOVSQW, VPMOVSWB,
    VPMOVUSDB, VPMOVUSDW, VPMOVUSQB, VPMOVUSQD, VPMOVUSQW, VPMOVUSWB,

    VRANGEPS, VRANGEPD, VRANGESS, VRANGESD,
    VREDUCEPS, VREDUCEPD, VREDUCESS, VREDUCESD,

    VDBPSADBW,

    // AVX-512 VNNI (Vector Neural Network Instructions)
    VPDPBUSD, VPDPBUSDS, VPDPWSSD, VPDPWSSDS,

    // AVX-512 VBMI (Vector Byte Manipulation Instructions)
    VPERMB, VPERMI2B, VPERMI2W, VPERMI2D, VPERMI2Q,
    VPERMT2B, VPERMT2W, VPERMT2D, VPERMT2Q,

    // AVX-512 IFMA (Integer Fused Multiply-Add)
    VPMADD52LUQ, VPMADD52HUQ,

    // AVX-512 BITALG
    VPSHUFBITQMB, VPOPCNTB, VPOPCNTW,

    // AVX-512DQ additional
    VFPCLASSPS, VFPCLASSPD, VFPCLASSSS, VFPCLASSSD,
    VCVTQQ2PS, VCVTQQ2PD, VCVTTPD2QQ, VCVTTPD2UQQ,
    VCVTPD2QQ, VCVTPD2UQQ,
    VCVTUQQ2PS, VCVTUQQ2PD,
    VPMULLQ, VEXTRACTF64X2, VEXTRACTI64X2,
    VINSERTF64X2, VINSERTI64X2,

    // SHA-512 (Intel Golden Cove+)
    SHA512RNDS2, SHA512MSG1, SHA512MSG2,

    // GFNI (Galois Field New Instructions)
    GF2P8AFFINEINVQB, GF2P8AFFINEQB, GF2P8MULB,
    VGF2P8AFFINEINVQB, VGF2P8AFFINEQB, VGF2P8MULB,

    // CMPCCXADD (atomic conditional add, Sierra Forest+)
    CMPccXADD,

    // SM3 (Chinese cryptographic hash)
    VSM3MSG1, VSM3MSG2, VSM3RNDS2,

    // SM4 (Chinese block cipher)
    VSM4KEY4, VSM4RNDS4,

    // Miscellaneous modern instructions
    SERIALIZE,      // 0F 01 E8 — memory ordering fence
    PREFETCHIT0,    // 0F 18 /7 — instruction prefetch L1
    PREFETCHIT1,    // 0F 18 /6 — instruction prefetch L2
    CLDEMOTE,       // 0F 1C /0 — cache line demote
    UMONITOR,       // F3 0F AE /6 — user-level monitor
    UMWAIT,         // F2 0F AE /6 — user-level wait
    TPAUSE,         // 66 0F AE /6 — timed pause
    ENQCMD,         // F3 0F 38 F8 — enqueue command
    ENQCMDS,        // F2 0F 38 F8 — enqueue command supervisor
    MOVDIRI,        // 0F 38 F9 — direct store integer
    MOVDIR64B,      // 66 0F 38 F8 — direct store 64 bytes

    // --- Sentinel ---
    UNKNOWN,
    MAX_MNEMONIC,
};

// ---------------------------------------------------------------------------
// MnemonicToString – returns a human-readable name for every mnemonic value.
// Implemented as a switch so the compiler can verify exhaustiveness.
// ---------------------------------------------------------------------------

[[nodiscard]] inline constexpr std::string_view MnemonicToString(Mnemonic m) noexcept {
    switch (m) {
    case Mnemonic::ADD:           return "add";
    case Mnemonic::SUB:           return "sub";
    case Mnemonic::XOR:           return "xor";
    case Mnemonic::AND:           return "and";
    case Mnemonic::OR:            return "or";
    case Mnemonic::CMP:           return "cmp";
    case Mnemonic::TEST:          return "test";
    case Mnemonic::INC:           return "inc";
    case Mnemonic::DEC:           return "dec";
    case Mnemonic::NOT:           return "not";
    case Mnemonic::NEG:           return "neg";
    case Mnemonic::DIV:           return "div";
    case Mnemonic::IDIV:          return "idiv";
    case Mnemonic::MUL:           return "mul";
    case Mnemonic::IMUL:          return "imul";
    case Mnemonic::MOV:           return "mov";
    case Mnemonic::MOVZX:         return "movzx";
    case Mnemonic::MOVSX:         return "movsx";
    case Mnemonic::MOVSXD:        return "movsxd";
    case Mnemonic::LEA:           return "lea";
    case Mnemonic::XCHG:          return "xchg";
    case Mnemonic::PUSH:          return "push";
    case Mnemonic::POP:           return "pop";
    case Mnemonic::PUSHA:         return "pusha";
    case Mnemonic::PUSHAD:        return "pushad";
    case Mnemonic::POPA:          return "popa";
    case Mnemonic::POPAD:         return "popad";
    case Mnemonic::SHL:           return "shl";
    case Mnemonic::SHR:           return "shr";
    case Mnemonic::SAR:           return "sar";
    case Mnemonic::SAL:           return "sal";
    case Mnemonic::ROL:           return "rol";
    case Mnemonic::ROR:           return "ror";
    case Mnemonic::RCL:           return "rcl";
    case Mnemonic::RCR:           return "rcr";
    case Mnemonic::JMP:           return "jmp";
    case Mnemonic::CALL:          return "call";
    case Mnemonic::RET:           return "ret";
    case Mnemonic::RETF:          return "retf";
    case Mnemonic::LOOP:          return "loop";
    case Mnemonic::LOOPE:         return "loope";
    case Mnemonic::LOOPNE:        return "loopne";
    case Mnemonic::JZ:            return "jz";
    case Mnemonic::JNZ:           return "jnz";
    case Mnemonic::JO:            return "jo";
    case Mnemonic::JNO:           return "jno";
    case Mnemonic::JP:            return "jp";
    case Mnemonic::JNP:           return "jnp";
    case Mnemonic::JS:            return "js";
    case Mnemonic::JNS:           return "jns";
    case Mnemonic::JB:            return "jb";
    case Mnemonic::JBE:           return "jbe";
    case Mnemonic::JL:            return "jl";
    case Mnemonic::JLE:           return "jle";
    case Mnemonic::JNB:           return "jnb";
    case Mnemonic::JNBE:          return "jnbe";
    case Mnemonic::JNL:           return "jnl";
    case Mnemonic::JNLE:          return "jnle";
    case Mnemonic::JCXZ:          return "jcxz";
    case Mnemonic::JECXZ:         return "jecxz";
    case Mnemonic::JRCXZ:         return "jrcxz";
    case Mnemonic::MOVSB:         return "movsb";
    case Mnemonic::MOVSW:         return "movsw";
    case Mnemonic::MOVSD_STR:     return "movsd";
    case Mnemonic::MOVSQ:         return "movsq";
    case Mnemonic::LODSB:         return "lodsb";
    case Mnemonic::LODSW:         return "lodsw";
    case Mnemonic::LODSD:         return "lodsd";
    case Mnemonic::LODSQ:         return "lodsq";
    case Mnemonic::STOSB:         return "stosb";
    case Mnemonic::STOSW:         return "stosw";
    case Mnemonic::STOSD:         return "stosd";
    case Mnemonic::STOSQ:         return "stosq";
    case Mnemonic::SCASB:         return "scasb";
    case Mnemonic::SCASW:         return "scasw";
    case Mnemonic::SCASD:         return "scasd";
    case Mnemonic::SCASQ:         return "scasq";
    case Mnemonic::CMPSB:         return "cmpsb";
    case Mnemonic::CMPSW:         return "cmpsw";
    case Mnemonic::CMPSD_STR:     return "cmpsd";
    case Mnemonic::CMPSQ:         return "cmpsq";
    case Mnemonic::INT:           return "int";
    case Mnemonic::INT1:          return "int1";
    case Mnemonic::INT3:          return "int3";
    case Mnemonic::INTO:          return "into";
    case Mnemonic::IRET:          return "iret";
    case Mnemonic::IRETD:         return "iretd";
    case Mnemonic::IRETQ:         return "iretq";
    case Mnemonic::SYSCALL:       return "syscall";
    case Mnemonic::SYSENTER:      return "sysenter";
    case Mnemonic::SYSEXIT:       return "sysexit";
    case Mnemonic::SYSRET:        return "sysret";
    case Mnemonic::RDTSC:         return "rdtsc";
    case Mnemonic::RDTSCP:        return "rdtscp";
    case Mnemonic::RDPMC:         return "rdpmc";
    case Mnemonic::CPUID:         return "cpuid";
    case Mnemonic::HLT:           return "hlt";
    case Mnemonic::IN_INST:       return "in";
    case Mnemonic::OUT_INST:      return "out";
    case Mnemonic::INS_INST:      return "ins";
    case Mnemonic::OUTS_INST:     return "outs";
    case Mnemonic::PUSHF:         return "pushf";
    case Mnemonic::PUSHFQ:        return "pushfq";
    case Mnemonic::PUSHFD:        return "pushfd";
    case Mnemonic::POPF:          return "popf";
    case Mnemonic::POPFQ:         return "popfq";
    case Mnemonic::POPFD:         return "popfd";
    case Mnemonic::CLC:           return "clc";
    case Mnemonic::STC:           return "stc";
    case Mnemonic::CLI:           return "cli";
    case Mnemonic::STI:           return "sti";
    case Mnemonic::CLD:           return "cld";
    case Mnemonic::STD:           return "std";
    case Mnemonic::CMC:           return "cmc";
    case Mnemonic::LAHF:          return "lahf";
    case Mnemonic::SAHF:          return "sahf";
    case Mnemonic::SGDT:          return "sgdt";
    case Mnemonic::SIDT:          return "sidt";
    case Mnemonic::SLDT:          return "sldt";
    case Mnemonic::STR:           return "str";
    case Mnemonic::LGDT:          return "lgdt";
    case Mnemonic::LIDT:          return "lidt";
    case Mnemonic::LLDT:          return "lldt";
    case Mnemonic::LTR:           return "ltr";
    case Mnemonic::LMSW:          return "lmsw";
    case Mnemonic::SMSW:          return "smsw";
    case Mnemonic::CMPXCHG:       return "cmpxchg";
    case Mnemonic::CMPXCHG8B:     return "cmpxchg8b";
    case Mnemonic::CMPXCHG16B:    return "cmpxchg16b";
    case Mnemonic::XADD:          return "xadd";
    case Mnemonic::LOCK_PREFIX:   return "lock";
    case Mnemonic::UD0:           return "ud0";
    case Mnemonic::UD1:           return "ud1";
    case Mnemonic::UD2:           return "ud2";
    case Mnemonic::NOP:           return "nop";
    case Mnemonic::PAUSE:         return "pause";
    case Mnemonic::ENDBR32:       return "endbr32";
    case Mnemonic::ENDBR64:       return "endbr64";
    case Mnemonic::INCSSPD:       return "incsspd";
    case Mnemonic::INCSSPQ:       return "incsspq";
    case Mnemonic::RDSSPD:        return "rdsspd";
    case Mnemonic::RDSSPQ:        return "rdsspq";
    case Mnemonic::SAVEPREVSSP:   return "saveprevssp";
    case Mnemonic::RSTORSSP:      return "rstorssp";
    case Mnemonic::SETSSBSY:      return "setssbsy";
    case Mnemonic::CLRSSBSY:      return "clrssbsy";
    case Mnemonic::WRSSD:         return "wrssd";
    case Mnemonic::WRSSQ:         return "wrssq";
    case Mnemonic::WRUSSD:        return "wrussd";
    case Mnemonic::WRUSSQ:        return "wrussq";
    case Mnemonic::LDTILECFG:     return "ldtilecfg";
    case Mnemonic::STTILECFG:     return "sttilecfg";
    case Mnemonic::TILELOADD:     return "tileloadd";
    case Mnemonic::TILESTORED:    return "tilestored";
    case Mnemonic::TILEZERO:      return "tilezero";
    case Mnemonic::TILERELEASE:   return "tilerelease";
    case Mnemonic::TDPBSSD:       return "tdpbssd";
    case Mnemonic::TDPBSUD:       return "tdpbsud";
    case Mnemonic::TDPBUSD:       return "tdpbusd";
    case Mnemonic::TDPBUUD:       return "tdpbuud";
    case Mnemonic::TDPBF16PS:     return "tdpbf16ps";
    case Mnemonic::TDPFP16PS:     return "tdpfp16ps";
    case Mnemonic::CBW:           return "cbw";
    case Mnemonic::CWDE:          return "cwde";
    case Mnemonic::CDQE:          return "cdqe";
    case Mnemonic::CWD:           return "cwd";
    case Mnemonic::CDQ:           return "cdq";
    case Mnemonic::CQO:           return "cqo";
    case Mnemonic::ENTER:         return "enter";
    case Mnemonic::LEAVE:         return "leave";
    case Mnemonic::BT:            return "bt";
    case Mnemonic::BTS:           return "bts";
    case Mnemonic::BTR:           return "btr";
    case Mnemonic::BTC:           return "btc";
    case Mnemonic::BSF:           return "bsf";
    case Mnemonic::BSR:           return "bsr";
    case Mnemonic::POPCNT:        return "popcnt";
    case Mnemonic::LZCNT:         return "lzcnt";
    case Mnemonic::TZCNT:         return "tzcnt";
    case Mnemonic::BSWAP:         return "bswap";
    case Mnemonic::MOVBE:         return "movbe";
    case Mnemonic::CMOVZ:         return "cmovz";
    case Mnemonic::CMOVNZ:        return "cmovnz";
    case Mnemonic::CMOVB:         return "cmovb";
    case Mnemonic::CMOVNB:        return "cmovnb";
    case Mnemonic::CMOVBE:        return "cmovbe";
    case Mnemonic::CMOVNBE:       return "cmovnbe";
    case Mnemonic::CMOVL:         return "cmovl";
    case Mnemonic::CMOVNL:        return "cmovnl";
    case Mnemonic::CMOVLE:        return "cmovle";
    case Mnemonic::CMOVNLE:       return "cmovnle";
    case Mnemonic::CMOVO:         return "cmovo";
    case Mnemonic::CMOVNO:        return "cmovno";
    case Mnemonic::CMOVS:         return "cmovs";
    case Mnemonic::CMOVNS:        return "cmovns";
    case Mnemonic::CMOVP:         return "cmovp";
    case Mnemonic::CMOVNP:        return "cmovnp";
    case Mnemonic::SETZ:          return "setz";
    case Mnemonic::SETNZ:         return "setnz";
    case Mnemonic::SETB:          return "setb";
    case Mnemonic::SETNB:         return "setnb";
    case Mnemonic::SETBE:         return "setbe";
    case Mnemonic::SETNBE:        return "setnbe";
    case Mnemonic::SETL:          return "setl";
    case Mnemonic::SETNL:         return "setnl";
    case Mnemonic::SETLE:         return "setle";
    case Mnemonic::SETNLE:        return "setnle";
    case Mnemonic::SETO:          return "seto";
    case Mnemonic::SETNO:         return "setno";
    case Mnemonic::SETS:          return "sets";
    case Mnemonic::SETNS:         return "setns";
    case Mnemonic::SETP:          return "setp";
    case Mnemonic::SETNP:         return "setnp";
    case Mnemonic::RDMSR:         return "rdmsr";
    case Mnemonic::WRMSR:         return "wrmsr";
    case Mnemonic::RDPID:         return "rdpid";
    case Mnemonic::CLTS:          return "clts";
    case Mnemonic::INVD:          return "invd";
    case Mnemonic::WBINVD:        return "wbinvd";
    case Mnemonic::INVLPG:        return "invlpg";
    case Mnemonic::SWAPGS:        return "swapgs";
    case Mnemonic::WRFSBASE:      return "wrfsbase";
    case Mnemonic::WRGSBASE:      return "wrgsbase";
    case Mnemonic::RDFSBASE:      return "rdfsbase";
    case Mnemonic::RDGSBASE:      return "rdgsbase";
    case Mnemonic::MFENCE:        return "mfence";
    case Mnemonic::SFENCE:        return "sfence";
    case Mnemonic::LFENCE:        return "lfence";
    case Mnemonic::PREFETCHT0:    return "prefetcht0";
    case Mnemonic::PREFETCHT1:    return "prefetcht1";
    case Mnemonic::PREFETCHT2:    return "prefetcht2";
    case Mnemonic::PREFETCHNTA:   return "prefetchnta";
    case Mnemonic::CLFLUSH:       return "clflush";
    case Mnemonic::CLFLUSHOPT:    return "clflushopt";
    case Mnemonic::CLWB:          return "clwb";
    case Mnemonic::XGETBV:        return "xgetbv";
    case Mnemonic::XSETBV:        return "xsetbv";
    case Mnemonic::XSAVE:         return "xsave";
    case Mnemonic::XRSTOR:        return "xrstor";
    case Mnemonic::XSAVEOPT:      return "xsaveopt";
    case Mnemonic::XSAVEC:        return "xsavec";
    case Mnemonic::XSAVES:        return "xsaves";
    case Mnemonic::XRSTORS:       return "xrstors";
    case Mnemonic::FXSAVE:        return "fxsave";
    case Mnemonic::FXRSTOR:       return "fxrstor";
    case Mnemonic::MONITOR:       return "monitor";
    case Mnemonic::MWAIT:         return "mwait";

    // SSE moves
    case Mnemonic::MOVSS:         return "movss";
    case Mnemonic::MOVSD_SSE:     return "movsd";
    case Mnemonic::MOVAPS:        return "movaps";
    case Mnemonic::MOVUPS:        return "movups";
    case Mnemonic::MOVAPD:        return "movapd";
    case Mnemonic::MOVUPD:        return "movupd";
    case Mnemonic::MOVDQA:        return "movdqa";
    case Mnemonic::MOVDQU:        return "movdqu";
    case Mnemonic::MOVQ_SSE:      return "movq";
    case Mnemonic::MOVD_SSE:      return "movd";
    case Mnemonic::MOVLPS:        return "movlps";
    case Mnemonic::MOVHPS:        return "movhps";
    case Mnemonic::MOVLPD:        return "movlpd";
    case Mnemonic::MOVHPD:        return "movhpd";
    case Mnemonic::MOVLHPS:       return "movlhps";
    case Mnemonic::MOVHLPS:       return "movhlps";
    case Mnemonic::MOVNTPS:       return "movntps";
    case Mnemonic::MOVNTPD:       return "movntpd";
    case Mnemonic::MOVNTI:        return "movnti";
    case Mnemonic::MOVNTDQ:       return "movntdq";
    case Mnemonic::MOVNTDQA:      return "movntdqa";

    // SSE arithmetic
    case Mnemonic::ADDSS:         return "addss";
    case Mnemonic::ADDSD:         return "addsd";
    case Mnemonic::ADDPS:         return "addps";
    case Mnemonic::ADDPD:         return "addpd";
    case Mnemonic::SUBSS:         return "subss";
    case Mnemonic::SUBSD:         return "subsd";
    case Mnemonic::SUBPS:         return "subps";
    case Mnemonic::SUBPD:         return "subpd";
    case Mnemonic::MULSS:         return "mulss";
    case Mnemonic::MULSD:         return "mulsd";
    case Mnemonic::MULPS:         return "mulps";
    case Mnemonic::MULPD:         return "mulpd";
    case Mnemonic::DIVSS:         return "divss";
    case Mnemonic::DIVSD:         return "divsd";
    case Mnemonic::DIVPS:         return "divps";
    case Mnemonic::DIVPD:         return "divpd";
    case Mnemonic::SQRTSS:        return "sqrtss";
    case Mnemonic::SQRTSD:        return "sqrtsd";
    case Mnemonic::SQRTPS:        return "sqrtps";
    case Mnemonic::SQRTPD:        return "sqrtpd";
    case Mnemonic::RSQRTSS:       return "rsqrtss";
    case Mnemonic::RSQRTPS:       return "rsqrtps";
    case Mnemonic::RCPSS:         return "rcpss";
    case Mnemonic::RCPPS:         return "rcpps";
    case Mnemonic::MAXSS:         return "maxss";
    case Mnemonic::MAXSD:         return "maxsd";
    case Mnemonic::MAXPS:         return "maxps";
    case Mnemonic::MAXPD:         return "maxpd";
    case Mnemonic::MINSS:         return "minss";
    case Mnemonic::MINSD:         return "minsd";
    case Mnemonic::MINPS:         return "minps";
    case Mnemonic::MINPD:         return "minpd";

    // SSE compare
    case Mnemonic::CMPSS:         return "cmpss";
    case Mnemonic::CMPSD_CMP:     return "cmpsd";
    case Mnemonic::CMPPS:         return "cmpps";
    case Mnemonic::CMPPD:         return "cmppd";
    case Mnemonic::COMISS:        return "comiss";
    case Mnemonic::COMISD:        return "comisd";
    case Mnemonic::UCOMISS:       return "ucomiss";
    case Mnemonic::UCOMISD:       return "ucomisd";

    // SSE logic
    case Mnemonic::ANDPS:         return "andps";
    case Mnemonic::ANDPD:         return "andpd";
    case Mnemonic::ANDNPS:        return "andnps";
    case Mnemonic::ANDNPD:        return "andnpd";
    case Mnemonic::ORPS:          return "orps";
    case Mnemonic::ORPD:          return "orpd";
    case Mnemonic::XORPS:         return "xorps";
    case Mnemonic::XORPD:         return "xorpd";

    // SSE unpack/shuffle
    case Mnemonic::UNPCKLPS:      return "unpcklps";
    case Mnemonic::UNPCKHPS:      return "unpckhps";
    case Mnemonic::UNPCKLPD:      return "unpcklpd";
    case Mnemonic::UNPCKHPD:      return "unpckhpd";
    case Mnemonic::SHUFPS:        return "shufps";
    case Mnemonic::SHUFPD:        return "shufpd";

    // SSE convert
    case Mnemonic::CVTSI2SS:      return "cvtsi2ss";
    case Mnemonic::CVTSI2SD:      return "cvtsi2sd";
    case Mnemonic::CVTSS2SD:      return "cvtss2sd";
    case Mnemonic::CVTSD2SS:      return "cvtsd2ss";
    case Mnemonic::CVTSS2SI:      return "cvtss2si";
    case Mnemonic::CVTSD2SI:      return "cvtsd2si";
    case Mnemonic::CVTTSS2SI:     return "cvttss2si";
    case Mnemonic::CVTTSD2SI:     return "cvttsd2si";
    case Mnemonic::CVTDQ2PS:      return "cvtdq2ps";
    case Mnemonic::CVTDQ2PD:      return "cvtdq2pd";
    case Mnemonic::CVTPS2DQ:      return "cvtps2dq";
    case Mnemonic::CVTPD2DQ:      return "cvtpd2dq";
    case Mnemonic::CVTTPS2DQ:     return "cvttps2dq";
    case Mnemonic::CVTTPD2DQ:     return "cvttpd2dq";
    case Mnemonic::CVTPS2PD:      return "cvtps2pd";
    case Mnemonic::CVTPD2PS:      return "cvtpd2ps";

    // SSE pack
    case Mnemonic::PACKUSWB:      return "packuswb";
    case Mnemonic::PACKSSWB:      return "packsswb";
    case Mnemonic::PACKSSDW:      return "packssdw";
    case Mnemonic::PACKUSDW:      return "packusdw";

    // SSE integer arithmetic
    case Mnemonic::PADDB:         return "paddb";
    case Mnemonic::PADDW:         return "paddw";
    case Mnemonic::PADDD:         return "paddd";
    case Mnemonic::PADDQ:         return "paddq";
    case Mnemonic::PSUBB:         return "psubb";
    case Mnemonic::PSUBW:         return "psubw";
    case Mnemonic::PSUBD:         return "psubd";
    case Mnemonic::PSUBQ:         return "psubq";
    case Mnemonic::PADDSB:        return "paddsb";
    case Mnemonic::PADDSW:        return "paddsw";
    case Mnemonic::PADDUSB:       return "paddusb";
    case Mnemonic::PADDUSW:       return "paddusw";
    case Mnemonic::PSUBSB:        return "psubsb";
    case Mnemonic::PSUBSW:        return "psubsw";
    case Mnemonic::PSUBUSB:       return "psubusb";
    case Mnemonic::PSUBUSW:       return "psubusw";
    case Mnemonic::PMULLW:        return "pmullw";
    case Mnemonic::PMULHW:        return "pmulhw";
    case Mnemonic::PMULHUW:       return "pmulhuw";
    case Mnemonic::PMULUDQ:       return "pmuludq";
    case Mnemonic::PMULLD:        return "pmulld";
    case Mnemonic::PMULDQ:        return "pmuldq";
    case Mnemonic::PMADDWD:       return "pmaddwd";
    case Mnemonic::PMADDUBSW:     return "pmaddubsw";

    // SSE integer compare
    case Mnemonic::PCMPEQB:       return "pcmpeqb";
    case Mnemonic::PCMPEQW:       return "pcmpeqw";
    case Mnemonic::PCMPEQD:       return "pcmpeqd";
    case Mnemonic::PCMPEQQ:       return "pcmpeqq";
    case Mnemonic::PCMPGTB:       return "pcmpgtb";
    case Mnemonic::PCMPGTW:       return "pcmpgtw";
    case Mnemonic::PCMPGTD:       return "pcmpgtd";
    case Mnemonic::PCMPGTQ:       return "pcmpgtq";

    // SSE integer min/max
    case Mnemonic::PMINUB:        return "pminub";
    case Mnemonic::PMINUW:        return "pminuw";
    case Mnemonic::PMINUD:        return "pminud";
    case Mnemonic::PMINSB:        return "pminsb";
    case Mnemonic::PMINSW:        return "pminsw";
    case Mnemonic::PMINSD:        return "pminsd";
    case Mnemonic::PMAXUB:        return "pmaxub";
    case Mnemonic::PMAXUW:        return "pmaxuw";
    case Mnemonic::PMAXUD:        return "pmaxud";
    case Mnemonic::PMAXSB:        return "pmaxsb";
    case Mnemonic::PMAXSW:        return "pmaxsw";
    case Mnemonic::PMAXSD:        return "pmaxsd";

    // SSE integer logic
    case Mnemonic::PAND:          return "pand";
    case Mnemonic::PANDN:         return "pandn";
    case Mnemonic::POR:           return "por";
    case Mnemonic::PXOR:          return "pxor";

    // SSE integer shift
    case Mnemonic::PSLLW:         return "psllw";
    case Mnemonic::PSLLD:         return "pslld";
    case Mnemonic::PSLLQ:         return "psllq";
    case Mnemonic::PSLLDQ:        return "pslldq";
    case Mnemonic::PSRLW:         return "psrlw";
    case Mnemonic::PSRLD:         return "psrld";
    case Mnemonic::PSRLQ:         return "psrlq";
    case Mnemonic::PSRLDQ:        return "psrldq";
    case Mnemonic::PSRAW:         return "psraw";
    case Mnemonic::PSRAD:         return "psrad";

    // SSE integer shuffle/unpack
    case Mnemonic::PSHUFD:        return "pshufd";
    case Mnemonic::PSHUFB:        return "pshufb";
    case Mnemonic::PSHUFLW:       return "pshuflw";
    case Mnemonic::PSHUFHW:       return "pshufhw";
    case Mnemonic::PUNPCKLBW:     return "punpcklbw";
    case Mnemonic::PUNPCKLWD:     return "punpcklwd";
    case Mnemonic::PUNPCKLDQ:     return "punpckldq";
    case Mnemonic::PUNPCKLQDQ:    return "punpcklqdq";
    case Mnemonic::PUNPCKHBW:     return "punpckhbw";
    case Mnemonic::PUNPCKHWD:     return "punpckhwd";
    case Mnemonic::PUNPCKHDQ:     return "punpckhdq";
    case Mnemonic::PUNPCKHQDQ:    return "punpckhqdq";

    // SSE insert/extract
    case Mnemonic::PINSRB:        return "pinsrb";
    case Mnemonic::PINSRW:        return "pinsrw";
    case Mnemonic::PINSRD:        return "pinsrd";
    case Mnemonic::PINSRQ:        return "pinsrq";
    case Mnemonic::PEXTRB:        return "pextrb";
    case Mnemonic::PEXTRW:        return "pextrw";
    case Mnemonic::PEXTRD:        return "pextrd";
    case Mnemonic::PEXTRQ:        return "pextrq";

    // SSE4 blend/align
    case Mnemonic::PALIGNR:       return "palignr";
    case Mnemonic::PBLENDW:       return "pblendw";
    case Mnemonic::PBLENDVB:      return "pblendvb";
    case Mnemonic::BLENDPS:       return "blendps";
    case Mnemonic::BLENDPD:       return "blendpd";
    case Mnemonic::BLENDVPS:      return "blendvps";
    case Mnemonic::BLENDVPD:      return "blendvpd";
    case Mnemonic::INSERTPS:      return "insertps";
    case Mnemonic::EXTRACTPS:     return "extractps";

    // SSE4 dot/SAD
    case Mnemonic::DPPS:          return "dpps";
    case Mnemonic::DPPD:          return "dppd";
    case Mnemonic::MPSADBW:       return "mpsadbw";

    // SSE4 round
    case Mnemonic::ROUNDSS:       return "roundss";
    case Mnemonic::ROUNDSD:       return "roundsd";
    case Mnemonic::ROUNDPS:       return "roundps";
    case Mnemonic::ROUNDPD:       return "roundpd";

    // SSE4.2 string compare
    case Mnemonic::PCMPISTRI:     return "pcmpistri";
    case Mnemonic::PCMPISTRM:     return "pcmpistrm";
    case Mnemonic::PCMPESTRI:     return "pcmpestri";
    case Mnemonic::PCMPESTRM:     return "pcmpestrm";

    // SSE mask
    case Mnemonic::PTEST:         return "ptest";
    case Mnemonic::MOVMSKPS:      return "movmskps";
    case Mnemonic::MOVMSKPD:      return "movmskpd";
    case Mnemonic::PMOVMSKB:      return "pmovmskb";

    // MXCSR
    case Mnemonic::LDMXCSR:       return "ldmxcsr";
    case Mnemonic::STMXCSR:       return "stmxcsr";

    // SSE3 horizontal
    case Mnemonic::HADDPS:        return "haddps";
    case Mnemonic::HADDPD:        return "haddpd";
    case Mnemonic::HSUBPS:        return "hsubps";
    case Mnemonic::HSUBPD:        return "hsubpd";
    case Mnemonic::ADDSUBPS:      return "addsubps";
    case Mnemonic::ADDSUBPD:      return "addsubpd";
    case Mnemonic::LDDQU:         return "lddqu";
    case Mnemonic::MOVSLDUP:      return "movsldup";
    case Mnemonic::MOVSHDUP:      return "movshdup";
    case Mnemonic::MOVDDUP:       return "movddup";

    // SSSE3
    case Mnemonic::PABSB:         return "pabsb";
    case Mnemonic::PABSW:         return "pabsw";
    case Mnemonic::PABSD:         return "pabsd";
    case Mnemonic::PHADDW:        return "phaddw";
    case Mnemonic::PHADDD:        return "phaddd";
    case Mnemonic::PHADDSW:       return "phaddsw";
    case Mnemonic::PHSUBW:        return "phsubw";
    case Mnemonic::PHSUBD:        return "phsubd";
    case Mnemonic::PHSUBSW:       return "phsubsw";
    case Mnemonic::PSIGNB:        return "psignb";
    case Mnemonic::PSIGNW:        return "psignw";
    case Mnemonic::PSIGND:        return "psignd";

    // SSE4.2 CRC / POPCNT
    case Mnemonic::CRC32_INST:    return "crc32";
    case Mnemonic::POPCNT_INST:   return "popcnt";

    // AVX / AVX2
    case Mnemonic::VADDPS:        return "vaddps";
    case Mnemonic::VADDPD:        return "vaddpd";
    case Mnemonic::VADDSS:        return "vaddss";
    case Mnemonic::VADDSD:        return "vaddsd";
    case Mnemonic::VSUBPS:        return "vsubps";
    case Mnemonic::VSUBPD:        return "vsubpd";
    case Mnemonic::VSUBSS:        return "vsubss";
    case Mnemonic::VSUBSD:        return "vsubsd";
    case Mnemonic::VMULPS:        return "vmulps";
    case Mnemonic::VMULPD:        return "vmulpd";
    case Mnemonic::VMULSS:        return "vmulss";
    case Mnemonic::VMULSD:        return "vmulsd";
    case Mnemonic::VDIVPS:        return "vdivps";
    case Mnemonic::VDIVPD:        return "vdivpd";
    case Mnemonic::VDIVSS:        return "vdivss";
    case Mnemonic::VDIVSD:        return "vdivsd";
    case Mnemonic::VMOVAPS:       return "vmovaps";
    case Mnemonic::VMOVUPS:       return "vmovups";
    case Mnemonic::VMOVAPD:       return "vmovapd";
    case Mnemonic::VMOVUPD:       return "vmovupd";
    case Mnemonic::VMOVDQA:       return "vmovdqa";
    case Mnemonic::VMOVDQU:       return "vmovdqu";
    case Mnemonic::VMOVSS:        return "vmovss";
    case Mnemonic::VMOVSD_AVX:    return "vmovsd";
    case Mnemonic::VMOVD:         return "vmovd";
    case Mnemonic::VMOVQ:         return "vmovq";
    case Mnemonic::VBROADCASTSS:  return "vbroadcastss";
    case Mnemonic::VBROADCASTSD:  return "vbroadcastsd";
    case Mnemonic::VBROADCASTF128:return "vbroadcastf128";
    case Mnemonic::VPERM2F128:    return "vperm2f128";
    case Mnemonic::VPERM2I128:    return "vperm2i128";
    case Mnemonic::VPERMD:        return "vpermd";
    case Mnemonic::VPERMQ:        return "vpermq";
    case Mnemonic::VPERMPS:       return "vpermps";
    case Mnemonic::VPERMPD:       return "vpermpd";
    case Mnemonic::VPAND:         return "vpand";
    case Mnemonic::VPANDN:        return "vpandn";
    case Mnemonic::VPOR:          return "vpor";
    case Mnemonic::VPXOR:         return "vpxor";
    case Mnemonic::VPTEST:        return "vptest";
    case Mnemonic::VPADDB:        return "vpaddb";
    case Mnemonic::VPADDW:        return "vpaddw";
    case Mnemonic::VPADDD:        return "vpaddd";
    case Mnemonic::VPADDQ:        return "vpaddq";
    case Mnemonic::VPSUBB:        return "vpsubb";
    case Mnemonic::VPSUBW:        return "vpsubw";
    case Mnemonic::VPSUBD:        return "vpsubd";
    case Mnemonic::VPSUBQ:        return "vpsubq";
    case Mnemonic::VPMULLW:       return "vpmullw";
    case Mnemonic::VPMULLD:       return "vpmulld";
    case Mnemonic::VPMULUDQ:      return "vpmuludq";
    case Mnemonic::VPMULDQ:       return "vpmuldq";
    case Mnemonic::VPCMPEQB:      return "vpcmpeqb";
    case Mnemonic::VPCMPEQW:      return "vpcmpeqw";
    case Mnemonic::VPCMPEQD:      return "vpcmpeqd";
    case Mnemonic::VPCMPEQQ:      return "vpcmpeqq";
    case Mnemonic::VPCMPGTB:      return "vpcmpgtb";
    case Mnemonic::VPCMPGTW:      return "vpcmpgtw";
    case Mnemonic::VPCMPGTD:      return "vpcmpgtd";
    case Mnemonic::VPCMPGTQ:      return "vpcmpgtq";
    case Mnemonic::VPMINUB:       return "vpminub";
    case Mnemonic::VPMINUW:       return "vpminuw";
    case Mnemonic::VPMINUD:       return "vpminud";
    case Mnemonic::VPMINSB:       return "vpminsb";
    case Mnemonic::VPMINSW:       return "vpminsw";
    case Mnemonic::VPMINSD:       return "vpminsd";
    case Mnemonic::VPMAXUB:       return "vpmaxub";
    case Mnemonic::VPMAXUW:       return "vpmaxuw";
    case Mnemonic::VPMAXUD:       return "vpmaxud";
    case Mnemonic::VPMAXSB:       return "vpmaxsb";
    case Mnemonic::VPMAXSW:       return "vpmaxsw";
    case Mnemonic::VPMAXSD:       return "vpmaxsd";
    case Mnemonic::VPSLLW:        return "vpsllw";
    case Mnemonic::VPSLLD:        return "vpslld";
    case Mnemonic::VPSLLQ:        return "vpsllq";
    case Mnemonic::VPSLLDQ:       return "vpslldq";
    case Mnemonic::VPSRLW:        return "vpsrlw";
    case Mnemonic::VPSRLD:        return "vpsrld";
    case Mnemonic::VPSRLQ:        return "vpsrlq";
    case Mnemonic::VPSRLDQ:       return "vpsrldq";
    case Mnemonic::VPSRAW:        return "vpsraw";
    case Mnemonic::VPSRAD:        return "vpsrad";
    case Mnemonic::VPSLLVD:       return "vpsllvd";
    case Mnemonic::VPSLLVQ:       return "vpsllvq";
    case Mnemonic::VPSRLVD:       return "vpsrlvd";
    case Mnemonic::VPSRLVQ:       return "vpsrlvq";
    case Mnemonic::VPSRAVD:       return "vpsravd";
    case Mnemonic::VPSHUFD:       return "vpshufd";
    case Mnemonic::VPSHUFB:       return "vpshufb";
    case Mnemonic::VSHUFPS:       return "vshufps";
    case Mnemonic::VSHUFPD:       return "vshufpd";
    case Mnemonic::VPUNPCKLBW:    return "vpunpcklbw";
    case Mnemonic::VPUNPCKLWD:    return "vpunpcklwd";
    case Mnemonic::VPUNPCKLDQ:    return "vpunpckldq";
    case Mnemonic::VPUNPCKLQDQ:   return "vpunpcklqdq";
    case Mnemonic::VPUNPCKHBW:    return "vpunpckhbw";
    case Mnemonic::VPUNPCKHWD:    return "vpunpckhwd";
    case Mnemonic::VPUNPCKHDQ:    return "vpunpckhdq";
    case Mnemonic::VPUNPCKHQDQ:   return "vpunpckhqdq";
    case Mnemonic::VPBLENDW:      return "vpblendw";
    case Mnemonic::VPBLENDVB:     return "vpblendvb";
    case Mnemonic::VPBLENDD:      return "vpblendd";
    case Mnemonic::VBLENDPS:      return "vblendps";
    case Mnemonic::VBLENDPD:      return "vblendpd";
    case Mnemonic::VINSERTF128:   return "vinsertf128";
    case Mnemonic::VINSERTF32X4:  return "vinsertf32x4";
    case Mnemonic::VINSERTI128:   return "vinserti128";
    case Mnemonic::VINSERTI32X4:  return "vinserti32x4";
    case Mnemonic::VEXTRACTF128:  return "vextractf128";
    case Mnemonic::VEXTRACTF32X4: return "vextractf32x4";
    case Mnemonic::VEXTRACTI128:  return "vextracti128";
    case Mnemonic::VEXTRACTI32X4: return "vextracti32x4";
    case Mnemonic::VPGATHERDD:    return "vpgatherdd";
    case Mnemonic::VPGATHERDQ:    return "vpgatherdq";
    case Mnemonic::VPGATHERQD:    return "vpgatherqd";
    case Mnemonic::VPGATHERQQ:    return "vpgatherqq";
    case Mnemonic::VGATHERDPS:    return "vgatherdps";
    case Mnemonic::VGATHERDPD:    return "vgatherdpd";
    case Mnemonic::VGATHERQPS:    return "vgatherqps";
    case Mnemonic::VGATHERQPD:    return "vgatherqpd";

    // FMA
    case Mnemonic::VFMADD132PS:   return "vfmadd132ps";
    case Mnemonic::VFMADD213PS:   return "vfmadd213ps";
    case Mnemonic::VFMADD231PS:   return "vfmadd231ps";
    case Mnemonic::VFMADD132PD:   return "vfmadd132pd";
    case Mnemonic::VFMADD213PD:   return "vfmadd213pd";
    case Mnemonic::VFMADD231PD:   return "vfmadd231pd";
    case Mnemonic::VFMADD132SS:   return "vfmadd132ss";
    case Mnemonic::VFMADD213SS:   return "vfmadd213ss";
    case Mnemonic::VFMADD231SS:   return "vfmadd231ss";
    case Mnemonic::VFMADD132SD:   return "vfmadd132sd";
    case Mnemonic::VFMADD213SD:   return "vfmadd213sd";
    case Mnemonic::VFMADD231SD:   return "vfmadd231sd";
    case Mnemonic::VFMSUB132PS:   return "vfmsub132ps";
    case Mnemonic::VFMSUB213PS:   return "vfmsub213ps";
    case Mnemonic::VFMSUB231PS:   return "vfmsub231ps";
    case Mnemonic::VFMSUB132PD:   return "vfmsub132pd";
    case Mnemonic::VFMSUB213PD:   return "vfmsub213pd";
    case Mnemonic::VFMSUB231PD:   return "vfmsub231pd";
    case Mnemonic::VFNMADD132PS:  return "vfnmadd132ps";
    case Mnemonic::VFNMADD213PS:  return "vfnmadd213ps";
    case Mnemonic::VFNMADD231PS:  return "vfnmadd231ps";
    case Mnemonic::VFNMADD132PD:  return "vfnmadd132pd";
    case Mnemonic::VFNMADD213PD:  return "vfnmadd213pd";
    case Mnemonic::VFNMADD231PD:  return "vfnmadd231pd";
    case Mnemonic::VZEROALL:      return "vzeroall";
    case Mnemonic::VZEROUPPER:    return "vzeroupper";

    // AES-NI
    case Mnemonic::AESENC:        return "aesenc";
    case Mnemonic::AESENCLAST:    return "aesenclast";
    case Mnemonic::AESDEC:        return "aesdec";
    case Mnemonic::AESDECLAST:    return "aesdeclast";
    case Mnemonic::AESIMC:        return "aesimc";
    case Mnemonic::AESKEYGENASSIST: return "aeskeygenassist";
    case Mnemonic::VAESENC:       return "vaesenc";
    case Mnemonic::VAESENCLAST:   return "vaesenclast";
    case Mnemonic::VAESDEC:       return "vaesdec";
    case Mnemonic::VAESDECLAST:   return "vaesdeclast";
    case Mnemonic::VAESIMC:       return "vaesimc";
    case Mnemonic::VAESKEYGENASSIST: return "vaeskeygenassist";
    case Mnemonic::PCLMULQDQ:     return "pclmulqdq";
    case Mnemonic::VPCLMULQDQ:    return "vpclmulqdq";

    // SHA
    case Mnemonic::SHA1RNDS4:     return "sha1rnds4";
    case Mnemonic::SHA1NEXTE:     return "sha1nexte";
    case Mnemonic::SHA1MSG1:      return "sha1msg1";
    case Mnemonic::SHA1MSG2:      return "sha1msg2";
    case Mnemonic::SHA256RNDS2:   return "sha256rnds2";
    case Mnemonic::SHA256MSG1:    return "sha256msg1";
    case Mnemonic::SHA256MSG2:    return "sha256msg2";

    // BMI1 / BMI2
    case Mnemonic::ANDN:          return "andn";
    case Mnemonic::BEXTR:         return "bextr";
    case Mnemonic::BLSI:          return "blsi";
    case Mnemonic::BLSMSK:        return "blsmsk";
    case Mnemonic::BLSR:          return "blsr";
    case Mnemonic::BZHI:          return "bzhi";
    case Mnemonic::MULX:          return "mulx";
    case Mnemonic::PDEP:          return "pdep";
    case Mnemonic::PEXT:          return "pext";
    case Mnemonic::RORX:          return "rorx";
    case Mnemonic::SARX:          return "sarx";
    case Mnemonic::SHLX:          return "shlx";
    case Mnemonic::SHRX:          return "shrx";

    // ADX
    case Mnemonic::ADCX:          return "adcx";
    case Mnemonic::ADOX:          return "adox";

    // x87 FPU
    case Mnemonic::FLD:           return "fld";
    case Mnemonic::FST:           return "fst";
    case Mnemonic::FSTP:          return "fstp";
    case Mnemonic::FILD:          return "fild";
    case Mnemonic::FIST:          return "fist";
    case Mnemonic::FISTP:         return "fistp";
    case Mnemonic::FLDZ:          return "fldz";
    case Mnemonic::FLD1:          return "fld1";
    case Mnemonic::FLDPI:         return "fldpi";
    case Mnemonic::FLDL2E:        return "fldl2e";
    case Mnemonic::FLDL2T:        return "fldl2t";
    case Mnemonic::FLDLN2:        return "fldln2";
    case Mnemonic::FLDLG2:        return "fldlg2";
    case Mnemonic::FADD:          return "fadd";
    case Mnemonic::FADDP:         return "faddp";
    case Mnemonic::FIADD:         return "fiadd";
    case Mnemonic::FSUB:          return "fsub";
    case Mnemonic::FSUBP:         return "fsubp";
    case Mnemonic::FISUB:         return "fisub";
    case Mnemonic::FSUBR:         return "fsubr";
    case Mnemonic::FSUBRP:        return "fsubrp";
    case Mnemonic::FISUBR:        return "fisubr";
    case Mnemonic::FMUL:          return "fmul";
    case Mnemonic::FMULP:         return "fmulp";
    case Mnemonic::FIMUL:         return "fimul";
    case Mnemonic::FDIV:          return "fdiv";
    case Mnemonic::FDIVP:         return "fdivp";
    case Mnemonic::FIDIV:         return "fidiv";
    case Mnemonic::FDIVR:         return "fdivr";
    case Mnemonic::FDIVRP:        return "fdivrp";
    case Mnemonic::FIDIVR:        return "fidivr";
    case Mnemonic::FCOM:          return "fcom";
    case Mnemonic::FCOMP:         return "fcomp";
    case Mnemonic::FCOMPP:        return "fcompp";
    case Mnemonic::FCOMI:         return "fcomi";
    case Mnemonic::FCOMIP:        return "fcomip";
    case Mnemonic::FUCOMI:        return "fucomi";
    case Mnemonic::FUCOMIP:       return "fucomip";
    case Mnemonic::FUCOM:         return "fucom";
    case Mnemonic::FUCOMP:        return "fucomp";
    case Mnemonic::FUCOMPP:       return "fucompp";
    case Mnemonic::FABS:          return "fabs";
    case Mnemonic::FCHS:          return "fchs";
    case Mnemonic::FSQRT:         return "fsqrt";
    case Mnemonic::FRNDINT:       return "frndint";
    case Mnemonic::FSCALE:        return "fscale";
    case Mnemonic::FPREM:         return "fprem";
    case Mnemonic::FPREM1:        return "fprem1";
    case Mnemonic::FXTRACT:       return "fxtract";
    case Mnemonic::FSIN:          return "fsin";
    case Mnemonic::FCOS:          return "fcos";
    case Mnemonic::FSINCOS:       return "fsincos";
    case Mnemonic::FPTAN:         return "fptan";
    case Mnemonic::FPATAN:        return "fpatan";
    case Mnemonic::F2XM1:         return "f2xm1";
    case Mnemonic::FYL2X:         return "fyl2x";
    case Mnemonic::FYL2XP1:       return "fyl2xp1";
    case Mnemonic::FXCH:          return "fxch";
    case Mnemonic::FFREE:         return "ffree";
    case Mnemonic::FINCSTP:       return "fincstp";
    case Mnemonic::FDECSTP:       return "fdecstp";
    case Mnemonic::FNOP:          return "fnop";
    case Mnemonic::FWAIT:         return "fwait";
    case Mnemonic::FINIT:         return "finit";
    case Mnemonic::FNINIT:        return "fninit";
    case Mnemonic::FCLEX:         return "fclex";
    case Mnemonic::FNCLEX:        return "fnclex";
    case Mnemonic::FLDCW:         return "fldcw";
    case Mnemonic::FNSTCW:        return "fnstcw";
    case Mnemonic::FSTCW:         return "fstcw";
    case Mnemonic::FNSTSW:        return "fnstsw";
    case Mnemonic::FSTSW:         return "fstsw";
    case Mnemonic::FLDENV:        return "fldenv";
    case Mnemonic::FNSTENV:       return "fnstenv";
    case Mnemonic::FSTENV:        return "fstenv";
    case Mnemonic::FRSTOR:        return "frstor";
    case Mnemonic::FNSAVE:        return "fnsave";
    case Mnemonic::FSAVE:         return "fsave";

    // AVX-512
    case Mnemonic::VMOVDQA32:     return "vmovdqa32";
    case Mnemonic::VMOVDQA64:     return "vmovdqa64";
    case Mnemonic::VMOVDQU8:      return "vmovdqu8";
    case Mnemonic::VMOVDQU16:     return "vmovdqu16";
    case Mnemonic::VMOVDQU32:     return "vmovdqu32";
    case Mnemonic::VMOVDQU64:     return "vmovdqu64";
    case Mnemonic::VADDPS_Z:      return "vaddps";
    case Mnemonic::VSUBPS_Z:      return "vsubps";
    case Mnemonic::VMULPS_Z:      return "vmulps";
    case Mnemonic::VDIVPS_Z:      return "vdivps";
    case Mnemonic::VPCOMPRESSD:   return "vpcompressd";
    case Mnemonic::VPCOMPRESSQ:   return "vpcompressq";
    case Mnemonic::VPEXPANDD:     return "vpexpandd";
    case Mnemonic::VPEXPANDQ:     return "vpexpandq";
    case Mnemonic::VPTESTMD:      return "vptestmd";
    case Mnemonic::VPTESTMQ:      return "vptestmq";
    case Mnemonic::VPTESTNMD:     return "vptestnmd";
    case Mnemonic::VPTESTNMQ:     return "vptestnmq";
    case Mnemonic::VPTERNLOGD:    return "vpternlogd";
    case Mnemonic::VPTERNLOGQ:    return "vpternlogq";
    case Mnemonic::VPMOVZXBD:     return "vpmovzxbd";
    case Mnemonic::VPMOVZXBW:     return "vpmovzxbw";
    case Mnemonic::VPMOVZXBQ:     return "vpmovzxbq";
    case Mnemonic::VPMOVZXWD:     return "vpmovzxwd";
    case Mnemonic::VPMOVZXWQ:     return "vpmovzxwq";
    case Mnemonic::VPMOVZXDQ:     return "vpmovzxdq";
    case Mnemonic::VPMOVSXBD:     return "vpmovsxbd";
    case Mnemonic::VPMOVSXBW:     return "vpmovsxbw";
    case Mnemonic::VPMOVSXBQ:     return "vpmovsxbq";
    case Mnemonic::VPMOVSXWD:     return "vpmovsxwd";
    case Mnemonic::VPMOVSXWQ:     return "vpmovsxwq";
    case Mnemonic::VPMOVSXDQ:     return "vpmovsxdq";
    case Mnemonic::VCVTPS2PH:     return "vcvtps2ph";
    case Mnemonic::VCVTPH2PS:     return "vcvtph2ps";
    case Mnemonic::VPCONFLICTD:   return "vpconflictd";
    case Mnemonic::VPCONFLICTQ:   return "vpconflictq";
    case Mnemonic::VPLZCNTD:      return "vplzcntd";
    case Mnemonic::VPLZCNTQ:      return "vplzcntq";
    case Mnemonic::VSCALEFPS:     return "vscalefps";
    case Mnemonic::VSCALEFPD:     return "vscalefpd";
    case Mnemonic::VSCALEFSS:     return "vscalefss";
    case Mnemonic::VSCALEFSD:     return "vscalefsd";
    case Mnemonic::VRCP14PS:      return "vrcp14ps";
    case Mnemonic::VRCP14PD:      return "vrcp14pd";
    case Mnemonic::VRCP14SS:      return "vrcp14ss";
    case Mnemonic::VRCP14SD:      return "vrcp14sd";
    case Mnemonic::VRSQRT14PS:    return "vrsqrt14ps";
    case Mnemonic::VRSQRT14PD:    return "vrsqrt14pd";
    case Mnemonic::VRSQRT14SS:    return "vrsqrt14ss";
    case Mnemonic::VRSQRT14SD:    return "vrsqrt14sd";
    case Mnemonic::VFIXUPIMMPS:   return "vfixupimmps";
    case Mnemonic::VFIXUPIMMPD:   return "vfixupimmpd";
    case Mnemonic::VFIXUPIMMSS:   return "vfixupimmss";
    case Mnemonic::VFIXUPIMMSD:   return "vfixupimmsd";
    case Mnemonic::VGETEXPPS:     return "vgetexpps";
    case Mnemonic::VGETEXPPD:     return "vgetexppd";
    case Mnemonic::VGETEXPSS:     return "vgetexpss";
    case Mnemonic::VGETEXPSD:     return "vgetexpsd";
    case Mnemonic::VGETMANTPS:    return "vgetmantps";
    case Mnemonic::VGETMANTPD:    return "vgetmantpd";
    case Mnemonic::VGETMANTSS:    return "vgetmantss";
    case Mnemonic::VGETMANTSD:    return "vgetmantsd";

    // --- Newly added mnemonics ---
    case Mnemonic::ADC:           return "adc";
    case Mnemonic::SBB:           return "sbb";
    case Mnemonic::SHLD:          return "shld";
    case Mnemonic::SHRD:          return "shrd";
    case Mnemonic::LAR:           return "lar";
    case Mnemonic::LSL:           return "lsl";
    case Mnemonic::VERR:          return "verr";
    case Mnemonic::VERW:          return "verw";
    case Mnemonic::FICOM:         return "ficom";
    case Mnemonic::FICOMP:        return "ficomp";
    case Mnemonic::EMMS:          return "emms";
    case Mnemonic::MASKMOVDQU:    return "maskmovdqu";
    case Mnemonic::MASKMOVQ:      return "maskmovq";
    case Mnemonic::MOVD_MMX:      return "movd";
    case Mnemonic::MOVQ_MMX:      return "movq";
    case Mnemonic::PAVGB:         return "pavgb";
    case Mnemonic::PAVGW:         return "pavgw";
    case Mnemonic::PSADBW:        return "psadbw";
    case Mnemonic::PMULHRSW:      return "pmulhrsw";
    case Mnemonic::PHMINPOSUW:    return "phminposuw";
    case Mnemonic::CVTPI2PS:      return "cvtpi2ps";
    case Mnemonic::CVTPI2PD:      return "cvtpi2pd";
    case Mnemonic::CVTPS2PI:      return "cvtps2pi";
    case Mnemonic::CVTPD2PI:      return "cvtpd2pi";
    case Mnemonic::CVTTPS2PI:     return "cvttps2pi";
    case Mnemonic::CVTTPD2PI:     return "cvttpd2pi";
    case Mnemonic::PMOVSXBW:      return "pmovsxbw";
    case Mnemonic::PMOVSXBD:      return "pmovsxbd";
    case Mnemonic::PMOVSXBQ:      return "pmovsxbq";
    case Mnemonic::PMOVSXWD:      return "pmovsxwd";
    case Mnemonic::PMOVSXWQ:      return "pmovsxwq";
    case Mnemonic::PMOVSXDQ:      return "pmovsxdq";
    case Mnemonic::PMOVZXBW:      return "pmovzxbw";
    case Mnemonic::PMOVZXBD:      return "pmovzxbd";
    case Mnemonic::PMOVZXBQ:      return "pmovzxbq";
    case Mnemonic::PMOVZXWD:      return "pmovzxwd";
    case Mnemonic::PMOVZXWQ:      return "pmovzxwq";
    case Mnemonic::PMOVZXDQ:      return "pmovzxdq";

    // --- New AVX/AVX2 arithmetic ---
    case Mnemonic::VSQRTPS:       return "vsqrtps";
    case Mnemonic::VSQRTPD:       return "vsqrtpd";
    case Mnemonic::VSQRTSS:       return "vsqrtss";
    case Mnemonic::VSQRTSD:       return "vsqrtsd";
    case Mnemonic::VRSQRTPS:      return "vrsqrtps";
    case Mnemonic::VRSQRTSS:      return "vrsqrtss";
    case Mnemonic::VRCPPS:        return "vrcpps";
    case Mnemonic::VRCPSS:        return "vrcpss";
    case Mnemonic::VMINPS:        return "vminps";
    case Mnemonic::VMINPD:        return "vminpd";
    case Mnemonic::VMINSS:        return "vminss";
    case Mnemonic::VMINSD:        return "vminsd";
    case Mnemonic::VMAXPS:        return "vmaxps";
    case Mnemonic::VMAXPD:        return "vmaxpd";
    case Mnemonic::VMAXSS:        return "vmaxss";
    case Mnemonic::VMAXSD:        return "vmaxsd";

    // --- New AVX logic ---
    case Mnemonic::VANDPS:        return "vandps";
    case Mnemonic::VANDPD:        return "vandpd";
    case Mnemonic::VANDNPS:       return "vandnps";
    case Mnemonic::VANDNPD:       return "vandnpd";
    case Mnemonic::VORPS:         return "vorps";
    case Mnemonic::VORPD:         return "vorpd";
    case Mnemonic::VXORPS:        return "vxorps";
    case Mnemonic::VXORPD:        return "vxorpd";

    // --- New AVX compare ---
    case Mnemonic::VCMPPS:        return "vcmpps";
    case Mnemonic::VCMPPD:        return "vcmppd";
    case Mnemonic::VCMPSS:        return "vcmpss";
    case Mnemonic::VCMPSD_CMP:    return "vcmpsd";
    case Mnemonic::VUCOMISS:      return "vucomiss";
    case Mnemonic::VUCOMISD:      return "vucomisd";
    case Mnemonic::VCOMISS:       return "vcomiss";
    case Mnemonic::VCOMISD:       return "vcomisd";

    // --- New AVX move ---
    case Mnemonic::VMOVLPS:       return "vmovlps";
    case Mnemonic::VMOVLPD:       return "vmovlpd";
    case Mnemonic::VMOVHPS:       return "vmovhps";
    case Mnemonic::VMOVHPD:       return "vmovhpd";
    case Mnemonic::VMOVHLPS:      return "vmovhlps";
    case Mnemonic::VMOVLHPS:      return "vmovlhps";
    case Mnemonic::VMOVSLDUP:     return "vmovsldup";
    case Mnemonic::VMOVSHDUP:     return "vmovshdup";
    case Mnemonic::VMOVDDUP:      return "vmovddup";
    case Mnemonic::VMOVNTPS:      return "vmovntps";
    case Mnemonic::VMOVNTPD:      return "vmovntpd";
    case Mnemonic::VMOVNTDQ:      return "vmovntdq";
    case Mnemonic::VMOVMSKPS:     return "vmovmskps";
    case Mnemonic::VMOVMSKPD:     return "vmovmskpd";

    // --- New AVX unpack ---
    case Mnemonic::VUNPCKLPS:     return "vunpcklps";
    case Mnemonic::VUNPCKHPS:     return "vunpckhps";
    case Mnemonic::VUNPCKLPD:     return "vunpcklpd";
    case Mnemonic::VUNPCKHPD:     return "vunpckhpd";
    case Mnemonic::VPSHUFHW:      return "vpshufhw";
    case Mnemonic::VPSHUFLW:      return "vpshuflw";

    // --- New AVX convert ---
    case Mnemonic::VCVTSI2SS:     return "vcvtsi2ss";
    case Mnemonic::VCVTSI2SD:     return "vcvtsi2sd";
    case Mnemonic::VCVTSS2SI:     return "vcvtss2si";
    case Mnemonic::VCVTSD2SI:     return "vcvtsd2si";
    case Mnemonic::VCVTTSS2SI:    return "vcvttss2si";
    case Mnemonic::VCVTTSD2SI:    return "vcvttsd2si";
    case Mnemonic::VCVTPS2PD:     return "vcvtps2pd";
    case Mnemonic::VCVTPD2PS:     return "vcvtpd2ps";
    case Mnemonic::VCVTSS2SD:     return "vcvtss2sd";
    case Mnemonic::VCVTSD2SS:     return "vcvtsd2ss";
    case Mnemonic::VCVTDQ2PS:     return "vcvtdq2ps";
    case Mnemonic::VCVTPS2DQ:     return "vcvtps2dq";
    case Mnemonic::VCVTDQ2PD:     return "vcvtdq2pd";
    case Mnemonic::VCVTPD2DQ:     return "vcvtpd2dq";
    case Mnemonic::VCVTTPS2DQ:    return "vcvttps2dq";
    case Mnemonic::VCVTTPD2DQ:    return "vcvttpd2dq";

    // --- New broadcast/permute ---
    case Mnemonic::VBROADCASTI128:return "vbroadcasti128";
    case Mnemonic::VPERMILPS:     return "vpermilps";
    case Mnemonic::VPERMILPD:     return "vpermilpd";

    // --- New integer arithmetic ---
    case Mnemonic::VPADDUSB:      return "vpaddusb";
    case Mnemonic::VPADDUSW:      return "vpaddusw";
    case Mnemonic::VPADDSB:       return "vpaddsb";
    case Mnemonic::VPADDSW:       return "vpaddsw";
    case Mnemonic::VPSUBUSB:      return "vpsubusb";
    case Mnemonic::VPSUBUSW:      return "vpsubusw";
    case Mnemonic::VPSUBSB:       return "vpsubsb";
    case Mnemonic::VPSUBSW:       return "vpsubsw";
    case Mnemonic::VPMULHW:       return "vpmulhw";
    case Mnemonic::VPMULHUW:      return "vpmulhuw";
    case Mnemonic::VPMULHRSW:     return "vpmulhrsw";
    case Mnemonic::VPMADDWD:      return "vpmaddwd";
    case Mnemonic::VPMADDUBSW:    return "vpmaddubsw";
    case Mnemonic::VPSADBW:       return "vpsadbw";
    case Mnemonic::VPAVGB:        return "vpavgb";
    case Mnemonic::VPAVGW:        return "vpavgw";

    // --- New integer pack/align ---
    case Mnemonic::VPACKSSWB:     return "vpacksswb";
    case Mnemonic::VPACKUSWB:     return "vpackuswb";
    case Mnemonic::VPACKSSDW:     return "vpackssdw";
    case Mnemonic::VPACKUSDW:     return "vpackusdw";
    case Mnemonic::VPALIGNR:      return "vpalignr";

    // --- New blend ---
    case Mnemonic::VBLENDVPS:     return "vblendvps";
    case Mnemonic::VBLENDVPD:     return "vblendvpd";
    case Mnemonic::VPINSRB:       return "vpinsrb";
    case Mnemonic::VPINSRD:       return "vpinsrd";
    case Mnemonic::VPINSRQ:       return "vpinsrq";
    case Mnemonic::VPEXTRB:       return "vpextrb";
    case Mnemonic::VPEXTRD:       return "vpextrd";
    case Mnemonic::VPEXTRQ:       return "vpextrq";
    case Mnemonic::VINSERTPS:     return "vinsertps";
    case Mnemonic::VEXTRACTPS:    return "vextractps";

    // --- New abs/sign/hadd ---
    case Mnemonic::VPABSB:        return "vpabsb";
    case Mnemonic::VPABSW:        return "vpabsw";
    case Mnemonic::VPABSD:        return "vpabsd";
    case Mnemonic::VPHADDW:       return "vphaddw";
    case Mnemonic::VPHADDD:       return "vphaddd";
    case Mnemonic::VPHADDSW:      return "vphaddsw";
    case Mnemonic::VPHSUBW:       return "vphsubw";
    case Mnemonic::VPHSUBD:       return "vphsubd";
    case Mnemonic::VPHSUBSW:      return "vphsubsw";
    case Mnemonic::VPSIGNB:       return "vpsignb";
    case Mnemonic::VPSIGNW:       return "vpsignw";
    case Mnemonic::VPSIGND:       return "vpsignd";
    case Mnemonic::VPHMINPOSUW:   return "vphminposuw";
    case Mnemonic::VPMOVMSKB:     return "vpmovmskb";

    // --- New SSE3 horizontal ---
    case Mnemonic::VHADDPS:       return "vhaddps";
    case Mnemonic::VHADDPD:       return "vhaddpd";
    case Mnemonic::VHSUBPS:       return "vhsubps";
    case Mnemonic::VHSUBPD:       return "vhsubpd";
    case Mnemonic::VADDSUBPS:     return "vaddsubps";
    case Mnemonic::VADDSUBPD:     return "vaddsubpd";
    case Mnemonic::VLDDQU:        return "vlddqu";

    // --- New SSE4 round/dp ---
    case Mnemonic::VROUNDPS:      return "vroundps";
    case Mnemonic::VROUNDPD:      return "vroundpd";
    case Mnemonic::VROUNDSS:      return "vroundss";
    case Mnemonic::VROUNDSD:      return "vroundsd";
    case Mnemonic::VDPPS:         return "vdpps";
    case Mnemonic::VDPPD:         return "vdppd";
    case Mnemonic::VMPSADBW:      return "vmpsadbw";

    // --- New SSE4.2 string ---
    case Mnemonic::VPCMPESTRM:    return "vpcmpestrm";
    case Mnemonic::VPCMPESTRI:    return "vpcmpestri";
    case Mnemonic::VPCMPISTRM:    return "vpcmpistrm";
    case Mnemonic::VPCMPISTRI:    return "vpcmpistri";

    // --- New mask move ---
    case Mnemonic::VMASKMOVPS:    return "vmaskmovps";
    case Mnemonic::VMASKMOVPD:    return "vmaskmovpd";
    case Mnemonic::VPMASKMOVD:    return "vpmaskmovd";
    case Mnemonic::VPMASKMOVQ:    return "vpmaskmovq";
    case Mnemonic::VLDMXCSR:      return "vldmxcsr";
    case Mnemonic::VSTMXCSR:      return "vstmxcsr";

    // --- FMA missing SS/SD variants ---
    case Mnemonic::VFMSUB132SS:   return "vfmsub132ss";
    case Mnemonic::VFMSUB213SS:   return "vfmsub213ss";
    case Mnemonic::VFMSUB231SS:   return "vfmsub231ss";
    case Mnemonic::VFMSUB132SD:   return "vfmsub132sd";
    case Mnemonic::VFMSUB213SD:   return "vfmsub213sd";
    case Mnemonic::VFMSUB231SD:   return "vfmsub231sd";
    case Mnemonic::VFNMADD132SS:  return "vfnmadd132ss";
    case Mnemonic::VFNMADD213SS:  return "vfnmadd213ss";
    case Mnemonic::VFNMADD231SS:  return "vfnmadd231ss";
    case Mnemonic::VFNMADD132SD:  return "vfnmadd132sd";
    case Mnemonic::VFNMADD213SD:  return "vfnmadd213sd";
    case Mnemonic::VFNMADD231SD:  return "vfnmadd231sd";
    case Mnemonic::VFNMSUB132PS:  return "vfnmsub132ps";
    case Mnemonic::VFNMSUB213PS:  return "vfnmsub213ps";
    case Mnemonic::VFNMSUB231PS:  return "vfnmsub231ps";
    case Mnemonic::VFNMSUB132PD:  return "vfnmsub132pd";
    case Mnemonic::VFNMSUB213PD:  return "vfnmsub213pd";
    case Mnemonic::VFNMSUB231PD:  return "vfnmsub231pd";
    case Mnemonic::VFNMSUB132SS:  return "vfnmsub132ss";
    case Mnemonic::VFNMSUB213SS:  return "vfnmsub213ss";
    case Mnemonic::VFNMSUB231SS:  return "vfnmsub231ss";
    case Mnemonic::VFNMSUB132SD:  return "vfnmsub132sd";
    case Mnemonic::VFNMSUB213SD:  return "vfnmsub213sd";
    case Mnemonic::VFNMSUB231SD:  return "vfnmsub231sd";

    // --- VMX / SVM virtualization ---
    case Mnemonic::VMCALL:        return "vmcall";
    case Mnemonic::VMLAUNCH:      return "vmlaunch";
    case Mnemonic::VMRESUME:      return "vmresume";
    case Mnemonic::VMXOFF:        return "vmxoff";
    case Mnemonic::VMREAD:        return "vmread";
    case Mnemonic::VMWRITE:       return "vmwrite";
    case Mnemonic::VMPTRLD:       return "vmptrld";
    case Mnemonic::VMPTRST:       return "vmptrst";
    case Mnemonic::VMCLEAR:       return "vmclear";
    case Mnemonic::VMXON:         return "vmxon";
    case Mnemonic::INVEPT:        return "invept";
    case Mnemonic::INVVPID:       return "invvpid";

    // --- MONITOR / MWAIT ---
    case Mnemonic::MONITOR_INST:  return "monitor";
    case Mnemonic::MWAIT_INST:    return "mwait";

    // --- AVX-512 additional ---
    case Mnemonic::VADDPD_Z:      return "vaddpd";
    case Mnemonic::VSUBPD_Z:      return "vsubpd";
    case Mnemonic::VMULPD_Z:      return "vmulpd";
    case Mnemonic::VDIVPD_Z:      return "vdivpd";
    case Mnemonic::VANDPS_Z:      return "vandps";
    case Mnemonic::VANDPD_Z:      return "vandpd";
    case Mnemonic::VORPS_Z:       return "vorps";
    case Mnemonic::VORPD_Z:       return "vorpd";
    case Mnemonic::VXORPS_Z:      return "vxorps";
    case Mnemonic::VXORPD_Z:      return "vxorpd";
    case Mnemonic::VPCMPB:        return "vpcmpb";
    case Mnemonic::VPCMPW:        return "vpcmpw";
    case Mnemonic::VPCMPD:        return "vpcmpd";
    case Mnemonic::VPCMPQ:        return "vpcmpq";
    case Mnemonic::VPCMPUB:       return "vpcmpub";
    case Mnemonic::VPCMPUW:       return "vpcmpuw";
    case Mnemonic::VPCMPUD:       return "vpcmpud";
    case Mnemonic::VPCMPUQ:       return "vpcmpuq";
    case Mnemonic::VPBROADCASTB:  return "vpbroadcastb";
    case Mnemonic::VPBROADCASTW:  return "vpbroadcastw";
    case Mnemonic::VPBROADCASTD:  return "vpbroadcastd";
    case Mnemonic::VPBROADCASTQ:  return "vpbroadcastq";
    case Mnemonic::VSCATTERDPS:   return "vscatterdps";
    case Mnemonic::VSCATTERDPD:   return "vscatterdpd";
    case Mnemonic::VSCATTERQPS:   return "vscatterqps";
    case Mnemonic::VSCATTERQPD:   return "vscatterqpd";
    case Mnemonic::VPSCATTERDD:   return "vpscatterdd";
    case Mnemonic::VPSCATTERDQ:   return "vpscatterdq";
    case Mnemonic::VPSCATTERQD:   return "vpscatterqd";
    case Mnemonic::VPSCATTERQQ:   return "vpscatterqq";
    case Mnemonic::VPROLD:        return "vprold";
    case Mnemonic::VPROLQ:        return "vprolq";
    case Mnemonic::VPRORD:        return "vprord";
    case Mnemonic::VPRORQ:        return "vprorq";
    case Mnemonic::VPROLVD:       return "vprolvd";
    case Mnemonic::VPROLVQ:       return "vprolvq";
    case Mnemonic::VPRORVD:       return "vprorvd";
    case Mnemonic::VPRORVQ:       return "vprorvq";
    case Mnemonic::VPANDD:        return "vpandd";
    case Mnemonic::VPANDQ:        return "vpandq";
    case Mnemonic::VPANDND:       return "vpandnd";
    case Mnemonic::VPANDNQ:       return "vpandnq";
    case Mnemonic::VPORD:         return "vpord";
    case Mnemonic::VPORQ:         return "vporq";
    case Mnemonic::VPXORD:        return "vpxord";
    case Mnemonic::VPXORQ:        return "vpxorq";
    case Mnemonic::VCVTUDQ2PS:    return "vcvtudq2ps";
    case Mnemonic::VCVTUDQ2PD:    return "vcvtudq2pd";
    case Mnemonic::VCVTPS2UDQ:    return "vcvtps2udq";
    case Mnemonic::VCVTPD2UDQ:    return "vcvtpd2udq";
    case Mnemonic::VCVTTPS2UDQ:   return "vcvttps2udq";
    case Mnemonic::VCVTTPD2UDQ:   return "vcvttpd2udq";
    case Mnemonic::VCVTUSI2SS:    return "vcvtusi2ss";
    case Mnemonic::VCVTUSI2SD:    return "vcvtusi2sd";
    case Mnemonic::VCVTSS2USI:    return "vcvtss2usi";
    case Mnemonic::VCVTSD2USI:    return "vcvtsd2usi";
    case Mnemonic::VCVTTSS2USI:   return "vcvttss2usi";
    case Mnemonic::VCVTTSD2USI:   return "vcvttsd2usi";
    case Mnemonic::VPMOVB2M:      return "vpmovb2m";
    case Mnemonic::VPMOVW2M:      return "vpmovw2m";
    case Mnemonic::VPMOVD2M:      return "vpmovd2m";
    case Mnemonic::VPMOVQ2M:      return "vpmovq2m";
    case Mnemonic::VPMOVM2B:      return "vpmovm2b";
    case Mnemonic::VPMOVM2W:      return "vpmovm2w";
    case Mnemonic::VPMOVM2D:      return "vpmovm2d";
    case Mnemonic::VPMOVM2Q:      return "vpmovm2q";
    case Mnemonic::VPMOVDB:       return "vpmovdb";
    case Mnemonic::VPMOVDW:       return "vpmovdw";
    case Mnemonic::VPMOVQB:       return "vpmovqb";
    case Mnemonic::VPMOVQD:       return "vpmovqd";
    case Mnemonic::VPMOVQW:       return "vpmovqw";
    case Mnemonic::VPMOVWB:       return "vpmovwb";
    case Mnemonic::VPMOVSDB:      return "vpmovsdb";
    case Mnemonic::VPMOVSDW:      return "vpmovsdw";
    case Mnemonic::VPMOVSQB:      return "vpmovsqb";
    case Mnemonic::VPMOVSQD:      return "vpmovsqd";
    case Mnemonic::VPMOVSQW:      return "vpmovsqw";
    case Mnemonic::VPMOVSWB:      return "vpmovswb";
    case Mnemonic::VPMOVUSDB:     return "vpmovusdb";
    case Mnemonic::VPMOVUSDW:    return "vpmovusdw";
    case Mnemonic::VPMOVUSQB:     return "vpmovusqb";
    case Mnemonic::VPMOVUSQD:     return "vpmovusqd";
    case Mnemonic::VPMOVUSQW:     return "vpmovusqw";
    case Mnemonic::VPMOVUSWB:    return "vpmovuswb";
    case Mnemonic::VRANGEPS:      return "vrangeps";
    case Mnemonic::VRANGEPD:      return "vrangepd";
    case Mnemonic::VRANGESS:      return "vrangess";
    case Mnemonic::VRANGESD:      return "vrangesd";
    case Mnemonic::VREDUCEPS:     return "vreduceps";
    case Mnemonic::VREDUCEPD:     return "vreducepd";
    case Mnemonic::VREDUCESS:     return "vreducess";
    case Mnemonic::VREDUCESD:     return "vreducesd";
    case Mnemonic::VDBPSADBW:     return "vdbpsadbw";

    // AVX-512 VNNI
    case Mnemonic::VPDPBUSD:      return "vpdpbusd";
    case Mnemonic::VPDPBUSDS:     return "vpdpbusds";
    case Mnemonic::VPDPWSSD:      return "vpdpwssd";
    case Mnemonic::VPDPWSSDS:     return "vpdpwssds";

    // AVX-512 VBMI
    case Mnemonic::VPERMB:        return "vpermb";
    case Mnemonic::VPERMI2B:      return "vpermi2b";
    case Mnemonic::VPERMI2W:      return "vpermi2w";
    case Mnemonic::VPERMI2D:      return "vpermi2d";
    case Mnemonic::VPERMI2Q:      return "vpermi2q";
    case Mnemonic::VPERMT2B:      return "vpermt2b";
    case Mnemonic::VPERMT2W:      return "vpermt2w";
    case Mnemonic::VPERMT2D:      return "vpermt2d";
    case Mnemonic::VPERMT2Q:      return "vpermt2q";

    // AVX-512 IFMA
    case Mnemonic::VPMADD52LUQ:   return "vpmadd52luq";
    case Mnemonic::VPMADD52HUQ:   return "vpmadd52huq";

    // AVX-512 BITALG
    case Mnemonic::VPSHUFBITQMB:  return "vpshufbitqmb";
    case Mnemonic::VPOPCNTB:      return "vpopcntb";
    case Mnemonic::VPOPCNTW:      return "vpopcntw";

    // AVX-512DQ additional
    case Mnemonic::VFPCLASSPS:    return "vfpclassps";
    case Mnemonic::VFPCLASSPD:    return "vfpclasspd";
    case Mnemonic::VFPCLASSSS:    return "vfpclassss";
    case Mnemonic::VFPCLASSSD:    return "vfpclasssd";
    case Mnemonic::VCVTQQ2PS:     return "vcvtqq2ps";
    case Mnemonic::VCVTQQ2PD:     return "vcvtqq2pd";
    case Mnemonic::VCVTTPD2QQ:    return "vcvttpd2qq";
    case Mnemonic::VCVTTPD2UQQ:   return "vcvttpd2uqq";
    case Mnemonic::VCVTPD2QQ:     return "vcvtpd2qq";
    case Mnemonic::VCVTPD2UQQ:    return "vcvtpd2uqq";
    case Mnemonic::VCVTUQQ2PS:    return "vcvtuqq2ps";
    case Mnemonic::VCVTUQQ2PD:    return "vcvtuqq2pd";
    case Mnemonic::VPMULLQ:       return "vpmullq";
    case Mnemonic::VEXTRACTF64X2: return "vextractf64x2";
    case Mnemonic::VEXTRACTI64X2: return "vextracti64x2";
    case Mnemonic::VINSERTF64X2:  return "vinsertf64x2";
    case Mnemonic::VINSERTI64X2:  return "vinserti64x2";

    // SHA-512
    case Mnemonic::SHA512RNDS2:   return "sha512rnds2";
    case Mnemonic::SHA512MSG1:    return "sha512msg1";
    case Mnemonic::SHA512MSG2:    return "sha512msg2";

    // GFNI
    case Mnemonic::GF2P8AFFINEINVQB:  return "gf2p8affineinvqb";
    case Mnemonic::GF2P8AFFINEQB:     return "gf2p8affineqb";
    case Mnemonic::GF2P8MULB:         return "gf2p8mulb";
    case Mnemonic::VGF2P8AFFINEINVQB: return "vgf2p8affineinvqb";
    case Mnemonic::VGF2P8AFFINEQB:    return "vgf2p8affineqb";
    case Mnemonic::VGF2P8MULB:        return "vgf2p8mulb";

    // CMPCCXADD
    case Mnemonic::CMPccXADD:     return "cmpccxadd";

    // SM3
    case Mnemonic::VSM3MSG1:      return "vsm3msg1";
    case Mnemonic::VSM3MSG2:      return "vsm3msg2";
    case Mnemonic::VSM3RNDS2:     return "vsm3rnds2";

    // SM4
    case Mnemonic::VSM4KEY4:      return "vsm4key4";
    case Mnemonic::VSM4RNDS4:     return "vsm4rnds4";

    // Misc modern
    case Mnemonic::SERIALIZE:     return "serialize";
    case Mnemonic::PREFETCHIT0:   return "prefetchit0";
    case Mnemonic::PREFETCHIT1:   return "prefetchit1";
    case Mnemonic::CLDEMOTE:      return "cldemote";
    case Mnemonic::UMONITOR:      return "umonitor";
    case Mnemonic::UMWAIT:        return "umwait";
    case Mnemonic::TPAUSE:        return "tpause";
    case Mnemonic::ENQCMD:        return "enqcmd";
    case Mnemonic::ENQCMDS:       return "enqcmds";
    case Mnemonic::MOVDIRI:       return "movdiri";
    case Mnemonic::MOVDIR64B:     return "movdir64b";

    case Mnemonic::UNKNOWN:       return "unknown";
    case Mnemonic::MAX_MNEMONIC:  return "<max_mnemonic>";
    }
    return "unknown";
}

// ============================================================================
// Section 3 – Register
// ============================================================================

enum class Register : uint16_t {
    NONE = 0,

    // 64-bit GPR
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,

    // 32-bit GPR
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,

    // 16-bit GPR
    AX, CX, DX, BX, SP, BP, SI, DI,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,

    // 8-bit GPR (low)
    AL, CL, DL, BL,
    // 8-bit GPR (high – legacy)
    AH, CH, DH, BH,
    // 8-bit GPR (REX-accessible)
    SPL, BPL, SIL, DIL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,

    // Segment registers
    ES, CS, SS, DS, FS, GS,

    // Control registers
    CR0, CR1, CR2, CR3, CR4, CR5, CR6, CR7,
    CR8, CR9, CR10, CR11, CR12, CR13, CR14, CR15,

    // Debug registers
    DR0, DR1, DR2, DR3, DR4, DR5, DR6, DR7,

    // x87 FPU stack
    ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7,

    // SSE (128-bit)
    XMM0,  XMM1,  XMM2,  XMM3,  XMM4,  XMM5,  XMM6,  XMM7,
    XMM8,  XMM9,  XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
    XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23,
    XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,

    // AVX (256-bit)
    YMM0,  YMM1,  YMM2,  YMM3,  YMM4,  YMM5,  YMM6,  YMM7,
    YMM8,  YMM9,  YMM10, YMM11, YMM12, YMM13, YMM14, YMM15,
    YMM16, YMM17, YMM18, YMM19, YMM20, YMM21, YMM22, YMM23,
    YMM24, YMM25, YMM26, YMM27, YMM28, YMM29, YMM30, YMM31,

    // AVX-512 (512-bit)
    ZMM0,  ZMM1,  ZMM2,  ZMM3,  ZMM4,  ZMM5,  ZMM6,  ZMM7,
    ZMM8,  ZMM9,  ZMM10, ZMM11, ZMM12, ZMM13, ZMM14, ZMM15,
    ZMM16, ZMM17, ZMM18, ZMM19, ZMM20, ZMM21, ZMM22, ZMM23,
    ZMM24, ZMM25, ZMM26, ZMM27, ZMM28, ZMM29, ZMM30, ZMM31,

    // AVX-512 opmask registers
    K0, K1, K2, K3, K4, K5, K6, K7,

    // Special-purpose
    RIP,
    RFLAGS,
    MXCSR,

    MAX_REGISTER,
};

[[nodiscard]] inline constexpr std::string_view RegisterToString(Register r) noexcept {
    switch (r) {
    case Register::NONE:    return "none";
    case Register::RAX:     return "rax";
    case Register::RCX:     return "rcx";
    case Register::RDX:     return "rdx";
    case Register::RBX:     return "rbx";
    case Register::RSP:     return "rsp";
    case Register::RBP:     return "rbp";
    case Register::RSI:     return "rsi";
    case Register::RDI:     return "rdi";
    case Register::R8:      return "r8";
    case Register::R9:      return "r9";
    case Register::R10:     return "r10";
    case Register::R11:     return "r11";
    case Register::R12:     return "r12";
    case Register::R13:     return "r13";
    case Register::R14:     return "r14";
    case Register::R15:     return "r15";
    case Register::EAX:     return "eax";
    case Register::ECX:     return "ecx";
    case Register::EDX:     return "edx";
    case Register::EBX:     return "ebx";
    case Register::ESP:     return "esp";
    case Register::EBP:     return "ebp";
    case Register::ESI:     return "esi";
    case Register::EDI:     return "edi";
    case Register::R8D:     return "r8d";
    case Register::R9D:     return "r9d";
    case Register::R10D:    return "r10d";
    case Register::R11D:    return "r11d";
    case Register::R12D:    return "r12d";
    case Register::R13D:    return "r13d";
    case Register::R14D:    return "r14d";
    case Register::R15D:    return "r15d";
    case Register::AX:      return "ax";
    case Register::CX:      return "cx";
    case Register::DX:      return "dx";
    case Register::BX:      return "bx";
    case Register::SP:      return "sp";
    case Register::BP:      return "bp";
    case Register::SI:      return "si";
    case Register::DI:      return "di";
    case Register::R8W:     return "r8w";
    case Register::R9W:     return "r9w";
    case Register::R10W:    return "r10w";
    case Register::R11W:    return "r11w";
    case Register::R12W:    return "r12w";
    case Register::R13W:    return "r13w";
    case Register::R14W:    return "r14w";
    case Register::R15W:    return "r15w";
    case Register::AL:      return "al";
    case Register::CL:      return "cl";
    case Register::DL:      return "dl";
    case Register::BL:      return "bl";
    case Register::AH:      return "ah";
    case Register::CH:      return "ch";
    case Register::DH:      return "dh";
    case Register::BH:      return "bh";
    case Register::SPL:     return "spl";
    case Register::BPL:     return "bpl";
    case Register::SIL:     return "sil";
    case Register::DIL:     return "dil";
    case Register::R8B:     return "r8b";
    case Register::R9B:     return "r9b";
    case Register::R10B:    return "r10b";
    case Register::R11B:    return "r11b";
    case Register::R12B:    return "r12b";
    case Register::R13B:    return "r13b";
    case Register::R14B:    return "r14b";
    case Register::R15B:    return "r15b";
    case Register::ES:      return "es";
    case Register::CS:      return "cs";
    case Register::SS:      return "ss";
    case Register::DS:      return "ds";
    case Register::FS:      return "fs";
    case Register::GS:      return "gs";
    case Register::CR0:     return "cr0";
    case Register::CR1:     return "cr1";
    case Register::CR2:     return "cr2";
    case Register::CR3:     return "cr3";
    case Register::CR4:     return "cr4";
    case Register::CR5:     return "cr5";
    case Register::CR6:     return "cr6";
    case Register::CR7:     return "cr7";
    case Register::CR8:     return "cr8";
    case Register::CR9:     return "cr9";
    case Register::CR10:    return "cr10";
    case Register::CR11:    return "cr11";
    case Register::CR12:    return "cr12";
    case Register::CR13:    return "cr13";
    case Register::CR14:    return "cr14";
    case Register::CR15:    return "cr15";
    case Register::DR0:     return "dr0";
    case Register::DR1:     return "dr1";
    case Register::DR2:     return "dr2";
    case Register::DR3:     return "dr3";
    case Register::DR4:     return "dr4";
    case Register::DR5:     return "dr5";
    case Register::DR6:     return "dr6";
    case Register::DR7:     return "dr7";
    case Register::ST0:     return "st0";
    case Register::ST1:     return "st1";
    case Register::ST2:     return "st2";
    case Register::ST3:     return "st3";
    case Register::ST4:     return "st4";
    case Register::ST5:     return "st5";
    case Register::ST6:     return "st6";
    case Register::ST7:     return "st7";
    case Register::XMM0:    return "xmm0";
    case Register::XMM1:    return "xmm1";
    case Register::XMM2:    return "xmm2";
    case Register::XMM3:    return "xmm3";
    case Register::XMM4:    return "xmm4";
    case Register::XMM5:    return "xmm5";
    case Register::XMM6:    return "xmm6";
    case Register::XMM7:    return "xmm7";
    case Register::XMM8:    return "xmm8";
    case Register::XMM9:    return "xmm9";
    case Register::XMM10:   return "xmm10";
    case Register::XMM11:   return "xmm11";
    case Register::XMM12:   return "xmm12";
    case Register::XMM13:   return "xmm13";
    case Register::XMM14:   return "xmm14";
    case Register::XMM15:   return "xmm15";
    case Register::XMM16:   return "xmm16";
    case Register::XMM17:   return "xmm17";
    case Register::XMM18:   return "xmm18";
    case Register::XMM19:   return "xmm19";
    case Register::XMM20:   return "xmm20";
    case Register::XMM21:   return "xmm21";
    case Register::XMM22:   return "xmm22";
    case Register::XMM23:   return "xmm23";
    case Register::XMM24:   return "xmm24";
    case Register::XMM25:   return "xmm25";
    case Register::XMM26:   return "xmm26";
    case Register::XMM27:   return "xmm27";
    case Register::XMM28:   return "xmm28";
    case Register::XMM29:   return "xmm29";
    case Register::XMM30:   return "xmm30";
    case Register::XMM31:   return "xmm31";
    case Register::YMM0:    return "ymm0";
    case Register::YMM1:    return "ymm1";
    case Register::YMM2:    return "ymm2";
    case Register::YMM3:    return "ymm3";
    case Register::YMM4:    return "ymm4";
    case Register::YMM5:    return "ymm5";
    case Register::YMM6:    return "ymm6";
    case Register::YMM7:    return "ymm7";
    case Register::YMM8:    return "ymm8";
    case Register::YMM9:    return "ymm9";
    case Register::YMM10:   return "ymm10";
    case Register::YMM11:   return "ymm11";
    case Register::YMM12:   return "ymm12";
    case Register::YMM13:   return "ymm13";
    case Register::YMM14:   return "ymm14";
    case Register::YMM15:   return "ymm15";
    case Register::YMM16:   return "ymm16";
    case Register::YMM17:   return "ymm17";
    case Register::YMM18:   return "ymm18";
    case Register::YMM19:   return "ymm19";
    case Register::YMM20:   return "ymm20";
    case Register::YMM21:   return "ymm21";
    case Register::YMM22:   return "ymm22";
    case Register::YMM23:   return "ymm23";
    case Register::YMM24:   return "ymm24";
    case Register::YMM25:   return "ymm25";
    case Register::YMM26:   return "ymm26";
    case Register::YMM27:   return "ymm27";
    case Register::YMM28:   return "ymm28";
    case Register::YMM29:   return "ymm29";
    case Register::YMM30:   return "ymm30";
    case Register::YMM31:   return "ymm31";
    case Register::ZMM0:    return "zmm0";
    case Register::ZMM1:    return "zmm1";
    case Register::ZMM2:    return "zmm2";
    case Register::ZMM3:    return "zmm3";
    case Register::ZMM4:    return "zmm4";
    case Register::ZMM5:    return "zmm5";
    case Register::ZMM6:    return "zmm6";
    case Register::ZMM7:    return "zmm7";
    case Register::ZMM8:    return "zmm8";
    case Register::ZMM9:    return "zmm9";
    case Register::ZMM10:   return "zmm10";
    case Register::ZMM11:   return "zmm11";
    case Register::ZMM12:   return "zmm12";
    case Register::ZMM13:   return "zmm13";
    case Register::ZMM14:   return "zmm14";
    case Register::ZMM15:   return "zmm15";
    case Register::ZMM16:   return "zmm16";
    case Register::ZMM17:   return "zmm17";
    case Register::ZMM18:   return "zmm18";
    case Register::ZMM19:   return "zmm19";
    case Register::ZMM20:   return "zmm20";
    case Register::ZMM21:   return "zmm21";
    case Register::ZMM22:   return "zmm22";
    case Register::ZMM23:   return "zmm23";
    case Register::ZMM24:   return "zmm24";
    case Register::ZMM25:   return "zmm25";
    case Register::ZMM26:   return "zmm26";
    case Register::ZMM27:   return "zmm27";
    case Register::ZMM28:   return "zmm28";
    case Register::ZMM29:   return "zmm29";
    case Register::ZMM30:   return "zmm30";
    case Register::ZMM31:   return "zmm31";
    case Register::K0:      return "k0";
    case Register::K1:      return "k1";
    case Register::K2:      return "k2";
    case Register::K3:      return "k3";
    case Register::K4:      return "k4";
    case Register::K5:      return "k5";
    case Register::K6:      return "k6";
    case Register::K7:      return "k7";
    case Register::RIP:     return "rip";
    case Register::RFLAGS:  return "rflags";
    case Register::MXCSR:   return "mxcsr";
    case Register::MAX_REGISTER: return "<max_register>";
    }
    return "unknown";
}

// ============================================================================
// Section 4 – Operand Type
// ============================================================================

enum class OperandType : uint8_t {
    NONE            = 0,
    REGISTER        = 1,
    MEMORY          = 2,
    IMMEDIATE       = 3,
    RELATIVE_OFFSET = 4,   ///< RIP-relative / branch-relative (renamed from RELATIVE to avoid Windows SDK macro clash)
    POINTER         = 5,   ///< Far pointer (ptr16:16/ptr16:32)
    FAR_PTR         = 5,   ///< Alias for POINTER (Zydis compat)
};

// ============================================================================
// Section 5 – Operand Width & CPU Flags
// ============================================================================

enum class OperandWidth : uint16_t {
    W0   = 0,
    W8   = 8,
    W16  = 16,
    W32  = 32,
    W64  = 64,
    W80  = 80,    // x87 extended precision
    W128 = 128,
    W256 = 256,
    W512 = 512,
};

// RFLAGS bit positions (Intel SDM Vol. 1, §3.4.3)
inline namespace CpuFlags {
    constexpr uint32_t FLAG_CF    = 1u << 0;   // Carry
    constexpr uint32_t FLAG_PF    = 1u << 2;   // Parity
    constexpr uint32_t FLAG_AF    = 1u << 4;   // Auxiliary carry
    constexpr uint32_t FLAG_ZF    = 1u << 6;   // Zero
    constexpr uint32_t FLAG_SF    = 1u << 7;   // Sign
    constexpr uint32_t FLAG_TF    = 1u << 8;   // Trap
    constexpr uint32_t FLAG_IF    = 1u << 9;   // Interrupt enable
    constexpr uint32_t FLAG_DF    = 1u << 10;  // Direction
    constexpr uint32_t FLAG_OF    = 1u << 11;  // Overflow
    constexpr uint32_t FLAG_IOPL  = 3u << 12;  // I/O privilege level (2 bits)
    constexpr uint32_t FLAG_NT    = 1u << 14;  // Nested task
    constexpr uint32_t FLAG_RF    = 1u << 16;  // Resume
    constexpr uint32_t FLAG_VM    = 1u << 17;  // Virtual-8086 mode
    constexpr uint32_t FLAG_AC    = 1u << 18;  // Alignment check / SMAP
    constexpr uint32_t FLAG_VIF   = 1u << 19;  // Virtual interrupt
    constexpr uint32_t FLAG_VIP   = 1u << 20;  // Virtual interrupt pending
    constexpr uint32_t FLAG_ID    = 1u << 21;  // CPUID available
} // namespace CpuFlags

// ============================================================================
// Section 6 – Instruction Attributes (bitfield)
// ============================================================================

inline namespace InstructionAttribs {
    constexpr uint64_t ATTRIB_HAS_LOCK              = 1ull << 0;
    constexpr uint64_t ATTRIB_HAS_REP               = 1ull << 1;
    constexpr uint64_t ATTRIB_HAS_REPNE             = 1ull << 2;
    constexpr uint64_t ATTRIB_HAS_REPE              = 1ull << 3;
    constexpr uint64_t ATTRIB_HAS_SEGMENT_OVERRIDE  = 1ull << 4;
    constexpr uint64_t ATTRIB_HAS_OPERAND_SIZE      = 1ull << 5;
    constexpr uint64_t ATTRIB_HAS_ADDRESS_SIZE      = 1ull << 6;
    constexpr uint64_t ATTRIB_HAS_REX               = 1ull << 7;
    constexpr uint64_t ATTRIB_HAS_VEX               = 1ull << 8;
    constexpr uint64_t ATTRIB_HAS_EVEX              = 1ull << 9;
    constexpr uint64_t ATTRIB_IS_RELATIVE           = 1ull << 10;
    constexpr uint64_t ATTRIB_IS_PRIVILEGED         = 1ull << 11;
    constexpr uint64_t ATTRIB_HAS_MODRM             = 1ull << 12;
    constexpr uint64_t ATTRIB_HAS_SIB               = 1ull << 13;
    constexpr uint64_t ATTRIB_HAS_BRANCH_TAKEN      = 1ull << 14;
    constexpr uint64_t ATTRIB_HAS_BRANCH_NOT_TAKEN  = 1ull << 15;
    constexpr uint64_t ATTRIB_IS_FAR_BRANCH         = 1ull << 16;
    constexpr uint64_t ATTRIB_HAS_REX2              = 1ull << 17;
} // namespace InstructionAttribs

// ============================================================================
// Section 6b – Operand Visibility & Action Flags
// ============================================================================

enum class OperandVisibility : uint8_t {
    INVALID  = 0,
    EXPLICIT = 1,   ///< Operand is explicitly encoded in the instruction
    IMPLICIT = 2,   ///< Operand is implicit (e.g., RAX in MUL)
    HIDDEN   = 3,   ///< Operand is hidden (e.g., RFLAGS modification)
};

inline namespace OperandActions {
    constexpr uint8_t OPERAND_ACTION_NONE      = 0;
    constexpr uint8_t OPERAND_ACTION_READ      = 1u << 0;
    constexpr uint8_t OPERAND_ACTION_WRITE     = 1u << 1;
    constexpr uint8_t OPERAND_ACTION_CONDREAD  = 1u << 2;
    constexpr uint8_t OPERAND_ACTION_CONDWRITE = 1u << 3;
    constexpr uint8_t OPERAND_ACTION_READWRITE = OPERAND_ACTION_READ | OPERAND_ACTION_WRITE;
} // namespace OperandActions

// ============================================================================
// Section 7 – Instruction Category
// ============================================================================

enum class InstructionCategory : uint8_t {
    UNKNOWN = 0,
    ARITHMETIC,
    LOGIC,
    DATA_TRANSFER,
    CONTROL_FLOW,
    STACK,
    STRING,
    FLAG,
    SYSTEM,
    FPU,
    SSE,
    AVX,
    AVX512,
    AES,
    SHA,
    BMI,
    IO,
    NOP,
    INTERRUPT,
    SYNCHRONIZATION,
    SEGMENT,
    BRANCH,
    CONDITIONAL,
    CRYPTO,
    GATHER_SCATTER,
    SHIFT_ROTATE,
    BINARY,
    CONVERT,
    CALL,
    RET,
    PUSH,
    POP,
    SYSCALL,
};

// ============================================================================
// Section 8 – ISA Extension
// ============================================================================

enum class ISAExtension : uint8_t {
    BASE = 0,
    SSE,
    SSE2,
    SSE3,
    SSSE3,
    SSE4_1,
    SSE4_2,
    AVX,
    AVX2,
    AVX512F,
    AVX512BW,
    AVX512DQ,
    AVX512VL,
    AVX512CD,
    AVX512VBMI,
    AVX512VNNI,
    FMA,
    AES_NI,
    SHA_EXT,
    BMI1,
    BMI2,
    ADX,
    CLMUL,
    F16C,
    FPU,
    RDRAND,
    RDSEED,
    MOVBE_EXT,
    POPCNT_EXT,
    LZCNT_EXT,
    TSX,
    MPX,
    CET,
    AMX,
    VAES,
    GFNI,
    SHA512,
    SM3,
    SM4,
    AVX512IFMA,
    AVX512BITALG,
    CMPCCXADD,
    APX,
    SERIALIZE_EXT,
    CLDEMOTE_EXT,
    WAITPKG,
    CLWB_EXT,
    ENQCMD_EXT,
    MOVDIRI_EXT,
    MOVDIR64B_EXT,
    PREFETCHI,
};

// ============================================================================
// Convenience helpers
// ============================================================================

/// True if the mnemonic represents any conditional jump (Jcc).
[[nodiscard]] inline constexpr bool IsConditionalJump(Mnemonic m) noexcept {
    switch (m) {
    case Mnemonic::JZ:   case Mnemonic::JNZ:  case Mnemonic::JO:   case Mnemonic::JNO:
    case Mnemonic::JP:   case Mnemonic::JNP:  case Mnemonic::JS:   case Mnemonic::JNS:
    case Mnemonic::JB:   case Mnemonic::JBE:  case Mnemonic::JL:   case Mnemonic::JLE:
    case Mnemonic::JNB:  case Mnemonic::JNBE: case Mnemonic::JNL:  case Mnemonic::JNLE:
    case Mnemonic::JCXZ: case Mnemonic::JECXZ: case Mnemonic::JRCXZ:
        return true;
    default:
        return false;
    }
}

/// True if the mnemonic is any form of return.
[[nodiscard]] inline constexpr bool IsReturn(Mnemonic m) noexcept {
    return m == Mnemonic::RET || m == Mnemonic::RETF ||
           m == Mnemonic::IRET || m == Mnemonic::IRETD || m == Mnemonic::IRETQ;
}

/// True if the mnemonic is a call instruction.
[[nodiscard]] inline constexpr bool IsCall(Mnemonic m) noexcept {
    return m == Mnemonic::CALL || m == Mnemonic::SYSCALL || m == Mnemonic::SYSENTER;
}

/// True if the mnemonic transfers control flow (jump, call, return, interrupt).
[[nodiscard]] inline constexpr bool IsControlFlow(Mnemonic m) noexcept {
    return IsConditionalJump(m) || IsReturn(m) || IsCall(m) ||
           m == Mnemonic::JMP || m == Mnemonic::INT || m == Mnemonic::INT1 ||
           m == Mnemonic::INT3 || m == Mnemonic::INTO ||
           m == Mnemonic::LOOP || m == Mnemonic::LOOPE || m == Mnemonic::LOOPNE;
}

/// True if the mnemonic is a privileged (ring-0) instruction.
[[nodiscard]] inline constexpr bool IsPrivileged(Mnemonic m) noexcept {
    switch (m) {
    case Mnemonic::LGDT:  case Mnemonic::LIDT:  case Mnemonic::LLDT:
    case Mnemonic::LTR:   case Mnemonic::LMSW:  case Mnemonic::CLTS:
    case Mnemonic::INVD:  case Mnemonic::WBINVD: case Mnemonic::INVLPG:
    case Mnemonic::HLT:   case Mnemonic::RDMSR: case Mnemonic::WRMSR:
    case Mnemonic::CLI:   case Mnemonic::STI:   case Mnemonic::SWAPGS:
    case Mnemonic::XSETBV:
        return true;
    default:
        return false;
    }
}

/// True if the register is a 64-bit general-purpose register.
[[nodiscard]] inline constexpr bool IsGPR64(Register r) noexcept {
    return r >= Register::RAX && r <= Register::R15;
}

/// True if the register is a 32-bit general-purpose register.
[[nodiscard]] inline constexpr bool IsGPR32(Register r) noexcept {
    return r >= Register::EAX && r <= Register::R15D;
}

/// True if the register is any general-purpose register (8/16/32/64-bit).
[[nodiscard]] inline constexpr bool IsGPR(Register r) noexcept {
    return r >= Register::RAX && r <= Register::R15B;
}

/// True if the register is an XMM register.
[[nodiscard]] inline constexpr bool IsXMM(Register r) noexcept {
    return r >= Register::XMM0 && r <= Register::XMM31;
}

/// True if the register is a YMM register.
[[nodiscard]] inline constexpr bool IsYMM(Register r) noexcept {
    return r >= Register::YMM0 && r <= Register::YMM31;
}

/// True if the register is a ZMM register.
[[nodiscard]] inline constexpr bool IsZMM(Register r) noexcept {
    return r >= Register::ZMM0 && r <= Register::ZMM31;
}

/// True if the register is any SIMD vector register (XMM/YMM/ZMM).
[[nodiscard]] inline constexpr bool IsVectorRegister(Register r) noexcept {
    return IsXMM(r) || IsYMM(r) || IsZMM(r);
}

/// True if the register is an opmask register (K0–K7).
[[nodiscard]] inline constexpr bool IsOpmask(Register r) noexcept {
    return r >= Register::K0 && r <= Register::K7;
}

/// True if the register is a segment register.
[[nodiscard]] inline constexpr bool IsSegment(Register r) noexcept {
    return r >= Register::ES && r <= Register::GS;
}

/// True if the register is a control register.
[[nodiscard]] inline constexpr bool IsControl(Register r) noexcept {
    return r >= Register::CR0 && r <= Register::CR15;
}

/// True if the register is a debug register.
[[nodiscard]] inline constexpr bool IsDebug(Register r) noexcept {
    return r >= Register::DR0 && r <= Register::DR7;
}

/// True if the register is an x87 FPU stack register.
[[nodiscard]] inline constexpr bool IsFPU(Register r) noexcept {
    return r >= Register::ST0 && r <= Register::ST7;
}

} // namespace Phantom::Disasm
