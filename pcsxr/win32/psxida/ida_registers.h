#pragma once

enum psx_registers
{
	psx_r0, psx_at, psx_v0, psx_v1, psx_a0, psx_a1, psx_a2, psx_a3,
	psx_t0, psx_t1, psx_t2, psx_t3, psx_t4, psx_t5, psx_t6, psx_t7,
	psx_s0, psx_s1, psx_s2, psx_s3, psx_s4, psx_s5, psx_s6, psx_s7,
	psx_t8, psx_t9, psx_k0, psx_k1, psx_gp, psx_sp, psx_fp, psx_ra, psx_lo, psx_hi,

	psx_pc,

	psx_Index,      psx_Random,    psx_EntryLo0,  psx_BPC,
	psx_Context,    psx_BDA,       psx_PIDMask,   psx_DCIC,
	psx_BadVAddr,   psx_BDAM,      psx_EntryHi,   psx_BPCM,
	psx_Status,     psx_Cause,     psx_EPC,       psx_PRid,
	psx_Config,     psx_LLAddr,    psx_WatchLO,   psx_WatchHI,
	psx_XContext,   psx_Reserved1, psx_Reserved2, psx_Reserved3,
	psx_Reserved4,  psx_Reserved5, psx_ECC,       psx_CacheErr,
	psx_TagLo,      psx_TagHi,     psx_ErrorEPC,  psx_Reserved6,

	psx_VXY0, psx_VZ0,  psx_VXY1, psx_VZ1,  psx_VXY2, psx_VZ2,  psx_RGB,  psx_OTZ,
	psx_IR0,  psx_IR1,  psx_IR2,  psx_IR3,  psx_SXY0, psx_SXY1, psx_SXY2, psx_SXYP,
	psx_SZ0,  psx_SZ1,  psx_SZ2,  psx_SZ3,  psx_RGB0, psx_RGB1, psx_RGB2, psx_RES1,
	psx_MAC0, psx_MAC1, psx_MAC2, psx_MAC3, psx_IRGB, psx_ORGB, psx_LZCS, psx_LZCR,

	psx_R11R12, psx_R13R21, psx_R22R23, psx_R31R32, psx_R33, psx_TRX,  psx_TRY,  psx_TRZ,
	psx_L11L12, psx_L13L21, psx_L22L23, psx_L31L32, psx_L33, psx_RBK,  psx_BBK,  psx_GBK,
	psx_LR1LR2, psx_LR3LG1, psx_LG2LG3, psx_LB1LB2, psx_LB3, psx_RFC,  psx_GFC,  psx_BFC,
	psx_OFX,    psx_OFY,    psx_H,      psx_DQA,    psx_DQB, psx_ZSF3, psx_ZSF4, psx_FLAG,
};