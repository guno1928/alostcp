//go:build amd64

#include "textflag.h"

DATA c0<>+0(SB)/8, $0x0d08050302010100
DATA c0<>+8(SB)/8, $0x6279e99059372215
GLOBL c0<>(SB), RODATA|NOPTR, $16

DATA c1<>+0(SB)/8, $0xf12fc26d55183ddb
DATA c1<>+8(SB)/8, $0xdd28b57342311120
GLOBL c1<>(SB), RODATA|NOPTR, $16

#define UPDATE \
	MOVOU X7, X10        \
	MOVOU X6, X11        \
	AESENC X7, X11       \
	MOVOU X11, X7        \
	MOVOU X5, X11        \
	AESENC X6, X11       \
	MOVOU X11, X6        \
	MOVOU X4, X11        \
	AESENC X5, X11       \
	MOVOU X11, X5        \
	MOVOU X3, X11        \
	AESENC X4, X11       \
	PXOR X9, X11         \
	MOVOU X11, X4        \
	MOVOU X2, X11        \
	AESENC X3, X11       \
	MOVOU X11, X3        \
	MOVOU X1, X11        \
	AESENC X2, X11       \
	MOVOU X11, X2        \
	MOVOU X0, X11        \
	AESENC X1, X11       \
	MOVOU X11, X1        \
	MOVOU X10, X11       \
	AESENC X0, X11       \
	PXOR X8, X11         \
	MOVOU X11, X0

#define INIT \
	MOVOU c0<>(SB), X14  \
	MOVOU c1<>(SB), X15  \
	MOVOU (R8), X12      \
	MOVOU (R9), X13      \
	MOVOU X12, X0        \
	PXOR X13, X0         \
	MOVOU X0, X4         \
	MOVOU X15, X1        \
	MOVOU X14, X2        \
	MOVOU X15, X3        \
	MOVOU X12, X5        \
	PXOR X14, X5         \
	MOVOU X12, X6        \
	PXOR X15, X6         \
	MOVOU X12, X7        \
	PXOR X14, X7         \
	MOVOU X13, X8        \
	MOVOU X12, X9

#define ZBLOCK \
	MOVOU X2, X12        \
	PAND X3, X12         \
	PXOR X6, X12         \
	PXOR X1, X12         \
	MOVOU X6, X13        \
	PAND X7, X13         \
	PXOR X2, X13         \
	PXOR X5, X13

// func aegisSeal(key, nonce, dst, src, ad *byte, srcLen, adLen int)
TEXT ·aegisSeal(SB), NOSPLIT, $64-56
	MOVQ key+0(FP), R8
	MOVQ nonce+8(FP), R9
	MOVQ dst+16(FP), DI
	MOVQ src+24(FP), SI
	MOVQ ad+32(FP), BX
	MOVQ srcLen+40(FP), CX
	MOVQ adLen+48(FP), DX
	MOVQ DI, R12
	MOVQ CX, R10
	MOVQ DX, R11

	INIT
	MOVQ $10, R13
seal_init_loop:
	UPDATE
	DECQ R13
	JNZ seal_init_loop

seal_ad_full:
	CMPQ DX, $32
	JL seal_ad_tail
	MOVOU (BX), X8
	MOVOU 16(BX), X9
	UPDATE
	ADDQ $32, BX
	SUBQ $32, DX
	JMP seal_ad_full

seal_ad_tail:
	TESTQ DX, DX
	JZ seal_enc
	PXOR X8, X8
	MOVOU X8, 0(SP)
	MOVOU X8, 16(SP)
	XORQ R14, R14
seal_ad_copy:
	CMPQ R14, DX
	JGE seal_ad_copy_done
	MOVBLZX (BX)(R14*1), R15
	MOVB R15, 0(SP)(R14*1)
	INCQ R14
	JMP seal_ad_copy
seal_ad_copy_done:
	MOVOU 0(SP), X8
	MOVOU 16(SP), X9
	UPDATE

seal_enc:
seal_enc_full:
	CMPQ CX, $32
	JL seal_enc_tail
	ZBLOCK
	MOVOU (SI), X8
	MOVOU 16(SI), X9
	MOVOU X8, X14
	PXOR X12, X14
	MOVOU X9, X15
	PXOR X13, X15
	MOVOU X14, (DI)
	MOVOU X15, 16(DI)
	UPDATE
	ADDQ $32, SI
	ADDQ $32, DI
	SUBQ $32, CX
	JMP seal_enc_full

seal_enc_tail:
	TESTQ CX, CX
	JZ seal_final
	PXOR X8, X8
	MOVOU X8, 0(SP)
	MOVOU X8, 16(SP)
	XORQ R14, R14
seal_enc_copy:
	CMPQ R14, CX
	JGE seal_enc_copy_done
	MOVBLZX (SI)(R14*1), R15
	MOVB R15, 0(SP)(R14*1)
	INCQ R14
	JMP seal_enc_copy
seal_enc_copy_done:
	ZBLOCK
	MOVOU 0(SP), X8
	MOVOU 16(SP), X9
	MOVOU X8, X14
	PXOR X12, X14
	MOVOU X9, X15
	PXOR X13, X15
	MOVOU X14, 32(SP)
	MOVOU X15, 48(SP)
	XORQ R14, R14
seal_enc_out_copy:
	CMPQ R14, CX
	JGE seal_enc_out_done
	MOVBLZX 32(SP)(R14*1), R15
	MOVB R15, (DI)(R14*1)
	INCQ R14
	JMP seal_enc_out_copy
seal_enc_out_done:
	UPDATE

seal_final:
	MOVQ R11, AX
	SHLQ $3, AX
	MOVQ AX, 0(SP)
	MOVQ R10, AX
	SHLQ $3, AX
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X8
	MOVOU X2, X12
	PXOR X8, X12
	MOVOU X12, X8
	MOVOU X12, X9
	MOVQ $7, R13
seal_fin_loop:
	UPDATE
	DECQ R13
	JNZ seal_fin_loop
	MOVOU X0, X14
	PXOR X1, X14
	PXOR X2, X14
	PXOR X3, X14
	PXOR X4, X14
	PXOR X5, X14
	PXOR X6, X14
	MOVQ R12, AX
	ADDQ R10, AX
	MOVOU X14, (AX)
	RET

// func aegisOpen(key, nonce, dst, src, ad, tag *byte, srcLen, adLen int)
TEXT ·aegisOpen(SB), NOSPLIT, $64-64
	MOVQ key+0(FP), R8
	MOVQ nonce+8(FP), R9
	MOVQ dst+16(FP), DI
	MOVQ src+24(FP), SI
	MOVQ ad+32(FP), BX
	MOVQ srcLen+48(FP), CX
	MOVQ adLen+56(FP), DX
	MOVQ CX, R10
	MOVQ DX, R11

	INIT
	MOVQ $10, R13
open_init_loop:
	UPDATE
	DECQ R13
	JNZ open_init_loop

open_ad_full:
	CMPQ DX, $32
	JL open_ad_tail
	MOVOU (BX), X8
	MOVOU 16(BX), X9
	UPDATE
	ADDQ $32, BX
	SUBQ $32, DX
	JMP open_ad_full

open_ad_tail:
	TESTQ DX, DX
	JZ open_dec
	PXOR X8, X8
	MOVOU X8, 0(SP)
	MOVOU X8, 16(SP)
	XORQ R14, R14
open_ad_copy:
	CMPQ R14, DX
	JGE open_ad_copy_done
	MOVBLZX (BX)(R14*1), R15
	MOVB R15, 0(SP)(R14*1)
	INCQ R14
	JMP open_ad_copy
open_ad_copy_done:
	MOVOU 0(SP), X8
	MOVOU 16(SP), X9
	UPDATE

open_dec:
open_dec_full:
	CMPQ CX, $32
	JL open_dec_tail
	ZBLOCK
	MOVOU (SI), X14
	PXOR X12, X14
	MOVOU 16(SI), X15
	PXOR X13, X15
	MOVOU X14, (DI)
	MOVOU X15, 16(DI)
	MOVOU X14, X8
	MOVOU X15, X9
	UPDATE
	ADDQ $32, SI
	ADDQ $32, DI
	SUBQ $32, CX
	JMP open_dec_full

open_dec_tail:
	TESTQ CX, CX
	JZ open_final
	PXOR X8, X8
	MOVOU X8, 0(SP)
	MOVOU X8, 16(SP)
	XORQ R14, R14
open_dec_copy:
	CMPQ R14, CX
	JGE open_dec_copy_done
	MOVBLZX (SI)(R14*1), R15
	MOVB R15, 0(SP)(R14*1)
	INCQ R14
	JMP open_dec_copy
open_dec_copy_done:
	ZBLOCK
	MOVOU 0(SP), X8
	PXOR X12, X8
	MOVOU 16(SP), X9
	PXOR X13, X9
	MOVOU X8, 32(SP)
	MOVOU X9, 48(SP)
	XORQ R14, R14
open_dec_out_copy:
	CMPQ R14, CX
	JGE open_dec_out_done
	MOVBLZX 32(SP)(R14*1), R15
	MOVB R15, (DI)(R14*1)
	INCQ R14
	JMP open_dec_out_copy
open_dec_out_done:
	MOVQ CX, R14
open_dec_zero:
	CMPQ R14, $32
	JGE open_dec_zero_done
	MOVB $0, 32(SP)(R14*1)
	INCQ R14
	JMP open_dec_zero
open_dec_zero_done:
	MOVOU 32(SP), X8
	MOVOU 48(SP), X9
	UPDATE

open_final:
	MOVQ R11, AX
	SHLQ $3, AX
	MOVQ AX, 0(SP)
	MOVQ R10, AX
	SHLQ $3, AX
	MOVQ AX, 8(SP)
	MOVOU 0(SP), X8
	MOVOU X2, X12
	PXOR X8, X12
	MOVOU X12, X8
	MOVOU X12, X9
	MOVQ $7, R13
open_fin_loop:
	UPDATE
	DECQ R13
	JNZ open_fin_loop
	MOVOU X0, X14
	PXOR X1, X14
	PXOR X2, X14
	PXOR X3, X14
	PXOR X4, X14
	PXOR X5, X14
	PXOR X6, X14
	MOVQ tag+40(FP), AX
	MOVOU X14, (AX)
	RET
