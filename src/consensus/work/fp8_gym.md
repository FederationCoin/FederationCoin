# FP8 gym (kind 2)

Frozen at genesis. Pin card: RTX 5070 Ti. Dimension, tile order, and
rounding do not change in a later release. Other chips mine this kind
only if they emit these bits. Golden digests in `fp8_gym_tests` are
the 5070 Ti dump.

IEEE `cvt.rn.satfinite` is the hardware pack name. It is not the flex
leftover-hole predicate `Saturated()`.

```mermaid
flowchart TD
  header["166-byte header v2"]
  seed["Blake2b-256 domain gfcn-fp8-gym-v2"]
  expand["2048 x 64-byte Blake2b stream"]
  matrices["A then B 256x256 E4M3FN"]
  remap["0x7F/0xFF to max finite 0x7E/0xFE"]
  mma["tiled QMMA m16n8k32 k_tile m_tile n_tile"]
  c32["C binary32"]
  quant["cvt.rn.satfinite to E4M3FN"]
  out["Blake2b-256 domain gfcn-fp8-gym-out-v2"]
  header --> seed --> expand --> matrices --> remap --> mma --> c32 --> quant --> out
```

Classify then visit (no nested IEEE/E4M3 sniff in the QMMA lane):

1. Each A/B byte is `E4M3NaN`, `E4M3SignedZero`, or `E4M3FiniteNonZero`.
2. Each accumulator cell is `IeeeFp32NaN`, `IeeeFp32Inf`, `IeeeFp32Zero`, or `IeeeFp32Finite`.
3. One k=32 lane fused-accumulates 32 products plus C at 25 fraction bits, then RZ-normalizes to binary32 (overflow to inf, underflow to subnormal, else normal).
4. Packed C is digested. That digest is the work for `nBits`.
