# Trigger 5 Compressed Frame Payload


## Introduction

When bit 0 of the frame-info nibble in the Trigger 5 bulk header is set (and header byte `0x10` is `0x71`), the packet payload is compressed with MCT's custom codec.
This document describes only that payload--the 20-byte header is covered in [Protocol-T5.md](Protocol-T5.md).

The algorithm is lossless DPCM (Differential Pulse-Code Modulation): each component is predicted from the previous pixel, and only the differences are stored.
Those differences are entropy-coded as a magnitude category with a fixed Huffman code plus raw value bits.
This is the same scheme JPEG uses for its coefficients, but with no transform and no quantization, so reconstruction is bit-exact.
Its closest relative is the Huffman-coded DPCM of lossless JPEG.
The 64-pixel coding unit is the only property it shares with block-based codecs.


## Glossary

- **DPCM**: Differential Pulse-Code Modulation.
  Compression that stores the difference between each sample and a prediction of that sample, rather than the sample itself.
- **prediction**: A value estimated from samples that have already been coded (here, the corresponding component of the previous pixel).
- **sample**: One numeric value of the signal.
  Here, a sample is one colour component of one pixel.
- **entropy coding**: Giving common values shorter codes than rare ones.
  Huffman coding is a form of entropy coding.
- **magnitude category with a fixed Huffman code plus raw value bits**: Coding a value by first writing its category with a Huffman code that is the same for every payload, then writing the value's raw value bits.
- **magnitude category**: A small integer saying how large a value is.
  This is the number of bits needed for its magnitude, or `0` for a value of zero.
- **fixed Huffman code**: A Huffman code whose code words are identical for every payload, so no table has to be transmitted.
- **Huffman code**: A prefix code: no code word is the beginning of another, so code words can be read one after another without separators.
- **raw value bit**: A bit written directly after a category and not itself coded.
  Together, the raw value bits give the value's magnitude and sign.
- **transform**: Converting a block of samples into another representation (such as frequency coefficients) before coding.
- **quantization**: Rounding values onto a coarser scale, discarding precision.


## Overview

The payload is one continuous bit stream, split into a sequence of groups of at most 64 pixels each:

- Each group starts with a 16-bit little-endian length.
  Bit 15 of the length marks the group as "raw" (verbatim bytes).
  When that bit is clear, the group holds Huffman-coded differences.
- Pixels are stored in memory order B, G, R, and groups run in raster order (left-to-right, top-to-bottom).
  A group may straddle a row boundary--the group counter does not reset per row.
- Inside a group each B/G/R component is DPCM-coded against the same component of the previous pixel, with all three predictors reset to `0x80` at the group start.
  Differences are taken modulo 256 and treated as signed.
- Each difference is coded as a magnitude category (Huffman) followed by the category's value bits (magnitude and sign).
  One special code covers the `±128` wrap-around.


## Primitives


### Bit stream

Bits are packed MSB-first into 32-bit little-endian words.
The first bit written is bit 31 of a word, and each word is stored low byte first, so a reader that consumes the payload bytes in order sees every 4-byte word from its last byte to its first.
All multi-bit fields below are written most-significant bit first.

The stream is padded with zero bits to whole bytes (a group) and to a whole 32-bit word (the payload).
The header's payload length can therefore be up to 3 bytes shorter than the word-aligned payload.


### Group framing

```
[16-bit little-endian length][length bytes of data]
```

The length counts only the data bytes that follow it.
It is stored low byte first in stream order.
Bit 15 is the raw flag, and the low 15 bits are the data size.

The decoder already knows how many pixels a group holds (`min(64, remaining)`), so the length is used to detect raw groups, to skip to the next group, and to detect truncation.


### Pixel and component order

Pixels are stored as three bytes in source-surface order B, G, R, flattened row by row.
The component stream is `B0 G0 R0 B1 G1 R1 ...`; a pixel's components are not specially aligned with the pair boundaries of the entropy coder.


### DPCM prediction

For component index `j` in the flattened group:

```
pred(j) = 0x80          if j < 3   (first pixel of the group)
pred(j) = s[j - 3]      otherwise  (same component of the previous pixel)
```

`s[j-3]` is the reconstructed value, which equals the original for lossless coding.


### Modulo-256 differences

Each difference is the signed value in `-128..127` congruent to `s[j] - pred(j) (mod 256)`:

```
d = (s[j] - pred(j)) mod 256
if d >= 128: d -= 256
```

Reconstruction is `s[j] = (pred(j) + d) mod 256`.


### Magnitude categories

A difference `d` is split into a category `c` (roughly the number of bits in `|d|`) and the `c` value bits needed to recover it exactly.
Categories use a fixed Huffman code:

| `d` | category `c` | Huffman code | value bits | total |
|---|--:|---|--:|--:|
| `0` | 0 | `00` | 0 | 2 |
| `±1` | 1 | `010` | 1 | 4 |
| `±2..±3` | 2 | `011` | 2 | 5 |
| `±4..±7` | 3 | `100` | 3 | 6 |
| `±8..±15` | 4 | `101` | 4 | 7 |
| `±16..±31` | 5 | `110` | 5 | 8 |
| `±32..±63` | 6 | `1110` | 6 | 10 |
| `±64..±127` | 7 | `11110` | 7 | 12 |


### Value bits

Value bits use the JPEG one's-complement representation:

```
c = category(d)
if d >= 0: value_bits = d          & ((1 << c) - 1)
if d <  0: value_bits = (d - 1)    & ((1 << c) - 1)
```

Decoding:

```
extend(c, bits) = bits                     if bits >= 2**(c-1)
                  bits - (2**c - 1)        otherwise
```

Category 0 has no value bits and decodes to `0`.


### The `±128` boundary code

`-128` does not fit the categories above (`+128` and `-128` are the same modulo 256).
It is coded as the special 5-bit code `11111` followed by two value bits, giving a 7-bit total:

| 2-bit value | difference |
|--:|---|
| 0 | `+128` / `-128` |
| 1 | unused (`+128` if it occurs) |
| 2 | `-127` |
| 3 | `+127` |

This special code overrides the category-8 entries--the last two rows are redundant with category 7 but are accepted by decoders.


### Raw groups

If a group's Huffman-coded data would exceed 256 bytes, the encoder discards it and stores the group's components verbatim instead, setting bit 15 of the length.
Raw group data is exactly `3 * pixels` bytes, in B, G, R order, with no prediction.
A full 64-pixel group is therefore at most 192 raw bytes, always below the threshold.


## How the primitives fit together

For each group in raster order:

1. Read the 16-bit length.
2. If the raw flag is set, copy `length` component bytes.
   Otherwise, decode `3 * pixels` differences and reconstruct them with the predictor.

```
read bitstream as 32-bit little-endian words, MSB-first
done = 0
while done < width * height:
    n = min(64, width * height - done)
    length = read_bits(16)                   # first byte is the low byte
    size   = length & 0x7fff
    raw    = length & 0x8000
    if raw:
        out = read_bytes(size)               # 3*n bytes, B,G,R
    else:
        for j in 0..3*n-1:
            c   = decode_huffman_category()  # 00/010/.../11110, or 11111 + 2 bits
            d   = extend(c, read_bits(c))    # 0 for category 0
            pred = 0x80 if j < 3 else out[j-3]
            out[j] = (pred + d) & 0xff
    emit out                                 # n pixels
    done += n
```

Notes:

- The encoder is free to code differences individually or in pairs (a pair lookup table is only an optimization); the resulting bit stream is identical.
- The predictor never uses data outside the current group, so groups are independently encodable and decodable.
