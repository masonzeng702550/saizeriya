/* yani.h — YaniHash-40 / 彩虹表的共用核心（build_table.c 與 solve_ref.c）
 *
 * 與 author/yani_core.py 位元級一致。任何改動必須兩邊同步，
 * 並用 `build_table --selftest` 對拍。
 */

#ifndef YANI_H
#define YANI_H

#include <stdint.h>
#include <string.h>

#define MAXPW 32

static const char CHARSET[7] = "yaniko";
static const uint64_t M40 = (1ULL << 40) - 1;

/* E：訊息迴圈遍數。暴力枚舉整個密語空間的成本正比於此。 */
#define PASSES 3

/* D：reduce_at 的混合常數（公開，與 K 無關） */
static const uint64_t RMIX1 = 0x5851F42D4C95ULL;
static const uint64_t RMIX2 = 0xF1357AEA2E63ULL;

/* 由主程式設定 */
static int PWLEN, TRUNC, ENDBITS;
static uint64_t NSPACE, CHAIN_LEN, NCHAINS;
static uint32_t K[4];

static inline uint32_t rotl32(uint32_t v, int r) {
    return (uint32_t)((v << r) | (v >> (32 - r)));
}

static inline uint64_t yani40(const char *msg, int len) {
    uint32_t a = K[0] ^ 0x9E3779B9u;
    uint32_t b = K[1] + 0x85EBCA6Bu;
    uint32_t c = K[2] ^ 0xC2B2AE35u;
    uint32_t d = K[3] + 0x27D4EB2Fu;
    for (int p = 0; p < PASSES; p++) {
        for (int i = 0; i < len; i++) {
            uint32_t x = (uint8_t)msg[i];
            a = (a ^ x) * 0x01000193u;
            b = rotl32(b + a, 13) ^ c;
            c = (c * 5u + 0xF00Du) ^ b;
            d = rotl32(d ^ a, 7) + b;
            a = a + d;
        }
        a = a ^ ((uint32_t)p * 0x7FEB352Du);
    }
    for (int r = 0; r < 4; r++) {
        a = (a ^ (b >> 15)) * 0x2545F491u;
        b = (b ^ (c >> 13)) * 0x9E3779B1u;
        c = (c ^ (d >> 11)) * 0x85EBCA77u;
        d = (d ^ (a >> 16)) * 0xC2B2AE3Du;
    }
    uint64_t v = (((uint64_t)(a ^ c)) << 32) | (uint64_t)(b ^ d);
    return v & M40;
}

static inline void reduce_at(uint64_t h, uint64_t i, char *out) {
    uint64_t x = (h + i * RMIX1) & M40;
    x = ((x << 21) | (x >> 19)) & M40;
    x = (x * RMIX2) & M40;
    x ^= x >> 23;
    uint64_t n = x % NSPACE;
    for (int k = 0; k < PWLEN; k++) {
        out[k] = CHARSET[n % 6];
        n /= 6;
    }
}

static inline void idx_to_pw(uint64_t idx, char *out) {
    for (int k = 0; k < PWLEN; k++) {
        out[k] = CHARSET[idx % 6];
        idx /= 6;
    }
}

static inline int chr_idx(char ch) {
    switch (ch) {
        case 'y': return 0; case 'a': return 1; case 'n': return 2;
        case 'i': return 3; case 'k': return 4; default: return 5;  /* 'o' */
    }
}

/* 截斷 endpoint -> 整數（base-6 小端，pw[0] 是最低位）。
   這個值同時也是 bit-packed 表裡直接存的內容。 */
static inline uint64_t trunc_val(const char *pw) {
    uint64_t v = 0, p = 1;
    for (int k = 0; k < TRUNC; k++) { v += (uint64_t)chr_idx(pw[k]) * p; p *= 6; }
    return v;
}

/* 從 bit-packed 位元流讀出第 c 列（低位在前） */
static inline uint64_t unpack_end(const unsigned char *blob, uint64_t c) {
    uint64_t bit = c * (uint64_t)ENDBITS;
    uint64_t byte = bit >> 3;
    uint64_t chunk;
    memcpy(&chunk, blob + byte, 8);          /* 小端機器；x86/ARM 皆是 */
    return (chunk >> (bit & 7)) & ((1ULL << ENDBITS) - 1);
}

static inline int calc_endbits(int trunc) {
    uint64_t max = 1;
    for (int i = 0; i < trunc; i++) max *= 6;
    max -= 1;
    int b = 0;
    while (max) { b++; max >>= 1; }
    return b;
}

#endif /* YANI_H */
