/* build_table.c — YaniHash-40 彩虹表建表器（多執行緒）
 *
 * 與 author/yani_core.py 的參考實作位元級一致（--selftest 可對拍）。
 *
 *   cc -O3 -march=native -pthread -o build_table build_table.c
 *   ./build_table --selftest
 *   ./build_table PWLEN TRUNC t m K1 K2 K3 K4 out.tbl [threads]
 *
 * 輸出格式：固定寬度記錄，每筆只有截斷到 TRUNC 個字元的 endpoint + '\n'。
 * start 不存——第 c 行就是第 c 條鏈，起點為 idx_to_pw(c)。
 * 以 pwrite 依 chain index 定位，因此多執行緒輸出順序仍為 c = 0..m-1。
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAXPW 32
static const char CHARSET[7] = "yaniko";
static const uint64_t RSTEP = 0x9E3779B9ULL;
static const uint64_t M40 = (1ULL << 40) - 1;

static int PWLEN;
static int TRUNC;   /* endpoint 截斷長度 */
static uint64_t NSPACE; /* 6^PWLEN */
static uint64_t CHAIN_LEN;
static uint64_t NCHAINS;
static uint32_t K[4];
static int RECLEN;
static int OUTFD;

static inline uint32_t rotl32(uint32_t v, int r) {
    return (uint32_t)((v << r) | (v >> (32 - r)));
}

static inline uint64_t yani40(const char *msg, int len) {
    uint32_t a = K[0] ^ 0x9E3779B9u;
    uint32_t b = K[1] + 0x85EBCA6Bu;
    uint32_t c = K[2] ^ 0xC2B2AE35u;
    uint32_t d = K[3] + 0x27D4EB2Fu;
    for (int i = 0; i < len; i++) {
        uint32_t x = (uint8_t)msg[i];
        a = (a ^ x) * 0x01000193u;
        b = rotl32(b + a, 13) ^ c;
        c = (c * 5u + 0xF00Du) ^ b;
        d = rotl32(d ^ a, 7) + b;
        a = a + d;
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
    uint64_t n = (h ^ ((i * RSTEP) & M40)) % NSPACE;
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

/* ---- worker ------------------------------------------------------------ */

static uint64_t g_next = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_done = 0;
#define BLOCK 4096

static void *worker(void *arg) {
    (void)arg;
    char *buf = malloc((size_t)BLOCK * RECLEN);
    char pw[MAXPW], start[MAXPW];
    for (;;) {
        pthread_mutex_lock(&g_lock);
        uint64_t lo = g_next;
        g_next += BLOCK;
        pthread_mutex_unlock(&g_lock);
        if (lo >= NCHAINS) break;
        uint64_t hi = lo + BLOCK;
        if (hi > NCHAINS) hi = NCHAINS;

        for (uint64_t c = lo; c < hi; c++) {
            idx_to_pw(c, start);
            memcpy(pw, start, PWLEN);
            for (uint64_t i = 0; i < CHAIN_LEN; i++)
                reduce_at(yani40(pw, PWLEN), i, pw);
            char *rec = buf + (size_t)(c - lo) * RECLEN;
            memcpy(rec, pw, TRUNC);          /* 只留截斷後的 endpoint */
            rec[RECLEN - 1] = '\n';
        }
        size_t nb = (size_t)(hi - lo) * RECLEN;
        off_t off = (off_t)lo * RECLEN;
        char *p = buf;
        while (nb) {
            ssize_t w = pwrite(OUTFD, p, nb, off);
            if (w <= 0) { perror("pwrite"); exit(1); }
            nb -= (size_t)w; p += w; off += w;
        }
        pthread_mutex_lock(&g_lock);
        g_done += (hi - lo);
        if ((g_done & 0x3FFFF) < BLOCK)
            fprintf(stderr, "\r  %" PRIu64 "/%" PRIu64 " chains", g_done, NCHAINS);
        pthread_mutex_unlock(&g_lock);
    }
    free(buf);
    return NULL;
}

/* ---- selftest ---------------------------------------------------------- */

static int selftest(void) {
    /* 用中性測試種子 (1,2,3,4) 與 yani_core.py 對拍，不涉及真值。
     * Python 端：
     *   import yani_core as C
     *   K=(1,2,3,4)
     *   C.yani40(b"yanikoaa",K).hex(); C.yani40(b"yyyyyyyy",K).hex()
     *   C.reduce_at(C.yani40(b"yyyyyyyy",K),0); C.walk("yyyyyyyy",256,K,0)
     */
    PWLEN = 8; NSPACE = 1679616; K[0]=1; K[1]=2; K[2]=3; K[3]=4;
    printf("selftest K=(1,2,3,4) PWLEN=8 t=256\n");
    const char *v[] = {"yanikoaa", "yyyyyyyy"};
    for (int i = 0; i < 2; i++)
        printf("yani40(\"%s\") = %010" PRIx64 "\n", v[i], yani40(v[i], 8));
    char out[MAXPW+1] = {0};
    reduce_at(yani40("yyyyyyyy", 8), 0, out);
    printf("reduce_at(yani40(\"yyyyyyyy\"), 0) = %s\n", out);
    char pw[MAXPW]; memcpy(pw, "yyyyyyyy", 8);
    for (uint64_t i = 0; i < 256; i++) reduce_at(yani40(pw, 8), i, pw);
    memcpy(out, pw, 8); out[8] = 0;
    printf("chain0_end(t=256) = %s\n", out);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
    if (argc < 10) {
        fprintf(stderr,
            "usage: %s PWLEN TRUNC t m K1 K2 K3 K4 out.tbl [threads]\n"
            "       %s --selftest\n", argv[0], argv[0]);
        return 2;
    }
    PWLEN = atoi(argv[1]);
    TRUNC = atoi(argv[2]);
    CHAIN_LEN = strtoull(argv[3], NULL, 0);
    NCHAINS = strtoull(argv[4], NULL, 0);
    for (int i = 0; i < 4; i++) K[i] = (uint32_t)strtoul(argv[5 + i], NULL, 0);
    const char *outpath = argv[9];
    int nthreads = argc > 10 ? atoi(argv[10]) : (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (PWLEN < 1 || PWLEN > 20) { fprintf(stderr, "bad PWLEN\n"); return 2; }
    if (TRUNC < 1 || TRUNC > PWLEN) { fprintf(stderr, "bad TRUNC\n"); return 2; }

    NSPACE = 1;
    for (int i = 0; i < PWLEN; i++) NSPACE *= 6;
    RECLEN = TRUNC + 1;

    OUTFD = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (OUTFD < 0) { perror("open"); return 1; }
    if (ftruncate(OUTFD, (off_t)NCHAINS * RECLEN)) { perror("ftruncate"); return 1; }

    fprintf(stderr,
        "PWLEN=%d TRUNC=%d N=6^%d=%" PRIu64 " t=%" PRIu64 " m=%" PRIu64
        " K=(%u,%u,%u,%u) threads=%d\n",
        PWLEN, TRUNC, PWLEN, NSPACE, CHAIN_LEN, NCHAINS,
        K[0], K[1], K[2], K[3], nthreads);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_t *th = malloc(sizeof(pthread_t) * nthreads);
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(OUTFD);

    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double hashes = (double)NCHAINS * (double)CHAIN_LEN;
    fprintf(stderr, "\ndone in %.2f s  (%.3g hashes, %.1f MH/s)  -> %s (%.1f MB)\n",
            dt, hashes, hashes / dt / 1e6, outpath,
            (double)NCHAINS * RECLEN / 1e6);
    return 0;
}
