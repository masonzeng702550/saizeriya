/* build_table.c — YaniHash-40 彩虹表建表器（多執行緒）
 *
 * 核心邏輯在 yani.h，與 author/yani_core.py 位元級一致。
 *
 *   cc -O3 -pthread -o build_table build_table.c
 *   ./build_table --selftest
 *   ./build_table PWLEN TRUNC t m K1 K2 K3 K4 out.tbl [threads]
 *
 * 輸出格式（v1.5 起）：bit-packed 位元流，每列 ENDBITS bits、低位在前。
 * start 不存——第 c 列就是第 c 條鏈，起點為 idx_to_pw(c)。
 * 每個 BLOCK（4096，可被 8 整除）的位元數必為 8 的倍數，故各執行緒
 * 的 pwrite 邊界對齊到 byte，不會互相踩到。
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "yani.h"

static int OUTFD;

static uint64_t g_next = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_done = 0;
#define BLOCK 4096  /* 必須是 8 的倍數 */

static void *worker(void *arg) {
    (void)arg;
    size_t cap = ((size_t)BLOCK * ENDBITS + 15) / 8;
    unsigned char *buf = malloc(cap);
    char pw[MAXPW];
    for (;;) {
        pthread_mutex_lock(&g_lock);
        uint64_t lo = g_next;
        g_next += BLOCK;
        pthread_mutex_unlock(&g_lock);
        if (lo >= NCHAINS) break;
        uint64_t hi = lo + BLOCK;
        if (hi > NCHAINS) hi = NCHAINS;

        uint64_t nb = (hi - lo) * (uint64_t)ENDBITS;
        size_t nbytes = (size_t)((nb + 7) / 8);
        memset(buf, 0, nbytes);

        uint64_t acc = 0;
        int nbits = 0;
        size_t out = 0;
        for (uint64_t c = lo; c < hi; c++) {
            idx_to_pw(c, pw);
            for (uint64_t i = 0; i < CHAIN_LEN; i++)
                reduce_at(yani40(pw, PWLEN), i, pw);
            acc |= trunc_val(pw) << nbits;
            nbits += ENDBITS;
            while (nbits >= 8) {
                buf[out++] = (unsigned char)(acc & 0xFF);
                acc >>= 8;
                nbits -= 8;
            }
        }
        if (nbits) buf[out++] = (unsigned char)(acc & 0xFF);

        off_t off = (off_t)((lo * (uint64_t)ENDBITS) / 8);
        unsigned char *p = buf;
        size_t left = out;
        while (left) {
            ssize_t w = pwrite(OUTFD, p, left, off);
            if (w <= 0) { perror("pwrite"); exit(1); }
            left -= (size_t)w; p += w; off += w;
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

static int selftest(void) {
    /* 中性測試種子 (1,2,3,4)，不涉及真值。Python 端：
     *   import yani_core as C; K=(1,2,3,4)
     *   C.yani40(b"yanikoaa",K).hex(); C.reduce_at(C.yani40(b"yyyyyyyy",K),0)
     *   C.walk("yyyyyyyy",256,K,0)
     */
    PWLEN = 8; NSPACE = 1679616; TRUNC = 4; ENDBITS = calc_endbits(TRUNC);
    K[0] = 1; K[1] = 2; K[2] = 3; K[3] = 4;
    printf("selftest K=(1,2,3,4) PWLEN=8 t=256 PASSES=%d ENDBITS=%d\n",
           PASSES, ENDBITS);
    const char *v[] = {"yanikoaa", "yyyyyyyy"};
    for (int i = 0; i < 2; i++)
        printf("yani40(\"%s\") = %010" PRIx64 "\n", v[i], yani40(v[i], 8));
    char out[MAXPW + 1] = {0}, pw[MAXPW];
    reduce_at(yani40("yyyyyyyy", 8), 0, out);
    printf("reduce_at(yani40(\"yyyyyyyy\"), 0) = %s\n", out);
    memcpy(pw, "yyyyyyyy", 8);
    for (uint64_t i = 0; i < 256; i++) reduce_at(yani40(pw, 8), i, pw);
    memcpy(out, pw, 8); out[8] = 0;
    printf("chain0_end(t=256) = %s   trunc_val = %" PRIu64 "\n", out, trunc_val(pw));
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
    ENDBITS = calc_endbits(TRUNC);

    off_t fsize = (off_t)((NCHAINS * (uint64_t)ENDBITS + 7) / 8);
    OUTFD = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (OUTFD < 0) { perror("open"); return 1; }
    if (ftruncate(OUTFD, fsize + 8)) { perror("ftruncate"); return 1; }

    fprintf(stderr,
        "PWLEN=%d TRUNC=%d ENDBITS=%d PASSES=%d N=6^%d=%" PRIu64
        " t=%" PRIu64 " m=%" PRIu64 " threads=%d\n",
        PWLEN, TRUNC, ENDBITS, PASSES, PWLEN, NSPACE, CHAIN_LEN, NCHAINS, nthreads);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_t *th = malloc(sizeof(pthread_t) * nthreads);
    for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* 砍掉為了讓 unpack_end 能安全讀 8 bytes 而多留的尾巴 */
    if (ftruncate(OUTFD, fsize)) { perror("ftruncate"); return 1; }
    close(OUTFD);

    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double hashes = (double)NCHAINS * (double)CHAIN_LEN;
    fprintf(stderr, "\ndone in %.2f s  (%.3g chain-steps, %.1f M/s)  -> %s (%.1f MB)\n",
            dt, hashes, hashes / dt / 1e6, outpath, (double)fsize / 1e6);
    return 0;
}
