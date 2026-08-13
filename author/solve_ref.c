/* solve_ref.c — 官方解的重運算部分：用彩虹表還原 shadow 裡的明文。
 *
 * 核心邏輯在 yani.h。金鑰推導與 flag 解密留在 solve_official.py。
 *
 *   cc -O3 -pthread -o solve_ref solve_ref.c
 *   ./solve_ref PWLEN TRUNC t m K1 K2 K3 K4 nyan.tbl <hash_hex>... [threads]
 *
 * 表格式（v1.5）：bit-packed，每列 ENDBITS bits、低位在前，
 * 第 c 列 = 第 c 條鏈、起點為 idx_to_pw(c)。
 * 截斷造成的 false alarm 必須走回起點用 yani40 驗證。
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "yani.h"

static unsigned char *TBL;
static uint64_t NTRUNC;
static uint32_t *BUCKET_OFF;   /* NTRUNC+1 */
static uint32_t *BUCKET_IDX;   /* NCHAINS  */

static void build_index(void) {
    BUCKET_OFF = calloc(NTRUNC + 1, sizeof(uint32_t));
    BUCKET_IDX = malloc(NCHAINS * sizeof(uint32_t));
    if (!BUCKET_OFF || !BUCKET_IDX) { fprintf(stderr, "oom\n"); exit(1); }
    for (uint64_t c = 0; c < NCHAINS; c++) BUCKET_OFF[unpack_end(TBL, c) + 1]++;
    for (uint64_t v = 0; v < NTRUNC; v++) BUCKET_OFF[v + 1] += BUCKET_OFF[v];
    uint32_t *cur = malloc((NTRUNC + 1) * sizeof(uint32_t));
    memcpy(cur, BUCKET_OFF, (NTRUNC + 1) * sizeof(uint32_t));
    for (uint64_t c = 0; c < NCHAINS; c++)
        BUCKET_IDX[cur[unpack_end(TBL, c)]++] = (uint32_t)c;
    free(cur);
}

static uint64_t TARGET_H;
static volatile int FOUND;
static char FOUND_PW[MAXPW];
static pthread_mutex_t FLOCK = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_col;
static pthread_mutex_t CLOCK_ = PTHREAD_MUTEX_INITIALIZER;

static void *col_worker(void *arg) {
    (void)arg;
    char cand[MAXPW], pw[MAXPW];
    for (;;) {
        if (FOUND) return NULL;
        pthread_mutex_lock(&CLOCK_);
        if (g_col == 0) { pthread_mutex_unlock(&CLOCK_); return NULL; }
        uint64_t j = --g_col;            /* 由後往前掃 */
        pthread_mutex_unlock(&CLOCK_);

        /* pw_{j+1} = R_j(h)，再走到鏈尾 */
        reduce_at(TARGET_H, j, cand);
        for (uint64_t i = j + 1; i < CHAIN_LEN; i++)
            reduce_at(yani40(cand, PWLEN), i, cand);

        uint64_t key = trunc_val(cand);
        for (uint32_t p = BUCKET_OFF[key]; p < BUCKET_OFF[key + 1]; p++) {
            /* false alarm：必須從 start 走回位置 j 再驗證 */
            idx_to_pw(BUCKET_IDX[p], pw);
            for (uint64_t i = 0; i < j; i++)
                reduce_at(yani40(pw, PWLEN), i, pw);
            if (yani40(pw, PWLEN) == TARGET_H) {
                pthread_mutex_lock(&FLOCK);
                if (!FOUND) { memcpy(FOUND_PW, pw, PWLEN); FOUND = 1; }
                pthread_mutex_unlock(&FLOCK);
                return NULL;
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 11) {
        fprintf(stderr,
            "usage: %s PWLEN TRUNC t m K1 K2 K3 K4 nyan.tbl <hash_hex>... [threads]\n",
            argv[0]);
        return 2;
    }
    PWLEN = atoi(argv[1]);
    TRUNC = atoi(argv[2]);
    CHAIN_LEN = strtoull(argv[3], NULL, 0);
    NCHAINS = strtoull(argv[4], NULL, 0);
    for (int i = 0; i < 4; i++) K[i] = (uint32_t)strtoul(argv[5 + i], NULL, 0);
    const char *tblpath = argv[9];

    NSPACE = 1; for (int i = 0; i < PWLEN; i++) NSPACE *= 6;
    NTRUNC = 1; for (int i = 0; i < TRUNC; i++) NTRUNC *= 6;
    ENDBITS = calc_endbits(TRUNC);

    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int nh = argc - 10;
    if (nh > 1 && strlen(argv[argc - 1]) <= 3) { nthreads = atoi(argv[argc - 1]); nh--; }

    /* 讀進記憶體並補 8 bytes 零，讓 unpack_end 讀最後一列時不會越界 */
    uint64_t want = (NCHAINS * (uint64_t)ENDBITS + 7) / 8;
    int fd = open(tblpath, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st; fstat(fd, &st);
    if ((uint64_t)st.st_size != want) {
        fprintf(stderr, "table size %lld != ceil(m*%d/8) = %" PRIu64 "\n",
                (long long)st.st_size, ENDBITS, want);
        return 1;
    }
    TBL = calloc(want + 8, 1);
    if (!TBL) { fprintf(stderr, "oom\n"); return 1; }
    if (read(fd, TBL, want) != (ssize_t)want) { perror("read"); return 1; }
    close(fd);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    build_index();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fprintf(stderr, "[*] index built in %.2f s (%" PRIu64 " chains, %" PRIu64
            " buckets, ENDBITS=%d, PASSES=%d)\n",
            (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9,
            NCHAINS, NTRUNC, ENDBITS, PASSES);

    pthread_t *th = malloc(sizeof(pthread_t) * nthreads);
    for (int t = 0; t < nh; t++) {
        TARGET_H = strtoull(argv[10 + t], NULL, 16);
        FOUND = 0; g_col = CHAIN_LEN;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < nthreads; i++) pthread_create(&th[i], NULL, col_worker, NULL);
        for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (!FOUND) { fprintf(stderr, "[!] %s NOT FOUND\n", argv[10 + t]); return 3; }
        printf("%.*s\n", PWLEN, FOUND_PW);
        fflush(stdout);
        fprintf(stderr, "[+] %s -> %.*s  (%.2f s)\n", argv[10 + t], PWLEN, FOUND_PW, dt);
    }
    return 0;
}
