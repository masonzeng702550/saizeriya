/* solve_ref.c — 官方解的重運算部分：用彩虹表還原 shadow 裡的明文。
 *
 * v1.4 起 CPython 跑不動（約 6 小時），因此作者端驗收也必須用 C。
 * 金鑰推導與 flag 解密仍留在 solve_official.py。
 *
 *   cc -O3 -pthread -o solve_ref solve_ref.c
 *   ./solve_ref PWLEN TRUNC t m K1 K2 K3 K4 nyan.tbl <hash1> ... [threads]
 *
 * 表格式：每行 TRUNC 個字元的截斷 endpoint，第 c 行 = 第 c 條鏈，
 * 起點為 idx_to_pw(c)。截斷造成的 false alarm 必須走回起點驗證。
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAXPW 32
static const char CHARSET[7] = "yaniko";
static const uint64_t RSTEP = 0x9E3779B9ULL;
static const uint64_t M40 = (1ULL << 40) - 1;

static int PWLEN, TRUNC, RECLEN;
static uint64_t NSPACE, CHAIN_LEN, NCHAINS, NTRUNC;
static uint32_t K[4];
static const unsigned char *TBL;

static uint32_t *BUCKET_OFF;   /* NTRUNC+1 */
static uint32_t *BUCKET_IDX;   /* NCHAINS  */

static inline uint32_t rotl32(uint32_t v, int r) {
    return (uint32_t)((v << r) | (v >> (32 - r)));
}

static inline uint64_t yani40(const char *msg, int len) {
    uint32_t a = K[0] ^ 0x9E3779B9u, b = K[1] + 0x85EBCA6Bu;
    uint32_t c = K[2] ^ 0xC2B2AE35u, d = K[3] + 0x27D4EB2Fu;
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
    for (int k = 0; k < PWLEN; k++) { out[k] = CHARSET[n % 6]; n /= 6; }
}

static inline void idx_to_pw(uint64_t idx, char *out) {
    for (int k = 0; k < PWLEN; k++) { out[k] = CHARSET[idx % 6]; idx /= 6; }
}

static inline int chr_idx(char ch) {
    switch (ch) {
        case 'y': return 0; case 'a': return 1; case 'n': return 2;
        case 'i': return 3; case 'k': return 4; default: return 5;  /* 'o' */
    }
}

/* 截斷 endpoint -> 整數。pw[0] 是最低位（base-6 小端）。 */
static inline uint64_t trunc_key(const char *pw) {
    uint64_t v = 0, p = 1;
    for (int k = 0; k < TRUNC; k++) { v += (uint64_t)chr_idx(pw[k]) * p; p *= 6; }
    return v;
}

static void build_index(void) {
    BUCKET_OFF = calloc(NTRUNC + 1, sizeof(uint32_t));
    BUCKET_IDX = malloc(NCHAINS * sizeof(uint32_t));
    if (!BUCKET_OFF || !BUCKET_IDX) { fprintf(stderr, "oom\n"); exit(1); }
    for (uint64_t c = 0; c < NCHAINS; c++)
        BUCKET_OFF[trunc_key((const char *)TBL + c * RECLEN) + 1]++;
    for (uint64_t v = 0; v < NTRUNC; v++) BUCKET_OFF[v + 1] += BUCKET_OFF[v];
    uint32_t *cur = malloc((NTRUNC + 1) * sizeof(uint32_t));
    memcpy(cur, BUCKET_OFF, (NTRUNC + 1) * sizeof(uint32_t));
    for (uint64_t c = 0; c < NCHAINS; c++)
        BUCKET_IDX[cur[trunc_key((const char *)TBL + c * RECLEN)]++] = (uint32_t)c;
    free(cur);
}

/* ---- 每個目標的搜尋：把 column j 分給各執行緒 ---- */

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

        uint64_t key = trunc_key(cand);
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
    RECLEN = TRUNC + 1;

    /* 尾端可選的 threads 參數：純數字且不是 40-bit hex 長度者 */
    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int nh = argc - 10;
    if (nh > 1 && strlen(argv[argc - 1]) <= 3) { nthreads = atoi(argv[argc - 1]); nh--; }

    int fd = open(tblpath, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st; fstat(fd, &st);
    if ((uint64_t)st.st_size != NCHAINS * RECLEN) {
        fprintf(stderr, "table size %lld != m*%d = %" PRIu64 "\n",
                (long long)st.st_size, RECLEN, NCHAINS * RECLEN);
        return 1;
    }
    TBL = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (TBL == MAP_FAILED) { perror("mmap"); return 1; }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    build_index();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    fprintf(stderr, "[*] index built in %.2f s (%" PRIu64 " chains, %" PRIu64 " buckets)\n",
            (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9, NCHAINS, NTRUNC);

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
