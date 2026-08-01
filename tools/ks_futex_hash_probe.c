/*
 * ks_hash_probe.c — verify the userspace futex hash against the kernel
 * using SHARED futexes (keys = {i_seq, pgoff, offset}, no mm involved).
 *
 * 1. mmap a memfd (shared, file-backed) at a fixed page.
 * 2. Pile 2048 threads FUTEX_WAIT on one address (bucket B).
 * 3. Time FUTEX_WAKE (nr_wake=0) for candidate addresses; slow ones are
 *    in the same bucket as the pile (the kernel walks the whole plist).
 * 4. Compute the userside shared-key hash; check agreement.
 *
 * If the timing-bucket set == the userside-hash bucket set, the jhash2/
 * key/seed/hashsize machinery matches this kernel and the private-path
 * failure is the mm pointer value.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_SHARED 0

static inline int futex_op(volatile uint32_t *uaddr, int op, uint32_t val,
                           const struct timespec *timeout, uint32_t *uaddr2,
                           uint32_t val3) {
  return (int)syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/* ---- the userside jhash2 + shared key (copied from futex_hash.h) ---- */
static inline uint32_t rol32(uint32_t word, unsigned int shift) {
  return (word << (shift & 31)) | (word >> ((-shift) & 31));
}
#define __jhash_mix(a, b, c)                     \
  {                                              \
    a -= c; a ^= rol32(c, 4); c += b;            \
    b -= a; b ^= rol32(a, 6); a += c;            \
    c -= b; c ^= rol32(b, 8); b += a;            \
    a -= c; a ^= rol32(c, 16); c += b;           \
    b -= a; b ^= rol32(a, 19); a += c;           \
    c -= b; c ^= rol32(b, 4); b += a;            \
  }
#define __jhash_final(a, b, c)                   \
  {                                              \
    c ^= b; c -= rol32(b, 14);                   \
    a ^= c; a -= rol32(c, 11);                   \
    b ^= a; b -= rol32(a, 25);                   \
    c ^= b; c -= rol32(b, 16);                   \
    a ^= c; a -= rol32(c, 4);                    \
    b ^= a; b -= rol32(a, 14);                   \
    c ^= b; c -= rol32(b, 24);                   \
  }
#define JHASH_INITVAL 0xdeadbeef
static inline uint32_t jhash2(const uint32_t *k, uint32_t length,
                              uint32_t initval) {
  uint32_t a, b, c;
  a = b = c = JHASH_INITVAL + (length << 2) + initval;
  while (length > 3) {
    a += k[0]; b += k[1]; c += k[2];
    __jhash_mix(a, b, c);
    length -= 3; k += 3;
  }
  switch (length) {
  case 3: c += k[2]; /* fall through */
  case 2: b += k[1]; /* fall through */
  case 1: a += k[0];
    __jhash_final(a, b, c);
  case 0: break;
  }
  return c;
}

typedef union {
  struct { uint64_t i_seq; unsigned long pgoff; unsigned int offset; } shared;
  struct { uint64_t ptr; unsigned long word; unsigned int offset; } both;
} futex_key_t;

#define OFFSET_OF(T, F) ((size_t) & ((T *)0)->F)

static uint32_t shared_futex_hash(uint64_t i_seq, uint64_t pgoff,
                                  uint32_t offset, uint32_t hashsize) {
  futex_key_t key;
  memset(&key, 0, sizeof(key));
  key.shared.i_seq = i_seq;
  key.shared.pgoff = pgoff;
  key.shared.offset = offset;
  uint32_t hash = jhash2((const uint32_t *)&key,
                         OFFSET_OF(futex_key_t, both.offset) / 4,
                         key.both.offset);
  return hash & (hashsize - 1);
}

/* ---- timing ---- */
static inline uint64_t rdtsc_begin(void) {
  uint64_t t;
  __asm__ volatile("isb" ::: "memory");
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t));
  return t;
}
static inline uint64_t rdtsc_end(void) {
  uint64_t t;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t));
  __asm__ volatile("isb" ::: "memory");
  return t;
}

static volatile int go_flag;
static volatile uint32_t *wait_addr;
static int waiters_ready;

static void *do_wait(void *arg) {
  (void)arg;
  __atomic_fetch_add(&waiters_ready, 1, __ATOMIC_SEQ_CST);
  while (!__atomic_load_n(&go_flag, __ATOMIC_SEQ_CST)) {
    futex_op(wait_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
  }
  return NULL;
}

static uint64_t measure(volatile uint32_t *addr) {
  uint64_t best = ~0ULL;
  for (int r = 0; r < 8; r++) {
    uint64_t t0 = rdtsc_begin();
    futex_op(addr, FUTEX_WAKE, 0, NULL, NULL, 0);
    uint64_t t1 = rdtsc_end();
    if (t1 - t0 < best) best = t1 - t0;
  }
  return best;
}

int main(void) {
  long nproc = sysconf(_SC_NPROCESSORS_ONLN);
  uint32_t hashsize = (uint32_t)(nproc * 256);
  printf("nproc=%ld hashsize=%u\n", nproc, hashsize);

  int mfd = memfd_create("ksprobe", 0);
  if (mfd < 0) { perror("memfd_create"); return 1; }
  if (ftruncate(mfd, 4096 * 4096 * 4) != 0) { perror("ftruncate"); return 1; }
  uint32_t *page = mmap(NULL, 4096 * 4096 * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
  if (page == MAP_FAILED) { perror("mmap"); return 1; }
  memset(page, 0, 4096 * 4096 * 4);
  printf("mapped shared futex arena at %p\n", page);

  /* the shared key: i_seq = inode number of the memfd */
  struct stat st;
  if (fstat(mfd, &st) != 0) { perror("fstat"); return 1; }
  uint64_t i_seq = (uint64_t)st.st_ino;
  printf("memfd ino=%llu\n", (unsigned long long)i_seq);

  /* pile 2048 threads on page[0] (pgoff 0, offset 0) */
  wait_addr = &page[0];
  pthread_t tids[2048];
  for (int i = 0; i < 2048; i++) pthread_create(&tids[i], NULL, do_wait, NULL);
  while (__atomic_load_n(&waiters_ready, __ATOMIC_SEQ_CST) < 2048) usleep(1000);
  __atomic_store_n(&go_flag, 1, __ATOMIC_SEQ_CST);
  usleep(200000); /* let them all park */

  uint64_t base = measure(&page[1]); /* empty bucket */
  printf("baseline wake ticks=%llu\n", (unsigned long long)base);
  /* candidates: 4096 pages x 4 offsets each, same inode */
  int slow[64];
  int nslow = 0;
  int cnt_slow = 0;
  for (int p = 1; p < 4096 && cnt_slow < 200; p++) {
    for (int o = 0; o < 4; o++) {
      uint64_t t = measure(&page[p * 1024 + o]);
      if (t > base * 10) {
        cnt_slow++;
        if (nslow < 64) { slow[nslow++] = p * 1024 + o; }
        if (cnt_slow <= 8)
          printf("SLOW idx=%d ticks=%llu\n", p * 1024 + o, (unsigned long long)t);
      }
    }
  }
  printf("total slow=%d\n", cnt_slow);
  printf("found %d slow candidates\n", nslow);

  /* userside check: slow candidates should share the bucket of page[0] */
  uint32_t bucket0 = shared_futex_hash(i_seq, 0, 0, hashsize);
  /* brute-force the kernel's i_seq: the correct value makes all slow
   * candidates agree with the pile bucket under the userside hash */
  uint32_t H = 2048;
  int best_agree = 0;
  uint64_t best_iseq = 0;
  for (uint64_t iseq = 0; iseq < 5000000; iseq++) {
    uint32_t b0 = shared_futex_hash(iseq, 0, 0, H);
    int agree = 0;
    for (int i = 0; i < nslow; i++) {
      int idx = slow[i];
      uint32_t b = shared_futex_hash(iseq, (idx / 1024), (idx % 1024) * 4, H);
      if (b == b0) agree++;
    }
    if (agree > best_agree) {
      best_agree = agree;
      best_iseq = iseq;
      printf("new best iseq=%llu agree=%d/%d\n",
             (unsigned long long)iseq, agree, nslow);
      if (agree == nslow) break;
    }
  }
  printf("BEST iseq=%llu agree=%d/%d (H=%u)\n",
         (unsigned long long)best_iseq, best_agree, nslow, H);

  /* wake everyone and exit */
  for (int i = 0; i < 4096 * 1024; i += 1024)
    futex_op(&page[i], FUTEX_WAKE, 2048, NULL, NULL, 0);
  return 0;
}
