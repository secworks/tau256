// TAU-256: 256-bit SPN cipher with 256-bit block.
// Uses pre-generated S-boxes.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "tau256_sboxes.h" // provides S_PI, S_LN2, INV_S_PI, INV_S_LN2

#define ROWS 4
#define COLS 8
#define WORDS 8
#define ROUNDS 16
#define ROUNDKEYS (ROUNDS + 1)

static inline uint8_t xtime(uint8_t a) {
  return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t res = 0;
  while (b) {
    if (b & 1) res ^= a;
    {
      uint8_t hi = a & 0x80;
      a <<= 1;
      if (hi) a ^= 0x1B;
    }
    b >>= 1;
  }
  return res;
}

static uint32_t pack_be(const uint8_t b[4]) {
  return ((uint32_t)b[0] << 24) |
         ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8)  |
         (uint32_t)b[3];
}

static void unpack_be(uint32_t w, uint8_t b[4]) {
  b[0] = (uint8_t)(w >> 24);
  b[1] = (uint8_t)(w >> 16);
  b[2] = (uint8_t)(w >> 8);
  b[3] = (uint8_t)(w);
}

static uint32_t rotword(uint32_t w) {
  return (w << 8) | (w >> 24);
}

static uint32_t subword_pi(uint32_t w) {
  uint8_t b[4];
  unpack_be(w, b);
  b[0] = S_PI[b[0]];
  b[1] = S_PI[b[1]];
  b[2] = S_PI[b[2]];
  b[3] = S_PI[b[3]];
  return pack_be(b);
}

static uint8_t rcon_value(uint8_t i) {
  uint8_t r = 1;
  if (i == 0) return 0;
  while (--i) r = xtime(r);
  return r;
}

static void words_to_state(const uint32_t in[WORDS], uint8_t st[ROWS][COLS]) {
  for (int c = 0; c < COLS; c++) {
    uint8_t b[4];
    unpack_be(in[c], b);
    st[0][c] = b[0];
    st[1][c] = b[1];
    st[2][c] = b[2];
    st[3][c] = b[3];
  }
}

static void state_to_words(const uint8_t st[ROWS][COLS], uint32_t out[WORDS]) {
  for (int c = 0; c < COLS; c++) {
    uint8_t b[4];
    b[0] = st[0][c];
    b[1] = st[1][c];
    b[2] = st[2][c];
    b[3] = st[3][c];
    out[c] = pack_be(b);
  }
}

static void add_round_key(uint8_t st[ROWS][COLS], const uint32_t rk[WORDS]) {
  for (int c = 0; c < COLS; c++) {
    uint8_t b[4];
    unpack_be(rk[c], b);
    st[0][c] ^= b[0];
    st[1][c] ^= b[1];
    st[2][c] ^= b[2];
    st[3][c] ^= b[3];
  }
}

static void sub_bytes(uint8_t st[ROWS][COLS]) {
  for (int c = 0; c < COLS; c++) {
    const uint8_t *S = (c % 2 == 0) ? S_PI : S_LN2;
    for (int r = 0; r < ROWS; r++) {
      st[r][c] = S[st[r][c]];
    }
  }
}

static void inv_sub_bytes(uint8_t st[ROWS][COLS]) {
  for (int c = 0; c < COLS; c++) {
    const uint8_t *S = (c % 2 == 0) ? INV_S_PI : INV_S_LN2;
    for (int r = 0; r < ROWS; r++) {
      st[r][c] = S[st[r][c]];
    }
  }
}

static void shift_rows(uint8_t st[ROWS][COLS]) {
  uint8_t tmp[COLS];
  for (int r = 0; r < ROWS; r++) {
    int sh = r % COLS;
    for (int c = 0; c < COLS; c++) tmp[c] = st[r][(c + sh) % COLS];
    for (int c = 0; c < COLS; c++) st[r][c] = tmp[c];
  }
}

static void inv_shift_rows(uint8_t st[ROWS][COLS]) {
  uint8_t tmp[COLS];
  for (int r = 0; r < ROWS; r++) {
    int sh = r % COLS;
    for (int c = 0; c < COLS; c++) tmp[(c + sh) % COLS] = st[r][c];
    for (int c = 0; c < COLS; c++) st[r][c] = tmp[c];
  }
}

static void mix_single_column(uint8_t a[4]) {
  uint8_t t0 = gf_mul(0x02, a[0]) ^ gf_mul(0x03, a[1]) ^ a[2] ^ a[3];
  uint8_t t1 = a[0] ^ gf_mul(0x02, a[1]) ^ gf_mul(0x03, a[2]) ^ a[3];
  uint8_t t2 = a[0] ^ a[1] ^ gf_mul(0x02, a[2]) ^ gf_mul(0x03, a[3]);
  uint8_t t3 = gf_mul(0x03, a[0]) ^ a[1] ^ a[2] ^ gf_mul(0x02, a[3]);
  a[0] = t0; a[1] = t1; a[2] = t2; a[3] = t3;
}

static void inv_mix_single_column(uint8_t a[4]) {
  uint8_t t0 = gf_mul(0x0e, a[0]) ^ gf_mul(0x0b, a[1]) ^ gf_mul(0x0d, a[2]) ^ gf_mul(0x09, a[3]);
  uint8_t t1 = gf_mul(0x09, a[0]) ^ gf_mul(0x0e, a[1]) ^ gf_mul(0x0b, a[2]) ^ gf_mul(0x0d, a[3]);
  uint8_t t2 = gf_mul(0x0d, a[0]) ^ gf_mul(0x09, a[1]) ^ gf_mul(0x0e, a[2]) ^ gf_mul(0x0b, a[3]);
  uint8_t t3 = gf_mul(0x0b, a[0]) ^ gf_mul(0x0d, a[1]) ^ gf_mul(0x09, a[2]) ^ gf_mul(0x0e, a[3]);
  a[0] = t0; a[1] = t1; a[2] = t2; a[3] = t3;
}

static void mix_columns(uint8_t st[ROWS][COLS]) {
  for (int c = 0; c < COLS; c++) {
    uint8_t col[4] = { st[0][c], st[1][c], st[2][c], st[3][c] };
    mix_single_column(col);
    st[0][c] = col[0];
    st[1][c] = col[1];
    st[2][c] = col[2];
    st[3][c] = col[3];
  }
}

static void inv_mix_columns(uint8_t st[ROWS][COLS]) {
  for (int c = 0; c < COLS; c++) {
    uint8_t col[4] = { st[0][c], st[1][c], st[2][c], st[3][c] };
    inv_mix_single_column(col);
    st[0][c] = col[0];
    st[1][c] = col[1];
    st[2][c] = col[2];
    st[3][c] = col[3];
  }
}

// Expand key: roundkeys[17][8]
static void tau256_key_expand(const uint32_t key[WORDS], uint32_t roundkeys[ROUNDKEYS][WORDS]) {
  const int Nb = 8, Nk = 8, Nr = 16, Nw = Nb * (Nr + 1);
  uint32_t W[136];

  for (int i = 0; i < Nk; i++) {
    W[i] = key[i];
  }

  for (int i = Nk; i < Nw; i++) {
    uint32_t temp = W[i - 1];
    if ((i % Nk) == 0) {
      temp = subword_pi(rotword(temp)) ^ ((uint32_t)rcon_value((uint8_t)(i / Nk)) << 24);
    } else if (Nk > 6 && (i % Nk) == 4) {
      temp = subword_pi(temp);
    }
    W[i] = W[i - Nk] ^ temp;
  }

  for (int r = 0; r <= Nr; r++) {
    for (int c = 0; c < Nb; c++) {
      roundkeys[r][c] = W[r * Nb + c];
    }
  }
}

static void tau256_encrypt_block(const uint32_t in[WORDS], uint32_t out[WORDS],
                                 const uint32_t rk[ROUNDKEYS][WORDS]) {
  uint8_t st[ROWS][COLS];

  words_to_state(in, st);

  add_round_key(st, rk[0]);

  for (int rnd = 1; rnd <= ROUNDS; rnd++) {
    sub_bytes(st);
    shift_rows(st);
    if (rnd != ROUNDS) mix_columns(st);
    add_round_key(st, rk[rnd]);
  }

  state_to_words(st, out);
}

static void tau256_decrypt_block(const uint32_t in[WORDS], uint32_t out[WORDS],
                                 const uint32_t rk[ROUNDKEYS][WORDS]) {
  uint8_t st[ROWS][COLS];

  words_to_state(in, st);

  add_round_key(st, rk[ROUNDS]);

  for (int rnd = ROUNDS - 1; rnd >= 1; rnd--) {
    inv_shift_rows(st);
    inv_sub_bytes(st);
    add_round_key(st, rk[rnd]);
    inv_mix_columns(st);
  }

  inv_shift_rows(st);
  inv_sub_bytes(st);
  add_round_key(st, rk[0]);

  state_to_words(st, out);
}

static void hex_words(const uint32_t *x, size_t nwords) {
  for (size_t i = 0; i < nwords; i++) {
    printf("%08x", x[i]);
  }
}

static int run_test(const char *name, const uint32_t key[WORDS], const uint32_t pt[WORDS]) {
  uint32_t rk[ROUNDKEYS][WORDS];
  uint32_t ct[WORDS];
  uint32_t dec[WORDS];

  tau256_key_expand(key, rk);
  tau256_encrypt_block(pt, ct, rk);
  tau256_decrypt_block(ct, dec, rk);

  printf("%s\n", name);
  printf("key: "); hex_words(key, WORDS); puts("");
  printf("pt : "); hex_words(pt,  WORDS); puts("");
  printf("ct : "); hex_words(ct,  WORDS); puts("");
  printf("dec: "); hex_words(dec, WORDS); puts("");
  printf("ok : %s\n\n", (memcmp(pt, dec, sizeof(dec)) == 0) ? "yes" : "NO");

  return (memcmp(pt, dec, sizeof(dec)) == 0) ? 0 : 1;
}

int main(void) {
  int errors = 0;

  // Key 0: same byte layout as original code: uint8_t key[32] = {3};
  // i.e. bytes = 03 00 00 00 00 ... 00
  static const uint32_t key0[WORDS] = {
    0x03000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
  };

  // Key 1: new nontrivial 256-bit key
  static const uint32_t key1[WORDS] = {
    0x00112233u, 0x44556677u, 0x8899aabbu, 0xccddeeffu,
    0x0f1e2d3cu, 0x4b5a6978u, 0x8796a5b4u, 0xc3d2e1f0u
  };

  // Plaintext 0: zero block
  static const uint32_t pt0[WORDS] = {
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
  };

  // Plaintext 1: new non-zero block
  static const uint32_t pt1[WORDS] = {
    0x00112233u, 0x44556677u, 0x8899aabbu, 0xccddeeffu,
    0x10213243u, 0x54657687u, 0x98a9bacbu, 0xdcedfe0fu
  };

  errors += run_test("TEST 1: key0, pt0", key0, pt0);
  errors += run_test("TEST 2: key0, pt1", key0, pt1);
  errors += run_test("TEST 3: key1, pt0", key1, pt0);
  errors += run_test("TEST 4: key1, pt1", key1, pt1);

  return errors ? 1 : 0;
}
