// TAU-256: 256-bit SPN cipher (educational). Uses pre-generated S-boxes.
// Build: make (see Makefile)

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "tau256_sboxes.h" // provides S_PI, S_LN2, INV_S_PI, INV_S_LN2

#define ROWS 4
#define COLS 8

static inline uint8_t xtime(uint8_t a) { return (uint8_t)((a<<1) ^ ((a&0x80)?0x1B:0x00)); }

static uint8_t gf_mul(uint8_t a, uint8_t b){
  uint8_t res = 0;
  while (b){
    if (b & 1) res ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return res;
}

static void add_round_key(uint8_t st[ROWS][COLS], const uint8_t rk[32]){
  for (int c=0;c<COLS;c++){
    for (int r=0;r<ROWS;r++){
      st[r][c] ^= rk[c*4 + r];
    }
  }
}

static void sub_bytes(uint8_t st[ROWS][COLS]){
  for (int c=0;c<COLS;c++){
    const uint8_t *S = (c % 2 == 0) ? S_PI : S_LN2;
    for (int r=0;r<ROWS;r++){
      st[r][c] = S[ st[r][c] ];
    }
  }
}

static void inv_sub_bytes(uint8_t st[ROWS][COLS]){
  for (int c=0;c<COLS;c++){
    const uint8_t *S = (c % 2 == 0) ? INV_S_PI : INV_S_LN2;
    for (int r=0;r<ROWS;r++){
      st[r][c] = S[ st[r][c] ];
    }
  }
}

static void shift_rows(uint8_t st[ROWS][COLS]){
  uint8_t tmp[COLS];
  for (int r=0;r<ROWS;r++){
    int sh = r % COLS;
    for (int c=0;c<COLS;c++) tmp[c] = st[r][(c+sh) % COLS];
    for (int c=0;c<COLS;c++) st[r][c] = tmp[c];
  }
}

static void inv_shift_rows(uint8_t st[ROWS][COLS]){
  uint8_t tmp[COLS];
  for (int r=0;r<ROWS;r++){
    int sh = r % COLS;
    for (int c=0;c<COLS;c++) tmp[(c+sh)%COLS] = st[r][c];
    for (int c=0;c<COLS;c++) st[r][c] = tmp[c];
  }
}

static void mix_single_column(uint8_t a[4]){
  uint8_t t0 = gf_mul(0x02,a[0]) ^ gf_mul(0x03,a[1]) ^ a[2] ^ a[3];
  uint8_t t1 = a[0] ^ gf_mul(0x02,a[1]) ^ gf_mul(0x03,a[2]) ^ a[3];
  uint8_t t2 = a[0] ^ a[1] ^ gf_mul(0x02,a[2]) ^ gf_mul(0x03,a[3]);
  uint8_t t3 = gf_mul(0x03,a[0]) ^ a[1] ^ a[2] ^ gf_mul(0x02,a[3]);
  a[0]=t0; a[1]=t1; a[2]=t2; a[3]=t3;
}

static void inv_mix_single_column(uint8_t a[4]){
  uint8_t t0 = gf_mul(0x0e,a[0]) ^ gf_mul(0x0b,a[1]) ^ gf_mul(0x0d,a[2]) ^ gf_mul(0x09,a[3]);
  uint8_t t1 = gf_mul(0x09,a[0]) ^ gf_mul(0x0e,a[1]) ^ gf_mul(0x0b,a[2]) ^ gf_mul(0x0d,a[3]);
  uint8_t t2 = gf_mul(0x0d,a[0]) ^ gf_mul(0x09,a[1]) ^ gf_mul(0x0e,a[2]) ^ gf_mul(0x0b,a[3]);
  uint8_t t3 = gf_mul(0x0b,a[0]) ^ gf_mul(0x0d,a[1]) ^ gf_mul(0x09,a[2]) ^ gf_mul(0x0e,a[3]);
  a[0]=t0; a[1]=t1; a[2]=t2; a[3]=t3;
}

static void mix_columns(uint8_t st[ROWS][COLS]){
  for (int c=0;c<COLS;c++){
    uint8_t col[4] = { st[0][c], st[1][c], st[2][c], st[3][c] };
    mix_single_column(col);
    st[0][c]=col[0]; st[1][c]=col[1]; st[2][c]=col[2]; st[3][c]=col[3];
  }
}

static void inv_mix_columns(uint8_t st[ROWS][COLS]){
  for (int c=0;c<COLS;c++){
    uint8_t col[4] = { st[0][c], st[1][c], st[2][c], st[3][c] };
    inv_mix_single_column(col);
    st[0][c]=col[0]; st[1][c]=col[1]; st[2][c]=col[2]; st[3][c]=col[3];
  }
}

static uint8_t rcon_value(uint8_t i){
  uint8_t r = 1;
  if (i==0) return 0;
  while (--i) r = xtime(r);
  return r;
}

static uint32_t pack_be(const uint8_t b[4]){
  return ((uint32_t)b[0]<<24) | ((uint32_t)b[1]<<16) | ((uint32_t)b[2]<<8) | (uint32_t)b[3];
}

static void unpack_be(uint32_t w, uint8_t b[4]){
  b[0] = (uint8_t)(w>>24); b[1] = (uint8_t)(w>>16); b[2] = (uint8_t)(w>>8); b[3] = (uint8_t)w;
}

static uint32_t rotword(uint32_t w){ return (w<<8) | (w>>24); }

static uint32_t subword_pi(uint32_t w){
  uint8_t b[4]; unpack_be(w,b);
  b[0]=S_PI[b[0]]; b[1]=S_PI[b[1]]; b[2]=S_PI[b[2]]; b[3]=S_PI[b[3]];
  return pack_be(b);
}

// Expand key: roundkeys[17][32]
static void tau256_key_expand(const uint8_t key[32], uint8_t roundkeys[17][32]){
  const int Nb = 8, Nk = 8, Nr = 16, Nw = Nb*(Nr+1);
  uint32_t W[136];
  for (int i=0;i<Nk;i++){
    W[i] = pack_be(&key[4*i]);
  }
  for (int i=Nk;i<Nw;i++){
    uint32_t temp = W[i-1];
    if (i % Nk == 0){
      temp = subword_pi(rotword(temp)) ^ ((uint32_t)rcon_value((uint8_t)(i/Nk)) << 24);
    } else if (Nk > 6 && (i % Nk) == 4){
      temp = subword_pi(temp);
    }
    W[i] = W[i - Nk] ^ temp;
  }
  for (int r=0;r<=Nr;r++){
    for (int c=0;c<Nb;c++){
      uint8_t b[4]; unpack_be(W[r*Nb + c], b);
      roundkeys[r][4*c+0]=b[0]; roundkeys[r][4*c+1]=b[1];
      roundkeys[r][4*c+2]=b[2]; roundkeys[r][4*c+3]=b[3];
    }
  }
}

static void tau256_encrypt_block(const uint8_t in[32], uint8_t out[32], const uint8_t rk[17][32]){
  uint8_t st[ROWS][COLS];
  for (int c=0;c<COLS;c++)
    for (int r=0;r<ROWS;r++)
      st[r][c] = in[c*4 + r];
  add_round_key(st, rk[0]);
  for (int rnd=1; rnd<=16; rnd++){
    sub_bytes(st);
    shift_rows(st);
    if (rnd != 16) mix_columns(st);
    add_round_key(st, rk[rnd]);
  }
  for (int c=0;c<COLS;c++)
    for (int r=0;r<ROWS;r++)
      out[c*4 + r] = st[r][c];
}

static void tau256_decrypt_block(const uint8_t in[32], uint8_t out[32], const uint8_t rk[17][32]){
  uint8_t st[ROWS][COLS];
  for (int c=0;c<COLS;c++)
    for (int r=0;r<ROWS;r++)
      st[r][c] = in[c*4 + r];
  add_round_key(st, rk[16]);
  for (int rnd=15; rnd>=1; rnd--){
    inv_shift_rows(st);
    inv_sub_bytes(st);
    add_round_key(st, rk[rnd]);
    inv_mix_columns(st);
  }
  inv_shift_rows(st);
  inv_sub_bytes(st);
  add_round_key(st, rk[0]);
  for (int c=0;c<COLS;c++)
    for (int r=0;r<ROWS;r++)
      out[c*4 + r] = st[r][c];
}

static void hex(const uint8_t *x, size_t n){
  for (size_t i=0;i<n;i++) printf("%02x", x[i]);
}

int main(void){
  uint8_t key[32] = {3};
  uint8_t pt [32] = {0};
  uint8_t ct [32], dec[32];
  uint8_t rk[17][32];

  tau256_key_expand(key, rk);
  tau256_encrypt_block(pt, ct, rk);
  tau256_decrypt_block(ct, dec, rk);

  printf("key: "); hex(key,32); puts("");
  printf("pt : "); hex(pt,32); puts("");
  printf("ct : "); hex(ct,32); puts("");
  printf("ok : %s\n", memcmp(pt,dec,32)==0 ? "yes" : "NO");
  return 0;
}
