#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHR(x,n) ((x) >> (n))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(uint32_t state[], const uint8_t block[], int flag)
{
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t W[64];
    int i;

    for(i = 0; i < 16; i++)
    {
        W[i] = (block[i*4] << 24) | (block[i*4 + 1] << 16) | (block[i*4 + 2] << 8) | (block[i*4 + 3]);
    }

    for(; i < 64; i++)
    {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for(i = 0; i < 64; i++)
    {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    if(flag == 1)
    {
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    else
    {
        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;
    }
}

void sha256_init(uint32_t *state) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

void sha256_update(uint32_t *state, const uint8_t *data, size_t len) {
    size_t i;
    uint8_t current_block[64] = {0};
    size_t current_block_offset = 0;

    for (i = 0; i < len; ++i) {
        current_block[current_block_offset++] = data[i];
        if (current_block_offset == 64) {
            sha256_transform(state, (uint8_t*)current_block, 1);
            memset(current_block, 0, 64);
            current_block_offset = 0;
        }
    }

    // Padding
    current_block[current_block_offset++] = 0x80;
    if(current_block_offset > 56) {
        sha256_transform(state, (uint8_t*)current_block, 1);
        memset(current_block, 0, 64);
    }

    uint64_t total_bits = 8 * len;
    for (int j = 0; j < 8; ++j) {
        current_block[63-j] = total_bits & 0xFF;
        total_bits >>= 8;
    }
    sha256_transform(state, (uint8_t*)current_block, 1);
}

void sha256_final(uint32_t *state, uint8_t *out) {
    for(int i = 0; i < 8; i++) {
        out[i*4] = state[i] >> 24;
        out[i*4 + 1] = state[i] >> 16;
        out[i*4 + 2] = state[i] >> 8;
        out[i*4 + 3] = state[i];
    }
}

void sha256(uint8_t *out, const uint8_t *data, size_t len) {
    uint32_t state[8] = {0};
    sha256_init(state);
    sha256_update(state, data, len);
    sha256_final(state, out);
}

int main() {
    uint8_t hash[SHA256_DIGEST_SIZE];
    const char *data = "Hello, World!";
    printf("SHA-256 for the message: %s\n", data);
    sha256(hash, (uint8_t*)data, strlen(data));
    printf("Hash: ");
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    return 0;
}
