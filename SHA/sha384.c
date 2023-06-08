#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SHA384_DIGEST_SIZE 48

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x, n) ((x) >> (n))

#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7))
#define SIG1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6))

const uint64_t K_64[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha384_transform(uint64_t *state, const uint8_t *block) {
    uint64_t W[80], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for(i = 0; i < 16; i++) {
        W[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8 + 1] << 48) | ((uint64_t)block[i*8 + 2] << 40)
        | ((uint64_t)block[i*8 + 3] << 32) | ((uint64_t)block[i*8 + 4] << 24) | ((uint64_t)block[i*8 + 5] << 16)
        | ((uint64_t)block[i*8 + 6] << 8) | block[i*8 + 7];
    }

    for(; i < 80; i++) {
        W[i] = SIG1_64(W[i-2]) + W[i-7] + SIG0_64(W[i-15]) + W[i-16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for(i = 0; i < 80; i++) {
        t1 = h + EP1_64(e) + CH64(e, f, g) + K_64[i] + W[i];
        t2 = EP0_64(a) + MAJ64(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha384_init(uint64_t *state) {
    state[0] = 0xcbbb9d5dc1059ed8;
    state[1] = 0x629a292a367cd507;
    state[2] = 0x9159015a3070dd17;
    state[3] = 0x152fecd8f70e5939;
    state[4] = 0x67332667ffc00b31;
    state[5] = 0x8eb44a8768581511;
    state[6] = 0xdb0c2e0d64f98fa7;
    state[7] = 0x47b5481dbefa4fa4;
}

void sha384_update(uint64_t *state, const uint8_t *data, size_t len) {
    uint8_t block[128];
    size_t i;

    for(i = 0; i < len; i++) {
        block[i % 128] = data[i];
        if((i % 128) == 127)
            sha384_transform(state, block);
    }

    memset(block, 0, 128);
    memcpy(block, data + (len - len % 128), len % 128);

    block[len % 128] = 0x80;

    if(len % 128 > 111) {
        sha384_transform(state, block);
        memset(block, 0, 128);
    }

    block[128 - 1] = (uint8_t)(len * 8);
    block[128 - 2] = (uint8_t)(len >> 5);
    block[128 - 3] = (uint8_t)(len >> 13);
    block[128 - 4] = (uint8_t)(len >> 21);
    block[128 - 5] = (uint8_t)(len >> 29);
    sha384_transform(state, block);
}

void sha384_final(uint8_t *hash, uint64_t *state) {
    int i;
    for(i = 0; i < SHA384_DIGEST_SIZE / 8; i++) {
        hash[i*8] = (uint8_t)(state[i] >> 56);
        hash[i*8 + 1] = (uint8_t)(state[i] >> 48);
        hash[i*8 + 2] = (uint8_t)(state[i] >> 40);
        hash[i*8 + 3] = (uint8_t)(state[i] >> 32);
        hash[i*8 + 4] = (uint8_t)(state[i] >> 24);
        hash[i*8 + 5] = (uint8_t)(state[i] >> 16);
        hash[i*8 + 6] = (uint8_t)(state[i] >> 8);
        hash[i*8 + 7] = (uint8_t)state[i];
    }
}

int main() {
    uint64_t state[8];
    uint8_t hash[SHA384_DIGEST_SIZE];
    char *message = "Hello, World!";
    sha384_init(state);
    sha384_update(state, (uint8_t*)message, strlen(message));
    sha384_final(hash, state);

    printf("SHA-384(\"%s\") = ", message);
    for(int i = 0; i < SHA384_DIGEST_SIZE; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
