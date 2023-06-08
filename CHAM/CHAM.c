#include <stdio.h>
#include <stdint.h>

// Macro constants
#define BLOCK_SIZE_64_128 4
#define KEY_SIZE_64_128 8
#define ROUNDS_64_128 88

#define BLOCK_SIZE_128_128 4
#define KEY_SIZE_128_128 4
#define ROUNDS_128_128 112

#define BLOCK_SIZE_128_256 4
#define KEY_SIZE_128_256 8
#define ROUNDS_128_256 120

// Prototype function declarations
void cham64_128_key_schedule(const uint16_t *key, uint16_t *round_keys);
void cham64_128_encrypt(const uint16_t plaintext[BLOCK_SIZE_64_128], uint16_t ciphertext[BLOCK_SIZE_64_128], const uint16_t round_keys[KEY_SIZE_64_128 * 2]);
void cham128_128_key_schedule(const uint32_t *key, uint32_t *round_keys);
void cham128_128_encrypt(const uint32_t plaintext[BLOCK_SIZE_128_128], uint32_t ciphertext[BLOCK_SIZE_128_128], const uint32_t round_keys[KEY_SIZE_128_128 * 2]);
void cham128_256_key_schedule(const uint32_t *key, uint32_t *round_keys);
void cham128_256_encrypt(const uint32_t plaintext[BLOCK_SIZE_128_256], uint32_t ciphertext[BLOCK_SIZE_128_256], const uint32_t round_keys[KEY_SIZE_128_256 * 2]);

int main() {
    // CHAM-64/128 test
    uint16_t secret_key_64_128[KEY_SIZE_64_128] = {0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0b0a, 0x0d0c, 0x0f0e};
    uint16_t plaintext_64_128[BLOCK_SIZE_64_128] = {0x1100, 0x3322, 0x5544, 0x7766};
    uint16_t round_keys_64_128[KEY_SIZE_64_128 * 2];
    uint16_t ciphertext_64_128[BLOCK_SIZE_64_128];

    cham64_128_key_schedule(secret_key_64_128, round_keys_64_128);
    cham64_128_encrypt(plaintext_64_128, ciphertext_64_128, round_keys_64_128);

    printf("CHAM-64/128\n");
    printf("Secret Key: ");
    for (int i = 0; i < KEY_SIZE_64_128; i++) {
        printf("%04x ", secret_key_64_128[i]);
    }
    printf("\nPlaintext: ");
    for (int i = 0; i < BLOCK_SIZE_64_128; i++) {
        printf("%04x ", plaintext_64_128[i]);
    }
    printf("\nRound Keys: ");
    for (int i = 0; i < KEY_SIZE_64_128 * 2; i++) {
        printf("%04x ", round_keys_64_128[i]);
    }
    printf("\nCiphertext: ");
    for (int i = 0; i < BLOCK_SIZE_64_128; i++) {
        printf("%04x ", ciphertext_64_128[i]);
    }
    printf("\n\n");

    // CHAM-128/128 test
    uint32_t secret_key_128_128[KEY_SIZE_128_128] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};
    uint32_t plaintext_128_128[BLOCK_SIZE_128_128] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
    uint32_t round_keys_128_128[KEY_SIZE_128_128 * 2];
    uint32_t ciphertext_128_128[BLOCK_SIZE_128_128];

    cham128_128_key_schedule(secret_key_128_128, round_keys_128_128);
    cham128_128_encrypt(plaintext_128_128, ciphertext_128_128, round_keys_128_128);

    printf("CHAM-128/128\n");
    printf("Secret Key: ");
    for (int i = 0; i < KEY_SIZE_128_128; i++) {
        printf("%08x ", secret_key_128_128[i]);
    }
    printf("\nPlaintext: ");
    for (int i = 0; i < BLOCK_SIZE_128_128; i++) {
        printf("%08x ", plaintext_128_128[i]);
    }
    printf("\nRound Keys: ");
    for (int i = 0; i < KEY_SIZE_128_128 * 2; i++) {
        printf("%08x ", round_keys_128_128[i]);
    }
    printf("\nCiphertext: ");
    for (int i = 0; i < BLOCK_SIZE_128_128; i++) {
        printf("%08x ", ciphertext_128_128[i]);
    }
    printf("\n\n");

    // CHAM-128/256 test
    uint32_t secret_key_128_256[KEY_SIZE_128_256] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc};
    uint32_t plaintext_128_256[BLOCK_SIZE_128_256] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
    uint32_t round_keys_128_256[KEY_SIZE_128_256 * 2];
    uint32_t ciphertext_128_256[BLOCK_SIZE_128_256];

    cham128_256_key_schedule(secret_key_128_256, round_keys_128_256);
    cham128_256_encrypt(plaintext_128_256, ciphertext_128_256, round_keys_128_256);

    printf("CHAM-128/256\n");
    printf("Secret Key: ");
    for (int i = 0; i < KEY_SIZE_128_256; i++) {
        printf("%08x ", secret_key_128_256[i]);
    }
    printf("\nPlaintext: ");
    for (int i = 0; i < BLOCK_SIZE_128_256; i++) {
        printf("%08x ", plaintext_128_256[i]);
    }
    printf("\nRound Keys: ");
    for (int i = 0; i < KEY_SIZE_128_256 * 2; i++) {
        printf("%08x ", round_keys_128_256[i]);
    }
    printf("\nCiphertext: ");
    for (int i = 0; i < BLOCK_SIZE_128_256; i++) {
        printf("%08x ", ciphertext_128_256[i]);
    }
    printf("\n");

    return 0;
}

// CHAM-64/128 functions
void cham64_128_key_schedule(const uint16_t *key, uint16_t *round_keys) {
    for (int i = 0; i < KEY_SIZE_64_128; i++) {
        round_keys[i] = key[i] ^ ((key[i] << 1) | (key[i] >> (16 - 1))) ^ ((key[i] << 8) | (key[i] >> (16 - 8)));
        round_keys[(i + KEY_SIZE_64_128) ^ 1] = key[i] ^ ((key[i] << 1) | (key[i] >> (16 - 1))) ^ ((key[i] << 11) | (key[i] >> (16 - 11)));
    }
}

void cham64_128_encrypt(const uint16_t plaintext[BLOCK_SIZE_64_128], uint16_t ciphertext[BLOCK_SIZE_64_128], const uint16_t round_keys[KEY_SIZE_64_128 * 2]) {
    for (int i = 0; i < BLOCK_SIZE_64_128; i++) {
        ciphertext[i] = plaintext[i];
    }

    for (int round = 0; round < ROUNDS_64_128; round++) {
        uint16_t x = ciphertext[0], y = ciphertext[1];

        if (round % 2 == 0) {
            x ^= round;
            y = (y << 1) | (y >> 15);
        } else {
            x ^= round;
            y = (y << 8) | (y >> 8);
        }

        uint16_t temp = x + (y ^ round_keys[round % (KEY_SIZE_64_128 * 2)]);

        if (round % 2 == 0) {
            temp = (temp << 8) | (temp >> 8);
        } else {
            temp = (temp << 1) | (temp >> 15);
        }

        ciphertext[0] = temp;

        // Rotate words
        uint16_t temp_word = ciphertext[0];
        ciphertext[0] = ciphertext[1];
        ciphertext[1] = ciphertext[2];
        ciphertext[2] = ciphertext[3];
        ciphertext[3] = temp_word;
    }
}

// CHAM-128/128 functions
void cham128_128_key_schedule(const uint32_t *key, uint32_t *round_keys) {
    for (int i = 0; i < KEY_SIZE_128_128; i++) {
        round_keys[i] = key[i] ^ ((key[i] << 1) | (key[i] >> (32 - 1))) ^ ((key[i] << 8) | (key[i] >> (32 - 8)));
        round_keys[(i + KEY_SIZE_128_128) ^ 1] = key[i] ^ ((key[i] << 1) | (key[i] >> (32 - 1))) ^ ((key[i] << 11) | (key[i] >> (32 - 11)));
    }
}

void cham128_128_encrypt(const uint32_t plaintext[BLOCK_SIZE_128_128], uint32_t ciphertext[BLOCK_SIZE_128_128], const uint32_t round_keys[KEY_SIZE_128_128 * 2]) {
    for (int i = 0; i < BLOCK_SIZE_128_128; i++) {
        ciphertext[i] = plaintext[i];
    }

    for (int round = 0; round < ROUNDS_128_128; round++) {
        uint32_t x = ciphertext[0], y = ciphertext[1];

        if (round % 2 == 0) {
            x ^= round;
            y = (y << 1) | (y >> 31);
        } else {
            x ^= round;
            y = (y << 8) | (y >> 24);
        }

        uint32_t temp = x + (y ^ round_keys[round % (KEY_SIZE_128_128 * 2)]);

        if (round % 2 == 0) {
            temp = (temp << 8) | (temp >> 24);
        } else {
            temp = (temp << 1) | (temp >> 31);
        }

        ciphertext[0] = temp;

        // Rotate words
        uint32_t temp_word = ciphertext[0];
        ciphertext[0] = ciphertext[1];
        ciphertext[1] = ciphertext[2];
        ciphertext[2] = ciphertext[3];
        ciphertext[3] = temp_word;
    }
}

// CHAM-128/256 functions
void cham128_256_key_schedule(const uint32_t *key, uint32_t *round_keys) {
    for (int i = 0; i < KEY_SIZE_128_256; i++) {
        round_keys[i] = key[i] ^ ((key[i] << 1) | (key[i] >> (32 - 1))) ^ ((key[i] << 8) | (key[i] >> (32 - 8)));
        round_keys[(i + KEY_SIZE_128_256) ^ 1] = key[i] ^ ((key[i] << 1) | (key[i] >> (32 - 1))) ^ ((key[i] << 11) | (key[i] >> (32 - 11)));
    }
}

void cham128_256_encrypt(const uint32_t plaintext[BLOCK_SIZE_128_256], uint32_t ciphertext[BLOCK_SIZE_128_256], const uint32_t round_keys[KEY_SIZE_128_256 * 2]) {
    for (int i = 0; i < BLOCK_SIZE_128_256; i++) {
        ciphertext[i] = plaintext[i];
    }

    for (int round = 0; round < ROUNDS_128_256; round++) {
        uint32_t x = ciphertext[0], y = ciphertext[1];

        if (round % 2 == 0) {
            x ^= round;
            y = (y << 1) | (y >> 31);
        } else {
            x ^= round;
            y = (y << 8) | (y >> 24);
        }

        uint32_t temp = x + (y ^ round_keys[round % (KEY_SIZE_128_256 * 2)]);

        if (round % 2 == 0) {
            temp = (temp << 8) | (temp >> 24);
        } else {
            temp = (temp << 1) | (temp >> 31);
        }

        ciphertext[0] = temp;

        // Rotate words
        uint32_t temp_word = ciphertext[0];
        ciphertext[0] = ciphertext[1];
        ciphertext[1] = ciphertext[2];
        ciphertext[2] = ciphertext[3];
        ciphertext[3] = temp_word;
    }
}




