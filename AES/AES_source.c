#include <stdio.h>
#include <stdint.h>

// S-box (SubBytes)
static const uint8_t s_box[256] = {
		  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// Inverse S-box (InvSubBytes)
static const uint8_t inv_s_box[256] = {
		    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// Rcon table for key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Helper functions
static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static uint32_t SubWord(uint32_t word) {
    uint32_t result = 0;
    result |= s_box[(word >> 24) & 0xFF] << 24;
    result |= s_box[(word >> 16) & 0xFF] << 16;
    result |= s_box[(word >> 8) & 0xFF] << 8;
    result |= s_box[word & 0xFF];
    return result;
}

// Key expansion
void AES_KeyExpansion(const uint8_t *key, uint32_t *key_schedule, int key_size) {
    int num_words = key_size / 32;  // Number of words in the initial key
    int key_schedule_size = (key_size == 128) ? 44 : (key_size == 192) ? 52 : 60;

    // Copy the initial key to the key schedule
    for (int i = 0; i < num_words; i++) {
        key_schedule[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    // Generate the remaining words in the key schedule
    for (int i = num_words; i < key_schedule_size; i++) {
        uint32_t temp = key_schedule[i - 1];

        if (i % num_words == 0) {
            temp = SubWord(RotWord(temp)) ^ (rcon[i / num_words] << 24);
        } else if (key_size == 256 && i % num_words == 4) {
            temp = SubWord(temp);
        }

        key_schedule[i] = key_schedule[i - num_words] ^ temp;
    }
}

void SubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = s_box[state[row][col]];
        }
    }
}

void InvSubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = inv_s_box[state[row][col]];
        }
    }
}

void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1 - Shift left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2 - Shift left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3 - Shift left by 3
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1 - Shift right by 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Row 2 - Shift right by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3 - Shift right by 3
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t carry;

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }

        carry = a & 0x80;
        a <<= 1;

        if (carry) {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        }

        b >>= 1;
    }

    return p;
}

void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int col = 0; col < 4; col++) {
        temp[0] = gmul(state[0][col], 0x02) ^ gmul(state[1][col], 0x03) ^ state[2][col] ^ state[3][col];
        temp[1] = state[0][col] ^ gmul(state[1][col], 0x02) ^ gmul(state[2][col], 0x03) ^ state[3][col];
        temp[2] = state[0][col] ^ state[1][col] ^ gmul(state[2][col], 0x02) ^ gmul(state[3][col], 0x03);
        temp[3] = gmul(state[0][col], 0x03) ^ state[1][col] ^ state[2][col] ^ gmul(state[3][col], 0x02);

        for (int row = 0; row < 4; row++) {
            state[row][col] = temp[row];
        }
    }
}

void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int col = 0; col < 4; col++) {
        temp[0] = gmul(state[0][col], 0x0E) ^ gmul(state[1][col], 0x0B) ^ gmul(state[2][col], 0x0D) ^ gmul(state[3][col], 0x09);
        temp[1] = gmul(state[0][col], 0x09) ^ gmul(state[1][col], 0x0E) ^ gmul(state[2][col], 0x0B) ^ gmul(state[3][col], 0x0D);
        temp[2] = gmul(state[0][col], 0x0D) ^ gmul(state[1][col], 0x09) ^ gmul(state[2][col], 0x0E) ^ gmul(state[3][col], 0x0B);
        temp[3] = gmul(state[0][col], 0x0B) ^ gmul(state[1][col], 0x0D) ^ gmul(state[2][col], 0x09) ^ gmul(state[3][col], 0x0E);

        for (int row = 0; row < 4; row++) {
            state[row][col] = temp[row];
        }
    }
}

void AddRoundKey(uint8_t state[4][4], const uint32_t *round_key) {
    for (int col = 0; col < 4; col++) {
        uint32_t key_word = round_key[col];

        for (int row = 0; row < 4; row++) {
            state[row][col] ^= (key_word >> (24 - 8 * row)) & 0xFF;
        }
    }
}

void AES_Encrypt(const uint8_t *plaintext, const uint8_t *key, uint8_t *ciphertext, int key_size) {
    uint8_t state[4][4];
    uint32_t key_schedule[60]; // Maximum size (for 256-bit key)

    // Initialize state array with input plaintext
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = plaintext[row + 4 * col];
        }
    }

    // Perform key expansion
    AES_KeyExpansion(key, key_schedule, key_size);

    // Initial AddRoundKey
    AddRoundKey(state, key_schedule);

    // Main rounds
    int num_rounds = (key_size == 128) ? 10 : (key_size == 192) ? 12 : 14;
    for (int round = 1; round < num_rounds; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, key_schedule + 4 * round);
    }

    // Final round (without MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key_schedule + 4 * num_rounds);

    // Copy state array to output ciphertext
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            ciphertext[row + 4 * col] = state[row][col];
        }
    }
}

void AES_Decrypt(const uint8_t *ciphertext, const uint8_t *key, uint8_t *plaintext, int key_size) {
    uint8_t state[4][4];
    uint32_t key_schedule[60]; // Maximum size (for 256-bit key)

    // Initialize state array with input ciphertext
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = ciphertext[row + 4 * col];
        }
    }

    // Perform key expansion
    AES_KeyExpansion(key, key_schedule, key_size);

    // Initial AddRoundKey
    int num_rounds = (key_size == 128) ? 10 : (key_size == 192) ? 12 : 14;
    AddRoundKey(state, key_schedule + 4 * num_rounds);

    // Main rounds
    for (int round = num_rounds - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, key_schedule + 4 * round);
        InvMixColumns(state);
    }

    // Final round (without InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key_schedule);

    // Copy state array to output plaintext
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            plaintext[row + 4 * col] = state[row][col];
        }
    }
}
int main(void)
{
    uint8_t key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    uint8_t plaintext_128[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // ct: 69c4e0d86a7b0430d8cdb78070b4c55a

    uint8_t ciphertext_128[16];
    uint8_t decrypted_128[16];

    AES_Encrypt(plaintext_128, key_128, ciphertext_128, 128);
    AES_Decrypt(ciphertext_128, key_128, decrypted_128, 128);

    printf("Plaintext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext_128[i]);
    }
    printf("\n");

    printf("Ciphertext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext_128[i]);
    }
    printf("\n");

    printf("Decrypted:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted_128[i]);
    }
    printf("\n");

    uint8_t key_192[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

    uint8_t plaintext_192[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // ct: dda97ca4864cdfe06eaf70a0ec0d7191

    uint8_t ciphertext_192[16];
    uint8_t decrypted_192[16];

    AES_Encrypt(plaintext_192, key_192, ciphertext_192, 192);
    AES_Decrypt(ciphertext_192, key_192, decrypted_192, 192);

    printf("Plaintext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext_192[i]);
    }
    printf("\n");

    printf("Ciphertext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext_192[i]);
    }
    printf("\n");

    printf("Decrypted:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted_192[i]);
    }
    printf("\n");

    uint8_t key_256[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    uint8_t plaintext_256[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // ct: 8ea2b7ca516745bfeafc49904b496089

    uint8_t ciphertext_256[16];
    uint8_t decrypted_256[16];

    AES_Encrypt(plaintext_256, key_256, ciphertext_256, 256);
    AES_Decrypt(ciphertext_256, key_256, decrypted_256, 256);

    printf("Plaintext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext_256[i]);
    }
    printf("\n");

    printf("Ciphertext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext_256[i]);
    }
    printf("\n");

    printf("Decrypted:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted_256[i]);
    }
    printf("\n");

    return 0;
}
