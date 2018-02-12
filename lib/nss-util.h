#include "nss.h"

bool init();
void shutdown();
void do_chacha20poly1305(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext,
                         int len, const uint8_t *aad, int aad_len,
                         const uint8_t *iv, const uint8_t *key);
void do_aesgcm(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext, int len,
               const uint8_t *aad, int aad_len, const uint8_t *iv,
               const uint8_t *key, size_t key_len);
void do_sha2(size_t output_len, uint8_t *input, int input_len, uint8_t *digest);
