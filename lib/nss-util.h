#include "nss.h"

bool init();
void shutdown();
void chacha20poly1305(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext,
                      int len, const uint8_t *aad, int aad_len,
                      const uint8_t *iv, const uint8_t *key);
void aes128gcm(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext, int len,
               const uint8_t *aad, int aad_len, const uint8_t *iv,
               const uint8_t *key);
