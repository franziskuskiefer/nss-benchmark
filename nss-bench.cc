
#include <ctime>
#include <iostream>
#include <nss/pk11pub.h>
#include <nss/pkcs11n.h>
#include <nss/seccomon.h>
#include <stdint.h>

#include "lib/nss-util.h"
#include "lib/rand.h"
#include "lib/time.h"

bool chachapoly() {
  uint8_t mac[16] = {0};
  uint32_t len = 0x10000;
  uint64_t res = 0;
  uint8_t plaintext[len] = {0};
  uint8_t ciphertext[len + 16] = {0};
  uint32_t rounds = 500;
  if (!(get_random(plaintext, len))) {
    return false;
  }

  uint8_t key[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                     0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                     0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
  uint8_t aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                     0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
  uint64_t a, b;
  clock_t t1, t2;

  t1 = clock();
  a = rdtsc();
  for (int i = 0; i < rounds; i++) {
    PK11SlotInfo *slot = PK11_GetInternalSlot();
    SECItem keyItem = {siBuffer, key, 32};

    PK11SymKey *symKey =
        PK11_ImportSymKey(slot, CKM_NSS_CHACHA20_POLY1305, PK11_OriginUnwrap,
                          CKA_ENCRYPT, &keyItem, nullptr);
    if (!symKey) {
      PK11_FreeSlot(slot);
      return false;
    }
    // Generate random IV.
    uint8_t iv[12];
    if (!(get_random(iv, 12))) {
      PK11_FreeSymKey(symKey);
      PK11_FreeSlot(slot);
      return false;
    }
    CK_NSS_AEAD_PARAMS aead_params;
    aead_params.pNonce = iv;
    aead_params.ulNonceLen = 12;
    aead_params.pAAD = aad;
    aead_params.ulAADLen = 12;
    aead_params.ulTagLen = 16;
    SECItem params = {siBuffer, reinterpret_cast<unsigned char *>(&aead_params),
                      sizeof(aead_params)};
    uint32_t outputLen;
    SECStatus rv =
        PK11_Encrypt(symKey, CKM_NSS_CHACHA20_POLY1305, &params, &ciphertext[0],
                     &outputLen, len + 16, plaintext, len);
    if (rv != SECSuccess) {
      PK11_FreeSymKey(symKey);
      PK11_FreeSlot(slot);
      return false;
    }
    memcpy(mac, ciphertext + len, 16);
    plaintext[0] = mac[0];
  }
  b = rdtsc();
  t2 = clock();
  uint64_t cycles = b - a;
  clock_t time = t2 - t1;
  std::cout << "ChachaPoly speed:\n"
            << cycles << " cycles\n"
            << time << " time" << std::endl;
  return true;
}

int main(int argc, char const *argv[]) {
  if (!init()) {
    return 1;
  }

  if (!chachapoly()) {
    return 1;
  }

  shutdown();
  return 0;
}