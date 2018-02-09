#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/pkcs11n.h>
#include <nss/seccomon.h>

#include "nss.h"

bool init() {
  SECStatus rv = NSS_NoDB_Init("");
  if (rv != SECSuccess) {
    return false;
  }
  return true;
}

void shutdown() { (void)NSS_Shutdown(); }

void chacha20poly1305(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext,
                      int len, const uint8_t *aad, int aad_len,
                      const uint8_t *iv, const uint8_t *key) {
  PK11SlotInfo *slot = PK11_GetInternalSlot();
  SECItem keyItem = {siBuffer, const_cast<unsigned char *>(key), 32};

  PK11SymKey *symKey =
      PK11_ImportSymKey(slot, CKM_NSS_CHACHA20_POLY1305, PK11_OriginUnwrap,
                        CKA_ENCRYPT, &keyItem, nullptr);
  if (!symKey) {
    PK11_FreeSlot(slot);
    return;
  }
  CK_NSS_AEAD_PARAMS aead_params;
  aead_params.pNonce = const_cast<unsigned char *>(iv);
  aead_params.ulNonceLen = 12;
  aead_params.pAAD = const_cast<unsigned char *>(aad);
  aead_params.ulAADLen = aad_len;
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
    return;
  }
  memcpy(mac, ciphertext + len, 16);
}

void aesgcm(uint8_t *ciphertext, uint8_t *mac, uint8_t *plaintext, int len,
            const uint8_t *aad, int aad_len, const uint8_t *iv,
            const uint8_t *key, size_t key_len) {
  PK11SlotInfo *slot = PK11_GetInternalSlot();
  SECItem keyItem = {siBuffer, const_cast<unsigned char *>(key),
                     static_cast<unsigned int>(key_len)};

  PK11SymKey *symKey = PK11_ImportSymKey(slot, CKM_AES_GCM, PK11_OriginUnwrap,
                                         CKA_ENCRYPT, &keyItem, nullptr);
  if (!symKey) {
    PK11_FreeSlot(slot);
    return;
  }
  CK_GCM_PARAMS gcmParams;
  gcmParams.pIv = const_cast<unsigned char *>(iv);
  gcmParams.ulIvLen = 12;
  gcmParams.pAAD = const_cast<unsigned char *>(aad);
  gcmParams.ulAADLen = aad_len;
  gcmParams.ulTagBits = 128;
  SECItem params = {siBuffer, reinterpret_cast<unsigned char *>(&gcmParams),
                    sizeof(gcmParams)};
  uint32_t outputLen;
  SECStatus rv = PK11_Encrypt(symKey, CKM_AES_GCM, &params, &ciphertext[0],
                              &outputLen, len + 16, plaintext, len);
  if (rv != SECSuccess) {
    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    return;
  }
  memcpy(mac, ciphertext + len, 16);
}
