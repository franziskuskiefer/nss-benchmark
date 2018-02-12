
#include <iostream>
#include <nss/pk11pub.h>
#include <nss/pkcs11n.h>
#include <nss/seccomon.h>
#include <stdint.h>

#include "aead.h"
#include "lib/rand.h"
#include "lib/time.h"
#include "lib/nss-util.h"

static const uint8_t key[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
static const uint8_t aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                                0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
static const uint8_t nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                                  0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

static const uint32_t rounds = 5000;
static const uint32_t plaintext_len = 0x10000;

bool aesgcm(size_t key_len) {
  uint8_t mac[16] = {0};
  uint8_t plaintext[plaintext_len] = {0};
  uint8_t ciphertext[plaintext_len + 16] = {0};
  if (!(get_random(plaintext, plaintext_len))) {
    return false;
  }
  uint64_t a, b;
  clock_t t1, t2;

  t1 = clock();
  a = rdtsc();
  for (uint32_t i = 0; i < rounds; i++) {
    do_aesgcm(ciphertext, mac, plaintext, plaintext_len, aad, 12, nonce, key,
              key_len);
    plaintext[0] = mac[0];
  }
  b = rdtsc();
  t2 = clock();
  uint64_t cycles = b - a;
  clock_t time = t2 - t1;
  std::cout << "AES" << (key_len << 3) << "-GCM speed:\n"
            << cycles << " cycles\n"
            << time << " time" << std::endl
            << std::endl;
  return true;
}

bool chachapoly() {
  uint8_t mac[16] = {0};
  uint8_t plaintext[plaintext_len] = {0};
  uint8_t ciphertext[plaintext_len + 16] = {0};
  if (!(get_random(plaintext, plaintext_len))) {
    return false;
  }
  uint64_t a, b;
  clock_t t1, t2;

  t1 = clock();
  a = rdtsc();
  for (uint32_t i = 0; i < rounds; i++) {
    do_chacha20poly1305(ciphertext, mac, plaintext, plaintext_len, aad, 12,
                        nonce, key);
    plaintext[0] = mac[0];
  }
  b = rdtsc();
  t2 = clock();
  uint64_t cycles = b - a;
  clock_t time = t2 - t1;
  std::cout << "ChachaPoly speed:\n"
            << cycles << " cycles\n"
            << time << " time" << std::endl
            << std::endl;
  return true;
}
