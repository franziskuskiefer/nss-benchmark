#include <nss/pk11pub.h>
#include <nss/seccomon.h>
#include <iostream>
#include <algorithm>

#include "rand.h"

static const size_t MAX_RAND = 0x10000;

// Generate num_bytes random data and put it in data.
bool get_random(uint8_t *data, size_t num_bytes) {
  if (!data) {
    return false;
  }
  size_t collected = 0;
  size_t collect = num_bytes;
  while (collected != num_bytes) {
    collect = std::min(MAX_RAND, collect);
    SECStatus rv = PK11_GenerateRandom(data, collect);
    if (rv != SECSuccess) {
      return false;
    }
    collected += collect;
  }
  return true;
}
