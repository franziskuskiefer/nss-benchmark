#include <nss/pk11pub.h>
#include <nss/seccomon.h>
#include <iostream>

#include "rand.h"

// Generate num_bytes random data and put it in data.
bool get_random(uint8_t *data, size_t num_bytes) {
  if (!data) {
    return false;
  }
  if (num_bytes > 0x10000) {
    std::cout << "Sorry I can only get 0x10000 random bytes at a time :( "
              << std::endl;
    return false;
  }
  SECStatus rv = PK11_GenerateRandom(data, num_bytes);
  if (rv != SECSuccess) {
    return false;
  }
  return true;
}
