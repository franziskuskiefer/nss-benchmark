
#include <iostream>

#include "hash.h"
#include "lib/rand.h"
#include "lib/time.h"
#include "lib/nss-util.h"

static const uint32_t rounds = 10000;
static uint32_t data_len = 0x20000;

bool sha2(size_t output_len, bool single_block) {
  uint8_t digest[output_len >> 3] = {0};
  if (single_block) {
    switch (output_len) {
    case 256:
      data_len = 64;
      break;
    case 384:
    /* fall through */
    case 512:
      data_len = 128;
      break;
    default:
      std::cout << "Unkown digest size " << output_len << std::endl;
      return false;
    }
  }
  uint8_t data[data_len] = {0};
  if (!(get_random(data, data_len))) {
    return false;
  }
  uint64_t a, b;
  clock_t t1, t2;

  t1 = clock();
  a = rdtsc();
  for (uint32_t i = 0; i < rounds; i++) {
    do_sha2(output_len, data, data_len, digest);
    data[0] = digest[0];
  }
  b = rdtsc();
  t2 = clock();
  uint64_t cycles = b - a;
  clock_t time = t2 - t1;

  std::cout << "SHA" << output_len << " speed"
            << (single_block ? " (single block)" : "") << ":\n"
            << cycles << " cycles\n"
            << time << " time" << std::endl
            << std::endl;
  return true;
}
