
#include <iostream>

#include "hash.h"
#include "lib/rand.h"
#include "lib/time.h"
#include "lib/nss-util.h"

static const uint32_t rounds = 5000;
static const uint32_t data_len = 0x10000;

bool sha2(size_t output_len) {
  uint8_t digest[output_len >> 3] = {0};
  uint8_t data[data_len] = {0};
  if (!(get_random(data, data_len))) {
    return false;
  }
  uint64_t a, b;
  clock_t t1, t2;

  t1 = clock();
  a = rdtsc();
  for (int i = 0; i < rounds; i++) {
    do_sha2(output_len, data, data_len, digest);
    data[0] = digest[0];
  }
  b = rdtsc();
  t2 = clock();
  uint64_t cycles = b - a;
  clock_t time = t2 - t1;

  std::cout << "SHA" << output_len << " speed:\n"
            << cycles << " cycles\n"
            << time << " time" << std::endl
            << std::endl;
  return true;
}
