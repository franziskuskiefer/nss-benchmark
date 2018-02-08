#include <nss/seccomon.h>
#include <stdint.h>

#include "time.h"

#ifdef _WIN32
#include <intrin.h>
uint64_t rdtsc() { return __rdtsc(); }
#elif (defined(__GNUC__) || defined(__clang__)) &&                             \
    (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
uint64_t rdtsc() {
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | (uint64_t)lo;
}
#elif defined(__ARM_ARCH)
uint64_t rdtsc() {
  // from HACL*, not tested.
  uint32_t pmccntr;
  uint32_t pmuseren;
  uint32_t pmcntenset;
  // Read the user mode perf monitor counter access permissions.
  asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r"(pmuseren));
  if (pmuseren & 1) { // Allows reading perfmon counters for user mode code.
    asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r"(pmcntenset));
    if (pmcntenset & 0x80000000ul) { // Is it counting?
      asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
      // The counter is set up to count every 64th cycle
      return (int64_t)(pmccntr) << 6;
    }
  }
}
#endif
