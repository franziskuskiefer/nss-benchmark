
#include "aead.h"
#include "hash.h"
#include "lib/nss-util.h"

int main(int argc, char const *argv[]) {
  if (!init()) {
    return 1;
  }

  if (!chachapoly()) {
    return 1;
  }

  if (!aesgcm(16)) {
    return 1;
  }

  if (!aesgcm(32)) {
    return 1;
  }

  if (!sha2(256)) {
    return 1;
  }

  if (!sha2(384)) {
    return 1;
  }

  if (!sha2(512)) {
    return 1;
  }

  shutdown();
  return 0;
}