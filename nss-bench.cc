
#include "aead.h"
#include "hash.h"
#include "lib/nss-util.h"

#include <cstring>
#include <iostream>

bool doTest(const char *arg, const char *test) {
  return !arg ||
         (strlen(arg) == strlen(test) && !strncmp(arg, test, strlen(arg)));
}

int main(int argc, char const *argv[]) {
  if (!init()) {
    return 1;
  }

  const char *test = nullptr;
  if (argc > 1) {
    test = argv[1];
  }

  if (doTest(test, "chacha") && !chachapoly()) {
    return 1;
  }

  if (doTest(test, "aes128") && !aesgcm(16)) {
    return 1;
  }

  if (doTest(test, "aes256") && !aesgcm(32)) {
    return 1;
  }

  if (doTest(test, "sha256") && (!sha2(256) || !sha2(256, true))) {
    return 1;
  }

  if (doTest(test, "sha384") && (!sha2(384) || !sha2(384, true))) {
    return 1;
  }

  if (doTest(test, "sha512") && (!sha2(512) || !sha2(512, true))) {
    return 1;
  }

  shutdown();
  return 0;
}