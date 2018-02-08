#include <nss/nss.h>
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
