#ifndef scoped_ptrs_h__
#define scoped_ptrs_h__

#include <memory>
#include <nss/keyhi.h>
#include <nss/pk11pub.h>
#include <nss/pkcs11uri.h>
#include <nss/sslexp.h>

struct ScopedDelete {
  void operator()(PK11SlotInfo *slot) { PK11_FreeSlot(slot); }
  void operator()(PK11SymKey *key) { PK11_FreeSymKey(key); }
  void operator()(PRFileDesc *fd) { PR_Close(fd); }
  void operator()(SECAlgorithmID *id) { SECOID_DestroyAlgorithmID(id, true); }
  void operator()(SECKEYPublicKey *key) { SECKEY_DestroyPublicKey(key); }
  void operator()(SECKEYPrivateKey *key) { SECKEY_DestroyPrivateKey(key); }
  void operator()(SECKEYPrivateKeyList *list) {
    SECKEY_DestroyPrivateKeyList(list);
  }
  void operator()(PK11Context *context) { PK11_DestroyContext(context, true); }
};

template <class T> struct ScopedMaybeDelete {
  void operator()(T *ptr) {
    if (ptr) {
      ScopedDelete del;
      del(ptr);
    }
  }
};

#define SCOPED(x) typedef std::unique_ptr<x, ScopedMaybeDelete<x>> Scoped##x

SCOPED(PK11SlotInfo);
SCOPED(PK11SymKey);
SCOPED(PRFileDesc);
SCOPED(SECAlgorithmID);
SCOPED(SECKEYPublicKey);
SCOPED(SECKEYPrivateKey);
SCOPED(SECKEYPrivateKeyList);
SCOPED(PK11Context);

#undef SCOPED

#endif // scoped_ptrs_h__
