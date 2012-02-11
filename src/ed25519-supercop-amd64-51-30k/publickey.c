#include "crypto_sign.h"

#include "crypto_verify_32.h"
#include "sha512.h"

#include "ge25519.h"


int crypto_sign_publickey(
    unsigned char *pk,  // write 32 bytes into this
    unsigned char *sk,  // write 64 bytes into this (seed+pubkey)
    unsigned char *seed // 32 bytes
    )
{
  sc25519 scsk;
  ge25519 gepk;
  int i;

  crypto_hash_sha512(sk, seed, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;

  sc25519_from32bytes(&scsk,sk);
  
  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);
  for(i=0;i<32;i++)
    sk[32 + i] = pk[i];
  for(i=0;i<32;i++)
    sk[i] = seed[i];
  return 0;
}
