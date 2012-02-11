OBJS = \
 choose_t.o \
 consts.o \
 fe25519_add.o \
 fe25519_freeze.o \
 fe25519_getparity.o \
 fe25519_invert.o \
 fe25519_iseq.o \
 fe25519_iszero.o \
 fe25519_mul.o \
 fe25519_neg.o \
 fe25519_pack.o \
 fe25519_pow2523.o \
 fe25519_setint.o \
 fe25519_square.o \
 fe25519_sub.o \
 fe25519_unpack.o \
 ge25519_add.o \
 ge25519_add_p1p1.o \
 ge25519_base.o \
 ge25519_dbl_p1p1.o \
 ge25519_double.o \
 ge25519_double_scalarmult.o \
 ge25519_isneutral.o \
 ge25519_multi_scalarmult.o \
 ge25519_nielsadd2.o \
 ge25519_nielsadd_p1p1.o \
 ge25519_p1p1_to_p2.o \
 ge25519_p1p1_to_p3.o \
 ge25519_pack.o \
 ge25519_pnielsadd_p1p1.o \
 ge25519_scalarmult_base.o \
 ge25519_unpackneg.o \
 heap_rootreplaced.o \
 heap_rootreplaced_1limb.o \
 heap_rootreplaced_2limbs.o \
 heap_rootreplaced_3limbs.o \
 hram.o \
 index_heap.o \
 open.o \
 sc25519_add.o \
 sc25519_barrett.o \
 sc25519_from32bytes.o \
 sc25519_from64bytes.o \
 sc25519_from_shortsc.o \
 sc25519_iszero.o \
 sc25519_lt.o \
 sc25519_mul.o \
 sc25519_mul_shortsc.o \
 sc25519_slide.o \
 sc25519_sub_nored.o \
 sc25519_to32bytes.o \
 sc25519_window4.o \
 sign.o \
 ull4_mul.o \
   publickey.o sha512-blocks.o sha512-hash.o verify.o

OFF_OBJS= \
 batch.o \
 keypair.o

CC=gcc
CFLAGS=-O2 -Wall

test: test.o $(OBJS)
	gcc -o $@ $^

clean:
	rm -f *.o test
