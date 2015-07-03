from __future__ import print_function
import sys
import unittest
import time
from binascii import hexlify, unhexlify
import ed25519
from ed25519 import _ed25519 as raw

if sys.version_info[0] == 3:
    def int2byte(i):
        return bytes((i,))
else:
    int2byte = chr

def flip_bit(s, bit=0, in_byte=-1):
    as_bytes = [ord(b) if isinstance(b, str) else b for b in s]
    as_bytes[in_byte] = as_bytes[in_byte] ^ (0x01<<bit)
    return  b"".join([int2byte(b) for b in as_bytes])

# the pure-python demonstration code (on my 2010 MacBookPro) takes 5s to
# generate a public key, 9s to sign, 14s to verify

# the SUPERCOP-ref version we use takes 2ms for keygen, 2ms to sign, and 7ms
# to verify

class Basic(unittest.TestCase):
    timer = None
    def log(self, msg):
        return
        now = time.time()
        if self.timer is None:
            self.timer = now
        else:
            elapsed = now - self.timer
            self.timer = now
            print(" (%f elapsed)" % elapsed)
        print(msg)

    def test_version(self):
        # just make sure it can be retrieved
        ver = ed25519.__version__
        self.failUnless(isinstance(ver, type("")))

    def test_constants(self):
        # the secret key we get from raw.keypair() are 64 bytes long, and
        # are mostly the output of a sha512 call. The first 32 bytes are the
        # private exponent (random, with a few bits stomped).
        self.failUnlessEqual(raw.SECRETKEYBYTES, 64)
        # the public key is the encoded public point
        self.failUnlessEqual(raw.PUBLICKEYBYTES, 32)
        self.failUnlessEqual(raw.SIGNATUREKEYBYTES, 64)

    def test_raw(self):
        sk_s = b"\x00" * 32 # usually urandom(32)
        vk_s, skvk_s = raw.publickey(sk_s)
        self.failUnlessEqual(len(vk_s), 32)
        exp_vks = unhexlify(b"3b6a27bcceb6a42d62a3a8d02a6f0d73"
                            b"653215771de243a63ac048a18b59da29")
        self.failUnlessEqual(vk_s, exp_vks)
        self.failUnlessEqual(skvk_s[:32], sk_s)
        self.failUnlessEqual(skvk_s[32:], vk_s)
        msg = b"hello world"
        msg_and_sig = raw.sign(msg, skvk_s)
        sig = msg_and_sig[:-len(msg)]
        self.failUnlessEqual(len(sig), 64)
        exp_sig = unhexlify(b"b0b47780f096ae60bfff8d8e7b19c36b"
                            b"321ae6e69cca972f2ff987ef30f20d29"
                            b"774b53bae404485c4391ddf1b3f37aaa"
                            b"8a9747f984eb0884e8aa533386e73305")
        self.failUnlessEqual(sig, exp_sig)
        ret = raw.open(sig+msg, vk_s) # don't raise exception
        self.failUnlessEqual(ret, msg)
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              sig+msg+b".. NOT!", vk_s)
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              sig+flip_bit(msg), vk_s)
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              sig+msg, flip_bit(vk_s))
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              sig+msg, flip_bit(vk_s, in_byte=2))
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              flip_bit(sig)+msg, vk_s)
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              flip_bit(sig, in_byte=33)+msg, vk_s)

    def test_keypair(self):
        sk, vk = ed25519.create_keypair()
        self.failUnless(isinstance(sk, ed25519.SigningKey), sk)
        self.failUnless(isinstance(vk, ed25519.VerifyingKey), vk)
        sk2, vk2 = ed25519.create_keypair()
        self.failIfEqual(hexlify(sk.to_bytes()), hexlify(sk2.to_bytes()))

        # you can control the entropy source
        def not_so_random(length):
            return b"4"*length
        sk1, vk1 = ed25519.create_keypair(entropy=not_so_random)
        self.failUnlessEqual(sk1.to_ascii(encoding="base64"),
                             b"NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ")
        self.failUnlessEqual(vk1.to_ascii(encoding="base64"),
                             b"6yzxO/euOl9hQWih+wknLTl3HsS4UjcngV5GbK+O4WM")
        sk2, vk2 = ed25519.create_keypair(entropy=not_so_random)
        self.failUnlessEqual(sk1.to_ascii(encoding="base64"),
                             sk2.to_ascii(encoding="base64"))
        self.failUnlessEqual(vk1.to_ascii(encoding="base64"),
                             vk2.to_ascii(encoding="base64"))


    def test_publickey(self):
        seed = unhexlify(b"4ba96b0b5303328c7405220598a587c4"
                         b"acb06ed9a9601d149f85400195f1ec3d")
        sk = ed25519.SigningKey(seed)
        self.failUnlessEqual(hexlify(sk.to_bytes()),
                             (b"4ba96b0b5303328c7405220598a587c4"
                              b"acb06ed9a9601d149f85400195f1ec3d"
                              b"a66d161e090652b054740748f059f92a"
                              b"5b731f1c27b05571f6d942e4f8b7b264"))
        self.failUnlessEqual(hexlify(sk.to_seed()),
                             (b"4ba96b0b5303328c7405220598a587c4"
                              b"acb06ed9a9601d149f85400195f1ec3d"))
        self.failUnlessRaises(ValueError,
                              ed25519.SigningKey, b"wrong length")
        sk2 = ed25519.SigningKey(seed)
        self.failUnlessEqual(sk, sk2)

    def test_OOP(self):
        sk_s = unhexlify(b"4ba96b0b5303328c7405220598a587c4"
                         b"acb06ed9a9601d149f85400195f1ec3d"
                         b"a66d161e090652b054740748f059f92a"
                         b"5b731f1c27b05571f6d942e4f8b7b264")
        sk = ed25519.SigningKey(sk_s)
        self.failUnlessEqual(len(sk.to_bytes()), 64)
        self.failUnlessEqual(sk.to_bytes(), sk_s)

        sk2_seed = unhexlify(b"4ba96b0b5303328c7405220598a587c4"
                             b"acb06ed9a9601d149f85400195f1ec3d")
        sk2 = ed25519.SigningKey(sk2_seed)
        self.failUnlessEqual(sk2.to_bytes(), sk.to_bytes())

        vk = sk.get_verifying_key()
        self.failUnlessEqual(len(vk.to_bytes()), 32)
        exp_vks = unhexlify(b"a66d161e090652b054740748f059f92a"
                            b"5b731f1c27b05571f6d942e4f8b7b264")
        self.failUnlessEqual(vk.to_bytes(), exp_vks)
        self.failUnlessEqual(ed25519.VerifyingKey(vk.to_bytes()), vk)
        msg = b"hello world"
        sig = sk.sign(msg)
        self.failUnlessEqual(len(sig), 64)
        exp_sig = unhexlify(b"6eaffe94f2972b35158b6aaa9b69c1da"
                            b"97f0896aca29c41b1dd7b32e6c9e2ff6"
                            b"76fc8d8b034709cdcc37d8aeb86bebfb"
                            b"173ace3c319e211ea1d7e8d8884c1808")
        self.failUnlessEqual(sig, exp_sig)
        self.failUnlessEqual(vk.verify(sig, msg), None) # also, don't throw
        self.failUnlessRaises(ed25519.BadSignatureError,
                              vk.verify, sig, msg+b".. NOT!")

    def test_object_identity(self):
        sk1_s = unhexlify(b"ef32972ae3f1252a5aa1395347ea008c"
                          b"bd2fed0773a4ea45e2d2d06c8cf8fbd4"
                          b"c024601a9c5b854fb100ff3116cf4f22"
                          b"a311565f027391cb49d3bbe11c44399d")
        sk2_s = unhexlify(b"3d550c158900b4c2922b6656d2f80572"
                          b"89de4ee65043745179685ae7d29b944d"
                          b"672b8a2cb23f9e75e1d46ce249cd9c04"
                          b"68f816f1c734a102822b60e18b41eacd")
        sk1a = ed25519.SigningKey(sk1_s)
        sk1b = ed25519.SigningKey(sk1_s)
        vk1a = sk1a.get_verifying_key()
        vk1b = sk1b.get_verifying_key()
        sk2 = ed25519.SigningKey(sk2_s)
        vk2 = sk2.get_verifying_key()
        self.failUnlessEqual(sk1a, sk1b)
        self.failIfEqual(sk1a, sk2)
        self.failUnlessEqual(vk1a, vk1b)
        self.failIfEqual(vk1a, vk2)

        self.failIfEqual(sk2, b"not a SigningKey")
        self.failIfEqual(vk2, b"not a VerifyingKey")

    def test_prefix(self):
        sk1,vk1 = ed25519.create_keypair()
        PREFIX = b"private0-"
        p = sk1.to_bytes(PREFIX)
        # that gives us a binary string with a prefix
        self.failUnless(p[:len(PREFIX)] == PREFIX, repr(p))
        sk2 = ed25519.SigningKey(p, prefix=PREFIX)
        self.failUnlessEqual(sk1, sk2)
        self.failUnlessEqual(repr(sk1.to_bytes()), repr(sk2.to_bytes()))
        self.failUnlessRaises(ed25519.BadPrefixError,
                              ed25519.SigningKey, p, prefix=b"WRONG-")
        # SigningKey.to_seed() can do a prefix too
        p = sk1.to_seed(PREFIX)
        self.failUnless(p[:len(PREFIX)] == PREFIX, repr(p))
        sk3 = ed25519.SigningKey(p, prefix=PREFIX)
        self.failUnlessEqual(sk1, sk3)
        self.failUnlessEqual(repr(sk1.to_bytes()), repr(sk3.to_bytes()))
        self.failUnlessRaises(ed25519.BadPrefixError,
                              ed25519.SigningKey, p, prefix=b"WRONG-")

        # verifying keys can do this too
        PREFIX = b"public0-"
        p = vk1.to_bytes(PREFIX)
        self.failUnless(p.startswith(PREFIX), repr(p))
        vk2 = ed25519.VerifyingKey(p, prefix=PREFIX)
        self.failUnlessEqual(vk1, vk2)
        self.failUnlessEqual(repr(vk1.to_bytes()), repr(vk2.to_bytes()))
        self.failUnlessRaises(ed25519.BadPrefixError,
                              ed25519.VerifyingKey, p, prefix=b"WRONG-")

        # and signatures
        PREFIX = b"sig0-"
        p = sk1.sign(b"msg", PREFIX)
        self.failUnless(p.startswith(PREFIX), repr(p))
        vk1.verify(p, b"msg", PREFIX)
        self.failUnlessRaises(ed25519.BadPrefixError,
                              vk1.verify, p, b"msg", prefix=b"WRONG-")

    def test_ascii(self):
        b2a = ed25519.to_ascii
        a2b = ed25519.from_ascii
        for prefix in ("", "prefix-"):
            for length in range(0, 100):
                b1 = b"a"*length
                for base in ("base64", "base32", "base16", "hex"):
                    a = b2a(b1, prefix, base)
                    b2 = a2b(a, prefix, base)
                    self.failUnlessEqual(b1, b2)

    def test_encoding(self):
        sk_s = b"\x88" * 32 # usually urandom(32)
        sk1 = ed25519.SigningKey(sk_s)
        vk1 = sk1.get_verifying_key()

        def check1(encoding, expected):
            PREFIX = "private0-"
            p = sk1.to_ascii(PREFIX, encoding)
            self.failUnlessEqual(p, expected)
            sk2 = ed25519.SigningKey(p, prefix=PREFIX, encoding=encoding)
            self.failUnlessEqual(repr(sk1.to_bytes()), repr(sk2.to_bytes()))
            self.failUnlessEqual(sk1, sk2)
        check1("base64", b"private0-iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg")
        check1("base32", b"private0-rceirceirceirceirceirceirceirceirceirceirceirceircea")
        check1("hex", b"private0-8888888888888888888888888888888888888888888888888888888888888888")

        def check2(encoding, expected):
            PREFIX="public0-"
            p = vk1.to_ascii(PREFIX, encoding)
            self.failUnlessEqual(p, expected)
            vk2 = ed25519.VerifyingKey(p, prefix=PREFIX, encoding=encoding)
            self.failUnlessEqual(repr(vk1.to_bytes()), repr(vk2.to_bytes()))
            self.failUnlessEqual(vk1, vk2)
        check2("base64", b"public0-skkdlQKuKGMKK6yy4MdFEP/N0yjDNP8+E5PnWy0x59w")
        check2("base32", b"public0-wjer3ficvyuggcrlvszobr2fcd743uziym2p6pqtsptvwljr47oa")
        check2("hex", b"public0-b2491d9502ae28630a2bacb2e0c74510ffcdd328c334ff3e1393e75b2d31e7dc")

        def check3(encoding, expected):
            msg = b"msg"
            PREFIX="sig0-"
            sig = sk1.sign(msg, PREFIX, encoding)
            self.failUnlessEqual(sig, expected)
            vk1.verify(sig, msg, PREFIX, encoding)
        check3("base64", b"sig0-MNfdUir6tMlaYQ+/p8KANJ5d+bk8g2al76v5MeJCo6RiywxURda3sU580CyiW2FBG/Q7kDRswgYqxbkQw3o5CQ")
        check3("base32", b"sig0-gdl52urk7k2mswtbb672pquagspf36nzhsbwnjppvp4tdyscuosgfsymkrc5nn5rjz6nalfclnqucg7uhoidi3gcayvmloiqyn5dsci")
        check3("hex", b"sig0-30d7dd522afab4c95a610fbfa7c280349e5df9b93c8366a5efabf931e242a3a462cb0c5445d6b7b14e7cd02ca25b61411bf43b90346cc2062ac5b910c37a3909")


if __name__ == '__main__':
    unittest.main()
