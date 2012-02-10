
import os
import unittest
import time
from binascii import hexlify, unhexlify
import ed25519
from ed25519 import _ed25519 as raw

def flip_bit(s, bit=0, in_byte=-1):
    as_bytes = [ord(b) for b in s]
    as_bytes[in_byte] = as_bytes[in_byte] ^ (0x01<<bit)
    return "".join([chr(b) for b in as_bytes])

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
            print " (%f elapsed)" % elapsed
        print msg

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
        sk_s = "\x00" * 32 # usually urandom(32)
        vk_s, skvk_s = raw.publickey(sk_s)
        self.failUnlessEqual(len(vk_s), 32)
        exp_vks = unhexlify("3b6a27bcceb6a42d62a3a8d02a6f0d73"
                            "653215771de243a63ac048a18b59da29")
        self.failUnlessEqual(vk_s, exp_vks)
        self.failUnlessEqual(skvk_s[:32], sk_s)
        self.failUnlessEqual(skvk_s[32:], vk_s)
        msg = "hello world"
        msg_and_sig = raw.sign(msg, skvk_s)
        sig = msg_and_sig[:-len(msg)]
        self.failUnlessEqual(len(sig), 64)
        exp_sig = unhexlify("b0b47780f096ae60bfff8d8e7b19c36b"
                            "321ae6e69cca972f2ff987ef30f20d29"
                            "774b53bae404485c4391ddf1b3f37aaa"
                            "8a9747f984eb0884e8aa533386e73305")
        self.failUnlessEqual(sig, exp_sig)
        ret = raw.open(sig+msg, vk_s) # don't raise exception
        self.failUnlessEqual(ret, msg)
        self.failUnlessRaises(raw.BadSignatureError,
                              raw.open,
                              sig+msg+".. NOT!", vk_s)
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


    def test_publickey(self):
        sk_bytes = unhexlify("4ba96b0b5303328c7405220598a587c4"
                             "acb06ed9a9601d149f85400195f1ec3d")
        sk = ed25519.SigningKey(sk_bytes)
        self.failUnlessRaises(ValueError, ed25519.SigningKey, "wrong length")

        vk_bytes = sk.get_verifying_key_bytes()
        self.failUnlessEqual(hexlify(vk_bytes),
                             "a66d161e090652b054740748f059f92a"
                             "5b731f1c27b05571f6d942e4f8b7b264")

        vk = ed25519.VerifyingKey(vk_bytes)
        self.failUnlessRaises(ValueError, ed25519.VerifyingKey, "wrong length")

    def test_OOP(self):
        sk_bytes = unhexlify("4ba96b0b5303328c7405220598a587c4"
                             "acb06ed9a9601d149f85400195f1ec3d")
        sk = ed25519.SigningKey(sk_bytes)

        self.failUnlessEqual(hexlify(sk.get_verifying_key_bytes()),
                             "a66d161e090652b054740748f059f92a"
                             "5b731f1c27b05571f6d942e4f8b7b264")
        vk = ed25519.VerifyingKey(sk.get_verifying_key_bytes())

        msg = "hello world"
        sig = sk.sign(msg)
        self.failUnlessEqual(len(sig), 64)
        self.failUnlessEqual(hexlify(sig),
                             "6eaffe94f2972b35158b6aaa9b69c1da"
                             "97f0896aca29c41b1dd7b32e6c9e2ff6"
                             "76fc8d8b034709cdcc37d8aeb86bebfb"
                             "173ace3c319e211ea1d7e8d8884c1808")
        self.failUnlessEqual(vk.verify(sig, msg), None) # also, don't throw
        self.failUnlessRaises(ed25519.BadSignatureError,
                              vk.verify, sig, msg+".. NOT!")

    def test_object_identity(self):
        sk1_bytes = unhexlify("ef32972ae3f1252a5aa1395347ea008c"
                              "bd2fed0773a4ea45e2d2d06c8cf8fbd4")
        sk2_bytes = unhexlify("3d550c158900b4c2922b6656d2f80572"
                              "89de4ee65043745179685ae7d29b944d")
        sk1a = ed25519.SigningKey(sk1_bytes)
        sk1b = ed25519.SigningKey(sk1_bytes)
        sk2 = ed25519.SigningKey(sk2_bytes)
        self.failUnlessEqual(sk1a, sk1b)
        self.failIfEqual(sk1a, sk2)

        vk1_bytes = sk1a.get_verifying_key_bytes()
        self.failUnlessEqual(vk1_bytes, sk1b.get_verifying_key_bytes())
        vk2_bytes = sk2.get_verifying_key_bytes()
        vk1a = ed25519.VerifyingKey(vk1_bytes)
        vk1b = ed25519.VerifyingKey(vk1_bytes)
        vk2 = ed25519.VerifyingKey(vk2_bytes)
        self.failUnlessEqual(vk1a, vk1b)
        self.failIfEqual(vk1a, vk2)

        # exercise compare-against-other-type
        self.failIfEqual(sk2, "not a SigningKey")
        self.failIfEqual(vk2, "not a VerifyingKey")

    def test_prefix(self):
        sk = ed25519.SigningKey(os.urandom(32))
        vk = ed25519.VerifyingKey(sk.get_verifying_key_bytes())

        # and signatures
        PREFIX = "sig0-"
        p = sk.sign("msg", PREFIX)
        self.failUnless(p.startswith(PREFIX), repr(p))
        vk.verify(p, "msg", PREFIX)
        self.failUnlessRaises(ed25519.BadPrefixError,
                              vk.verify, p, "msg", prefix="WRONG-")

    def test_ascii(self):
        b2a = ed25519.to_ascii
        a2b = ed25519.from_ascii
        for prefix in ("", "prefix-"):
            for length in range(0, 100):
                b1 = "a"*length
                for base in ("base64", "base32", "base16", "hex"):
                    a = b2a(b1, prefix, base)
                    b2 = a2b(a, prefix, base)
                    self.failUnlessEqual(b1, b2)

    def test_encoding(self):
        sk_bytes = "\x88" * 32 # usually urandom(32)
        sk = ed25519.SigningKey(sk_bytes)
        vk = ed25519.VerifyingKey(sk.get_verifying_key_bytes())

        def check(encoding, expected):
            msg = "msg"
            PREFIX="sig0-"
            sig = sk.sign(msg, PREFIX, encoding)
            self.failUnlessEqual(sig, expected)
            vk.verify(sig, msg, PREFIX, encoding)
        check("base64", "sig0-MNfdUir6tMlaYQ+/p8KANJ5d+bk8g2al76v5MeJCo6RiywxURda3sU580CyiW2FBG/Q7kDRswgYqxbkQw3o5CQ")
        check("base32", "sig0-gdl52urk7k2mswtbb672pquagspf36nzhsbwnjppvp4tdyscuosgfsymkrc5nn5rjz6nalfclnqucg7uhoidi3gcayvmloiqyn5dsci")
        check("hex", "sig0-30d7dd522afab4c95a610fbfa7c280349e5df9b93c8366a5efabf931e242a3a462cb0c5445d6b7b14e7cd02ca25b61411bf43b90346cc2062ac5b910c37a3909")


if __name__ == '__main__':
    unittest.main()
