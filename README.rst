=====================================================
 Python Bindings to Ed25519 Digital Signature System
=====================================================

This package provides python bindings to a C implementation of the Ed25519
public-key signature system [1]_. The C code is copied from the SUPERCOP
benchmark suite [2]_, using the portable "ref" implementation (not the
high-performance assembly code), and is very similar to the copy in the NaCl
library [3]_. The C code is in the public domain [4]_. This python binding is
released under the MIT license [5]_.

With this library, you can quickly (2ms) create signing+verifying keypairs,
derive a verifying key from a signing key, sign messages, and verify the
signatures. The keys and signatures are very short, making them easy to
handle and incorporate into other protocols. All known attacks take at least
2^128 operations, providing the same security level as AES-128, NIST P-256,
and RSA-3072.


Dependencies
------------

This library includes a copy of all the C code necessary. You will need
Python 2.x (2.5 or later, not 3.x) and a C compiler. The tests are run
automatically against python2.5, python2.6, and python2.7 .


Speed and Key Sizes
-------------------

Signing key seeds are merely 32 bytes of random data, so generating a signing
key is trivial. Deriving a public verifying key takes more time, as do the
actual signing and verifying operations.

On my 2010-era Mac laptop (2.8GHz Core2Duo), deriving a verifying key takes
1.9ms, signing takes 1.9ms, and verification takes 6.3ms. The
high-performance assembly code in SUPERCOP (amd64-51-30k and amd64-64-24k) is
up to 100x faster than the portable reference version, and the python
overhead appears to be minimal (1-2us), so future releases may run even
faster.

Ed25519 private signing keys are 32 bytes long (this seed is expanded to 64
bytes when necessary). The public verifying keys are also 32 bytes long.
Signatures are 64 bytes long. All operations provide a 128-bit security
level.


Testing
-------

The Ed25519 web site includes a (spectacularly slow) pure-python
implementation for educational purposes. That code includes a set of
known-answer-tests. Those tests are included in this distribution, and takes
about 17 seconds to execute. The distribution also includes unit tests of the
object-oriented SigningKey / VerifyingKey layer. Run test.py to execute these
tests.


Security
--------

The Ed25519 algorithm and C implementation are carefully designed to prevent
timing attacks. The Python wrapper might not preserve this property. Until it
has been audited for this purpose, do not allow attackers to measure how long
it takes you to generate a keypair or sign a message. Key generation depends
upon a strong source of random numbers. Do not use it on a system where
os.urandom() is weak.

Unlike typical DSA/ECDSA algorithms, signing does *not* require a source of
entropy. Ed25519 signatures are deterministic: using the same key to sign the
same data any number of times will result in the same signature each time.


Compilation
-----------

To build and install the library, run the normal setup.py command::

 python setup.py build
 sudo python setup.py install

You can run the (fast) test suite, the (slower) known-answer-tests, and the speed-benchmarks through setup.py commands too::

 python setup.py test
 python setup.py test_kat
 python setup.py speed


Usage
-----

The first step is to generate a signing key and store it. At the same time,
you'll probably need to derive the verifying key and give it to someone else.
Signing keys are generated from 32-byte uniformly-random seeds. The safest
way to generate a key seed is with os.urandom(32)::

 import os, ed25519
 from binascii import hexlify, unhexlify

 sk_bytes = os.urandom(32)
 signing_key = ed25519.SigningKey(sk_bytes)
 open("my-secret-key","wb").write(sk_bytes)

 vkey_hex = hexlify(sk.get_verifying_key_bytes())
 print "the public key is", vkey_hex

To reconstruct the same key from the stored form later, just pass it back
into SigningKey::

 sk_bytes = open("my-secret-key","rb").read()
 signing_key = ed25519.SigningKey(sk_bytes)

Special-purpose applications may want to derive keypairs from existing
secrets; any 32-byte uniformly-distributed random string can be provided as a
seed. The safest approach is to feed a string with at least 256 bits of
entropy into a cryptographic hash function like SHA256, or to use a
well-known protocol like HKDF::

 import os, hashlib
 master = os.urandom(87)
 sk_bytes = hashlib.sha256(master).digest()
 signing_key = ed25519.SigningKey(sk_bytes)

Once you have the SigningKey instance, use its .sign() method to sign a
message. The signature is 64 bytes, but can be generated in printable form
with the encoding= argument::

 sig = signing_key.sign("hello world")
 print "sig is:", hexlify(sig)

On the verifying side, the receiver first needs to construct a
ed25519.VerifyingKey instance from the serialized form, then use its
.verify() method on the signature and message::

 vkey_hex = "1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"
 verifying_key = ed25519.VerifyingKey(unhexlify(vkey_hex)
 try:
   verifying_key.verify(sig, "hello world")
   print "signature is good"
 except ed25519.BadSignatureError:
   print "signature is bad!"

If you happen to have the SigningKey but not the corresponding VerifyingKey,
you can derive it with .get_verifying_key_bytes(). This allows the sending
side to hold just 32 bytes of data and derive everything else from that.
Deriving a verifying key takes about 1.9ms::

 sk_bytes = open("my-secret-seed","rb").read()
 signing_key = ed25519.SigningKey(sk_bytes)
 verifying_key = ed25519.VerifyingKey(signing_key.get_verifying_key_bytes())

There is also a basic command-line keygen/sign/verify tool in bin/edsig .


API Summary
-----------

The complete API is summarized here::

 sk_bytes = os.urandom(32)
 sk = SigningKey(sk_bytes)
 vk_bytes = sk.get_verifying_key_bytes()
 vk = VerifyingKey(vk_bytes)

 signature = sk.sign(message)
 vk.verify(signature, message)


footnotes
---------

.. [1] http://ed25519.cr.yp.to/
.. [2] http://bench.cr.yp.to/supercop.html
.. [3] http://nacl.cr.yp.to/
.. [4] http://ed25519.cr.yp.to/software.html "Copyrights"
.. [5] LICENSE, included in this distribution
