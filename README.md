Python Bindings to the Ed25519 Digital Signature System
=======================================================

[![Build Status](https://travis-ci.org/warner/python-ed25519.png?branch=master)](https://travis-ci.org/warner/python-ed25519)

This package provides python bindings to a C implementation of the Ed25519
public-key signature system [1][]. The C code is copied from the SUPERCOP
benchmark suite [2][], using the portable "ref" implementation (not the
high-performance assembly code), and is very similar to the copy in the NaCl
library [3][]. The C code is in the public domain [4][]. This python binding
is released under the MIT license (see LICENSE in this distribution).

With this library, you can quickly (2ms) create signing+verifying keypairs,
derive a verifying key from a signing key, sign messages, and verify the
signatures. The keys and signatures are very short, making them easy to
handle and incorporate into other protocols. All known attacks take at least
2^128 operations, providing the same security level as AES-128, NIST P-256,
and RSA-3072.


## Dependencies

This library includes a copy of all the C code necessary. You will need
Python 2.x (2.6 or later) or Python 3.x (3.3 or later) and a C compiler. The
tests are run automatically against python 2.6, 2.7, 3.3, 3.4, and pypy
versions of Python 2.7 and 3.2.


## Speed and Key Sizes

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


## Testing

The Ed25519 web site includes a (spectacularly slow) pure-python
implementation for educational purposes. That code includes a set of
known-answer-tests. Those tests are included in this distribution, and takes
about 17 seconds to execute. The distribution also includes unit tests of the
object-oriented SigningKey / VerifyingKey layer. Run test.py to execute these
tests.


## Security

The Ed25519 algorithm and C implementation are carefully designed to prevent
timing attacks. The Python wrapper might not preserve this property. Until it
has been audited for this purpose, do not allow attackers to measure how long
it takes you to generate a keypair or sign a message. Key generation depends
upon a strong source of random numbers. Do not use it on a system where
os.urandom() is weak.

Unlike typical DSA/ECDSA algorithms, signing does *not* require a source of
entropy. Ed25519 signatures are deterministic: using the same key to sign the
same data any number of times will result in the same signature each time.


## Compilation

To build and install the library, run the normal setup.py command:

```
python setup.py build
sudo python setup.py install
```

You can run the (fast) test suite, the (slower) known-answer-tests, and the
speed-benchmarks through setup.py commands too:

```
python setup.py test
python setup.py test_kat
python setup.py speed
```

## Prefixes and Encodings

The basic keypair/sign/verify operations work on binary bytestrings: signing
keys are created with a 32-byte seed or a 64-byte expanded form, verifying
keys are serialized as 32-byte binary strings, and signatures are 64-byte
binary strings.

All methods that generate or accept bytestrings take a prefix= argument,
which is simply prepended to the output or stripped from the input. This can
be used for a cheap version check: if you use e.g. prefix="pubkey0-" when
handling verifying keys, and later update your application to use a different
kind of key (and update to "pubkey1-"), then older receivers will throw a
clean error when faced with a key format that they cannot handle.

These methods also accept an encoding= argument, which makes them return an
ASCII string instead of a binary bytestring. This makes it convenient to
display verifying keys or signatures to cut-and-paste or encode into JSON
messages. Be careful when encouraging users to cut-and-paste signing keys,
since you might enable them to accidentally reveal those keys: in general, it
should require slightly more attention to handle signing keys than verifying
keys.

encoding= can be set to one of "base64", "base32", "base16", or "hex" (an
alias for "base16"). The strings are stripped of trailing "=" markers and
lowercased (for base32/base16).


## Usage

The first step is to create a signing key and store it. The safest way to
generate a key is with the create_keypair() function, which uses 32 bytes of
random data from os.urandom() (although you can provide an alternative
entropy source with the entropy= argument):

```python
import ed25519
signing_key, verifying_key = ed25519.create_keypair()
open("my-secret-key","wb").write(signing_key.to_bytes())
vkey_hex = verifying_key.to_ascii(encoding="hex")
print "the public key is", vkey_hex
```

The private signing key string produced by to_bytes() is 64 bytes long, and
includes a copy of the public key (to avoid the 1.9ms needed to recalculate
it later). If you want to store less data (and recompute the public key
later), you can store just the 32 byte seed instead:

```python
open("my-secret-seed","wb").write(signing_key.to_seed())
```

The signing key is an instance of the ed25519.SigningKey class. To
reconstruct this instance from a serialized form, the constructor accepts the
output of either `.to_bytes()` or `.to_seed()`:

```python
keydata = open("my-secret-key","rb").read()
signing_key = ed25519.SigningKey(keydata)
 
seed = open("my-secret-seed","rb").read()
signing_key2 = ed25519.SigningKey(seed)
assert signing_key == signing_key2
```

Special-purpose applications may want to derive keypairs from existing
secrets; any 32-byte uniformly-distributed random string can be provided as a
seed:

```python
import os, hashlib
master = os.urandom(87)
seed = hashlib.sha256(master).digest()
signing_key = ed25519.SigningKey(seed)
```

Once you have the SigningKey instance, use its .sign() method to sign a
message. The signature is 64 bytes, but can be generated in printable form
with the encoding= argument:

```python
sig = signing_key.sign(b"hello world", encoding="base64")
print "sig is:", sig
```

On the verifying side, the receiver first needs to construct a
ed25519.VerifyingKey instance from the serialized string, then use its
.verify() method on the signature and message:

```python
vkey_hex = b"1246b84985e1ab5f83f4ec2bdf271114666fd3d9e24d12981a3c861b9ed523c6"
verifying_key = ed25519.VerifyingKey(vkey_hex, encoding="hex")
try:
  verifying_key.verify(sig, b"hello world", encoding="base64")
  print "signature is good"
except ed25519.BadSignatureError:
  print "signature is bad!"
```

If you happen to have the SigningKey but not the corresponding VerifyingKey,
you can derive it with `.get_verifying_key()`. This allows the sending side to
hold just 32 bytes of data and derive everything else from that:

```python
keydata = open("my-secret-seed","rb").read()
signing_key = ed25519.SigningKey(keydata)
verifying_key = signing_key.get_verifying_key()
```

There is also a basic command-line keygen/sign/verify tool in bin/edsig .


## API Summary

The complete API is summarized here:

```python
sk,vk = ed25519.create_keypair(entropy=os.urandom)
vk = sk.get_verifying_key()
 
signature = sk.sign(message, prefix=, encoding=)
vk.verify(signature, message, prefix=, encoding=)
 
seed = sk.to_seed(prefix=)
sk = SigningKey(seed, prefix=)
bytes = sk.to_bytes(prefix=)
sk = SigningKey(bytes, prefix=)
ascii = sk.to_ascii(prefix=, encoding=)  # encodes seed
sk = SigningKey(ascii, prefix=, encoding=)
 
bytes = vk.to_bytes(prefix=)
vk = VerifyingKey(bytes, prefix=)
ascii = vk.to_ascii(prefix=, encoding=)
vk = VerifyingKey(ascii, prefix=, encoding=)
```




[1]: http://ed25519.cr.yp.to/
[2]: http://bench.cr.yp.to/supercop.html
[3]: http://nacl.cr.yp.to/
[4]: http://ed25519.cr.yp.to/software.html
