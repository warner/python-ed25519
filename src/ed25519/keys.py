import os
import base64
import _ed25519
BadSignatureError = _ed25519.BadSignatureError

class BadPrefixError(Exception):
    pass

def remove_prefix(s_bytes, prefix):
    if not s_bytes.startswith(prefix):
        raise BadPrefixError("did not see expected '%s' prefix" % (prefix,))
    return s_bytes[len(prefix):]

def to_ascii(s_bytes, prefix="", encoding="base64"):
    """Return a version-prefixed ASCII representation of the given binary
    string. 'encoding' indicates how to do the encoding, and can be one of:
     * base64
     * base32
     * base16 (or hex)

    This function handles bytes, not bits, so it does not append any trailing
    '=' (unlike standard base64.b64encode). It also lowercases the base32
    output.

    'prefix' will be prepended to the encoded form, and is useful for
    distinguishing the purpose and version of the binary string. E.g. you
    could prepend 'pub0-' to a VerifyingKey string to allow the receiving
    code to raise a useful error if someone pasted in a signature string by
    mistake.
    """
    if encoding == "base64":
        s_ascii = base64.b64encode(s_bytes).rstrip("=")
    elif encoding == "base32":
        s_ascii = base64.b32encode(s_bytes).rstrip("=").lower()
    elif encoding in ("base16", "hex"):
        s_ascii = base64.b16encode(s_bytes).lower()
    else:
        raise NotImplementedError
    return prefix+s_ascii

def from_ascii(s_ascii, prefix="", encoding="base64"):
    """This is the opposite of to_ascii. It will throw BadPrefixError if
    the prefix is not found.
    """
    s_ascii = remove_prefix(s_ascii.strip(), prefix)
    if encoding == "base64":
        s_ascii += "="*((4 - len(s_ascii)%4)%4)
        s_bytes = base64.b64decode(s_ascii)
    elif encoding == "base32":
        s_ascii += "="*((8 - len(s_ascii)%8)%8)
        s_bytes = base64.b32decode(s_ascii.upper())
    elif encoding in ("base16", "hex"):
        s_bytes = base64.b16decode(s_ascii.upper())
    else:
        raise NotImplementedError
    return s_bytes

class SigningKey(object):
    # this is how all keys are created
    def __init__(self, sk_bytes):
        if not isinstance(sk_bytes, type("")):
            raise TypeError("must be bytes, not %s" % type(sk_bytes))
        if len(sk_bytes) != 32:
            raise ValueError("must be exactly 32 bytes")
        vk_bytes, sk_and_vk = _ed25519.publickey(sk_bytes)
        assert sk_and_vk[:32] == sk_bytes
        assert vk_bytes == sk_and_vk[32:]
        self.vk_bytes = vk_bytes
        self.sk_and_vk = sk_and_vk

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.sk_and_vk == self.sk_and_vk)

    def get_verifying_key_bytes(self):
        return self.vk_bytes

    def sign(self, msg, prefix="", encoding=None):
        sig_and_msg = _ed25519.sign(msg, self.sk_and_vk)
        # the response is R+S+msg
        sig_R = sig_and_msg[0:32]
        sig_S = sig_and_msg[32:64]
        msg_out = sig_and_msg[64:]
        sig_out = sig_R + sig_S
        assert msg_out == msg
        if encoding:
            return to_ascii(sig_out, prefix, encoding)
        return prefix+sig_out

class VerifyingKey(object):
    def __init__(self, vk_bytes):
        if not isinstance(vk_bytes, type("")):
            raise TypeError("must be bytes, not %s" % type(vk_bytes))
        if len(vk_bytes) != 32:
            raise ValueError("must be exactly 32 bytes")
        self.vk_bytes = vk_bytes

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.vk_bytes == self.vk_bytes)

    def verify(self, sig, msg, prefix="", encoding=None):
        assert isinstance(sig, type("")) # string, really bytes
        if encoding:
            sig = from_ascii(sig, prefix, encoding)
        else:
            sig = remove_prefix(sig, prefix)
        assert len(sig) == 64
        sig_R = sig[:32]
        sig_S = sig[32:]
        sig_and_msg = sig_R + sig_S + msg
        # this might raise BadSignatureError
        msg2 = _ed25519.open(sig_and_msg, self.vk_bytes)
        assert msg2 == msg

def selftest():
    from binascii import unhexlify, hexlify
    message = "crypto libraries should always test themselves at powerup"
    sk_bytes = unhexlify("548b1f9f938519ad3d527d8c47a1e6ec1439fbec61710b245363865c6f234899")
    sk = SigningKey(sk_bytes)
    vk_bytes = unhexlify("787162d9ad1ad571237681560c1ad653fb7df9e09e637e6a8072e4520fd288ca")
    vk = VerifyingKey(vk_bytes)
    assert sk.get_verifying_key_bytes() == vk_bytes
    sig = sk.sign(message, prefix="sig0-", encoding="base64")
    assert sig == "sig0-E/QrwtSF52x8+q0l4ahA7eJbRKc777ClKNg217Q0z4fiYMCdmAOI+rTLVkiFhX6k3D+wQQfKdJYMxaTUFfv1DQ", sig
    vk.verify(sig, message, prefix="sig0-", encoding="base64")

selftest()
