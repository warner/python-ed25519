import os
import base64
import _ed25519
BadSignatureError = _ed25519.BadSignatureError

def create_keypair(entropy=os.urandom):
    SEEDLEN = _ed25519.SECRETKEYBYTES/2
    assert SEEDLEN == 32
    seed = entropy(SEEDLEN)
    sk = SigningKey(seed)
    vk = sk.get_verifying_key()
    return sk, vk

class BadPrefixError(Exception):
    pass

def remove_prefix(s_bytes, prefix):
    if not s_bytes.startswith(prefix):
        raise BadPrefixError("did not see expected '%s' prefix" % prefix)
    return s_bytes[len(prefix):]

def to_ascii(s_bytes, prefix="", encoding="base64"):
    """Return a version-prefixed ASCII representation of the given binary
    string. 'encoding' indicates how to do the encoding, and can be one of:
     * base64
     * base62
     * base32
     * base16 (or hex)

    This function handles bytes, not bits, so it does not append any trailing
    '=' (unlike standard base64.b64encode). It also lowercases the base32
    output. base62 is nearly as compact as base64, but lacks the unfriendly
    punctuation characters.

    'prefix' will be prepended to the encoded form, and is useful for
    distinguishing the purpose and version of the binary string. E.g. you
    could prepend 'pub0-' to a VerifyingKey string to allow the receiving
    code to raise a useful error if someone pasted in a signature string by
    mistake.
    """
    if encoding == "base64":
        s_ascii = base64.b64encode(s_bytes).rstrip("=")
    elif encoding == "base62":
        raise NotImplementedError
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
        s_ascii += "="*{0:0, 1:"?", 2:2, 3:1}[len(s_ascii)%4]
        s_bytes = base64.b64decode(s_ascii)
    elif encoding == "base62":
        raise NotImplementedError
    elif encoding == "base32":
        s_ascii += "="*{0:0, 1:"?", 2:6, 3:"?",
                        4:4, 5:3, 6:"?", 7:1}[len(s_ascii)%8]
        s_bytes = base64.b32decode(s_ascii.upper())
    elif encoding in ("base16", "hex"):
        s_bytes = base64.b16decode(s_ascii.upper())
    else:
        raise NotImplementedError
    return s_bytes

class SigningKey(object):
    # this can only be used to reconstruct a key created by create_keypair().
    def __init__(self, sk_s, prefix="", encoding=None):
        assert isinstance(sk_s, type("")) # string, really bytes
        sk_s = remove_prefix(sk_s, prefix)
        if encoding is not None:
            sk_s = from_ascii(sk_s, encoding=encoding)
        if len(sk_s) == 32:
            # create from seed
            vk_s, sk_s = _ed25519.publickey(sk_s)
        else:
            if len(sk_s) != 32+32:
                raise ValueError("SigningKey takes 32-byte seed or 64-byte string")
        self.sk_s = sk_s # seed+pubkey
        self.vk_s = sk_s[32:] # just pubkey

    def to_bytes(self, prefix=""):
        return prefix+self.sk_s

    def to_ascii(self, prefix="", encoding=None):
        assert encoding
        return to_ascii(self.sk_s, prefix, encoding)

    def to_seed(self, prefix=""):
        return prefix+self.sk_s[:32]

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.sk_s == self.sk_s)

    def get_verifying_key(self):
        return VerifyingKey(self.vk_s)

    def sign(self, msg, prefix="", encoding=None):
        sig_and_msg = _ed25519.sign(msg, self.sk_s)
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
    def __init__(self, vk_s, prefix="", encoding=None):
        assert isinstance(vk_s, type("")) # string, really bytes
        vk_s = remove_prefix(vk_s, prefix)
        if encoding is not None:
            vk_s = from_ascii(vk_s, encoding=encoding)

        assert len(vk_s) == 32
        self.vk_s = vk_s

    def to_bytes(self, prefix=""):
        return prefix+self.vk_s

    def to_ascii(self, prefix="", encoding=None):
        assert encoding
        return to_ascii(self.vk_s, prefix, encoding)

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.vk_s == self.vk_s)

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
        msg2 = _ed25519.open(sig_and_msg, self.vk_s)
        assert msg2 == msg

