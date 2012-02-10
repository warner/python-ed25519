import os
import _ed25519
BadSignatureError = _ed25519.BadSignatureError

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

    def sign(self, msg):
        sig_and_msg = _ed25519.sign(msg, self.sk_and_vk)
        # the response is R+S+msg
        sig_R = sig_and_msg[0:32]
        sig_S = sig_and_msg[32:64]
        msg_out = sig_and_msg[64:]
        sig_out = sig_R + sig_S
        assert msg_out == msg
        return sig_out

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

    def verify(self, sig, msg):
        assert isinstance(sig, type("")) # string, really bytes
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
    sig = sk.sign(message)
    assert hexlify(sig) == "13f42bc2d485e76c7cfaad25e1a840ede25b44a73befb0a528d836d7b434cf87e260c09d980388fab4cb564885857ea4dc3fb04107ca74960cc5a4d415fbf50d"
    vk.verify(sig, message)

selftest()
