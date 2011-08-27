
import _ed25519
BadSignatureError = _ed25519.BadSignatureError

def create_keypair():
    # this is the only way to generate a SigningKey. The underlying library
    # does not offer a way to make a key from a seed, and uses /dev/urandom
    # directly.
    vk_s, sk_s = _ed25519.keypair();
    assert len(vk_s) == 32
    assert len(sk_s) == 64
    return SigningKey(sk_s), VerifyingKey(vk_s)

class SigningKey(object):
    # this can only be used to reconstruct a key created by create_keypair().
    def __init__(self, sk_s):
        assert isinstance(sk_s, type("")) # string, really bytes
        if len(sk_s) == 32:
            # create from seed
            vk_s, sk_s = _ed25519.publickey(sk_s)
        else:
            if len(sk_s) != 32+32:
                raise ValueError("SigningKey takes 32-byte seed or 64-byte string")
        self.sk_s = sk_s # seed+pubkey
        self.vk_s = sk_s[32:] # just pubkey

    def to_string(self):
        return self.sk_s

    def to_seed(self):
        return self.sk_s[:32]

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.sk_s == self.sk_s)

    def get_verifying_key(self):
        return VerifyingKey(self.vk_s)

    def sign(self, msg):
        sig_and_msg = _ed25519.sign(msg, self.sk_s)
        # the response is R+S+msg
        sig_R = sig_and_msg[0:32]
        sig_S = sig_and_msg[32:64]
        msg_out = sig_and_msg[64:]
        sig_out = sig_R + sig_S
        assert msg_out == msg
        return sig_out

class VerifyingKey(object):
    def __init__(self, vk_s):
        assert isinstance(vk_s, type("")) # string, really bytes
        assert len(vk_s) == 32
        self.vk_s = vk_s

    def to_string(self):
        return self.vk_s

    def __eq__(self, them):
        if not isinstance(them, object): return False
        return (them.__class__ == self.__class__
                and them.vk_s == self.vk_s)

    def verify(self, sig, msg):
        assert isinstance(sig, type("")) # string, really bytes
        assert len(sig) == 64
        sig_R = sig[:32]
        sig_S = sig[32:]
        sig_and_msg = sig_R + sig_S + msg
        # this might raise BadSignatureError
        msg2 = _ed25519.open(sig_and_msg, self.vk_s)
        assert msg2 == msg

