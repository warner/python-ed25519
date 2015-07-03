from .keys import (BadSignatureError, BadPrefixError,
                  create_keypair, SigningKey, VerifyingKey,
                  remove_prefix, to_ascii, from_ascii)

(BadSignatureError, BadPrefixError,
 create_keypair, SigningKey, VerifyingKey,
 remove_prefix, to_ascii, from_ascii) # hush pyflakes

from ._version import get_versions
__version__ = str(get_versions()['version'])
del get_versions
