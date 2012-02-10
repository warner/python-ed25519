from keys import (BadSignatureError, BadPrefixError,
                  SigningKey, VerifyingKey,
                  remove_prefix, to_ascii, from_ascii)

(BadSignatureError, BadPrefixError,
 SigningKey, VerifyingKey,
 remove_prefix, to_ascii, from_ascii) # hush pyflakes

from _version import get_versions
__version__ = get_versions()['version']
del get_versions
