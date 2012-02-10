from keys import (BadSignatureError, SigningKey, VerifyingKey)

(BadSignatureError, SigningKey, VerifyingKey) # hush pyflakes

from _version import get_versions
__version__ = get_versions()['version']
del get_versions
