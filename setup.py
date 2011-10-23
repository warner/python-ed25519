
import os
from distutils.core import setup, Extension

LONG_DESCRIPTION="""\
Python bindings to the Ed25519 public-key signature system.

This offers a comfortable python interface to a C implementation of the
Ed25519 public-key signature system (http://ed25519.cr.yp.to/), using the
portable 'ref' code from the 'SUPERCOP' benchmarking suite.

This system provides high (128-bit) security, short (32-byte) keys, short
(64-byte) signatures, and fast (2-6ms) operation. Please see the README for
more details.
"""

sources = ["ed25519module.c"]
sources.extend(["src/"+s for s in os.listdir("src")
                if s.endswith(".c") and s!="test.c"])

m = Extension("_ed25519", include_dirs=["src"], sources=sources)

setup(name="ed25519",
      version="0.3",
      description="Ed25519 public-key signatures",
      long_description=LONG_DESCRIPTION,
      author="Brian Warner",
      author_email="warner-python-ed25519@lothar.com",
      license="MIT",
      url="https://github.com/warner/python-ed25519",
      ext_modules=[m],
      py_modules=["ed25519"],
      scripts=["bin/edsig"],
      )
