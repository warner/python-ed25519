
import os
from distutils.core import setup, Extension

sources = ["ed25519module.c"]
sources.extend(["src/"+s for s in os.listdir("src")
                if s.endswith(".c") and s!="test.c"])
   

m = Extension("_ed25519", include_dirs=["src"], sources=sources)

setup(name="ed25519",
      version="0.1",
      description="Ed25519 public-key signatures",
      ext_modules=[m],
      py_modules=["ed25519"],
      scripts=["bin/edsig"],
      )
