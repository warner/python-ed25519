
import sys, os
from distutils.core import setup, Extension, Command
import versioneer
versioneer.versionfile_source = "src/ed25519/_version.py"
versioneer.versionfile_build = "ed25519/_version.py"
versioneer.tag_prefix = ""
versioneer.parentdir_prefix = "ed25519-"


LONG_DESCRIPTION="""\
Python bindings to the Ed25519 public-key signature system.

This offers a comfortable python interface to a C implementation of the
Ed25519 public-key signature system (http://ed25519.cr.yp.to/), using the
portable 'ref' code from the 'SUPERCOP' benchmarking suite.

This system provides high (128-bit) security, short (32-byte) keys, short
(64-byte) signatures, and fast (2-6ms) operation. Please see the README for
more details.
"""

sources = ["src/ed25519-glue/ed25519module.c"]
sources.extend(["src/ed25519-supercop-ref/"+s
                for s in os.listdir("src/ed25519-supercop-ref")
                if s.endswith(".c") and s!="test.c"])

m = Extension("ed25519/_ed25519",
              include_dirs=["src/ed25519-supercop-ref"], sources=sources)

from distutils.util import get_platform
class Test(Command):
    description = "run tests"
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        # copied from distutils/command/build.py
        self.plat_name = get_platform()
        plat_specifier = ".%s-%s" % (self.plat_name, sys.version[0:3])
        self.build_lib = os.path.join("build", "lib"+plat_specifier)
        sys.path.insert(0, self.build_lib)
        import ed25519.test
        import unittest
        test = unittest.defaultTestLoader.loadTestsFromModule(ed25519.test)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(test)
        sys.exit(not result.wasSuccessful())

commands = versioneer.get_cmdclass().copy()
commands["test"] = Test
setup(name="ed25519",
      version=versioneer.get_version(),
      description="Ed25519 public-key signatures",
      long_description=LONG_DESCRIPTION,
      author="Brian Warner",
      author_email="warner-python-ed25519@lothar.com",
      license="MIT",
      url="https://github.com/warner/python-ed25519",
      ext_modules=[m],
      packages=["ed25519"],
      package_dir={"ed25519": "src/ed25519"},
      scripts=["bin/edsig"],
      cmdclass=commands,
      )
