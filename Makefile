
build: ed25519module.c
	python setup.py build
BUILDDIR = build/lib.macosx-10.6-universal-2.6
PP= PYTHONPATH=build/lib.macosx-10.6-universal-2.6
TEST=Basic
test:
	@echo "run '$(MAKE) kat' to run the (slower) known-answer-tests"
	$(PP) python $(BUILDDIR)/ed25519/test.py $(TEST)
kat:
	$(PP) python test-kat.py

bench:
	@echo "Running benchmark tests.."
	@echo -n " keypair generation: "
	@$(PP) python -m timeit -n 1000 -s "import ed25519" "ed25519.create_keypair()"
	@echo -n " signing: "
	@$(PP) python -m timeit -n 1000 -s "import ed25519; sk,vk=ed25519.create_keypair(); msg='hello world'" "sk.sign(msg)"
	@echo -n " verifying: "
	@$(PP) python -m timeit -n 1000 -s "import ed25519; sk,vk=ed25519.create_keypair(); msg='hello world'; sig=sk.sign(msg)" "vk.verify(sig,msg)"

# on my laptop: keypair 6.57ms, sign 6.56ms, verify 17.3ms
# against the portable 'ref' code in NaCl-20110221

# using the SUPERCOP 'ref' code: keypair 1.9ms, sign 1.9ms, verify 6.3ms
