TESTS = test/*.js

SANDBOXING_NACL_DIR=$(shell realpath ../../Sandboxing_NaCl)
NACL_CLANG32=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/i686-nacl-clang
NACL_CLANG64=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/x86_64-nacl-clang
NACL_AR32=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/i686-nacl-ar
NACL_AR64=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/x86_64-nacl-ar
NACL_STRIP32=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/i686-nacl-strip
NACL_STRIP64=$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/bin/x86_64-nacl-strip
NACL_CLANG++32=$(NACL_CLANG32)++
NACL_CLANG++64=$(NACL_CLANG64)++
NACL_VERIFER=$(SANDBOXING_NACL_DIR)/native_client/scons-out/opt-linux-x86-64/staging/ncval_new

all: test

build: compile

compile: bcrypt.so bcrypt.nexe
	npm install .
	npm run install

bcrypt.so: src/bcrypt.cc src/blowfish.cc
	$(CC) $(CFLAGS) -O3 -shared -fPIC $^ -o $@

bcrypt.nexe: src/bcrypt.cc src/blowfish.cc
	$(NACL_CLANG++64) $(CFLAGS) -O3 -fPIC src/bcrypt.cc -c -o bcrypt_nacl1.o
	$(NACL_CLANG++64) $(CFLAGS) -O3 -fPIC src/blowfish.cc -c -o bcrypt_nacl2.o
	$(NACL_CLANG++64) -fPIC -m64 -B$(SANDBOXING_NACL_DIR)/native_client/scons-out/nacl-x86-64/lib/ -Wl,-rpath-link,$(SANDBOXING_NACL_DIR)/native_client/scons-out/nacl-x86-64/lib -Wl,-rpath-link,$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/x86_64-nacl/lib -Wl,-rpath-link,$(SANDBOXING_NACL_DIR)/native_client/scons-out/nacl-x86-64/lib bcrypt_nacl*.o -L$(SANDBOXING_NACL_DIR)/native_client/scons-out/nacl-x86-64/lib -L$(SANDBOXING_NACL_DIR)/native_client/toolchain/linux_x86/pnacl_newlib/x86_64-nacl/lib -L$(SANDBOXING_NACL_DIR)/native_client/scons-out/nacl-x86-64/lib -ldyn_ldr_sandbox_init -o $@
	$(NACL_VERIFER) $@

test: build
	@./node_modules/nodeunit/bin/nodeunit \
		$(TESTS)

clean:
	-rm -rf lib/bindings/
	-rm -rf bcrypt.so
	-rm -rf bcrypt.nexe
	-rm -rf ./mainCombine

.PHONY: clean test build
