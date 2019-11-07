TESTS = test/*.js

all: test

build: clean compile

compile: bcrypt.so
	npm install .
	npm run install

bcrypt.so: src/bcrypt.cc src/blowfish.cc
	$(CC) $(CFLAGS) -g3 -Wall -shared -fPIC $^ -o $@


test: build
	@./node_modules/nodeunit/bin/nodeunit \
		$(TESTS)

clean:
	rm -Rf lib/bindings/
	-rm -rf bcrypt.so


.PHONY: clean test build
