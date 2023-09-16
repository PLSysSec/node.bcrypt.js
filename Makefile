build:
	-cd original && make build
	-cd rlbox && make build
	-npm i
bench:
	@echo "Running benchmark!"
	node bench.js
	cloc --count-and-diff original/src/bcrypt_node.cc rlbox/src/bcrypt_node.cc
clean:
	-cd original && make clean
	-cd rlbox && make clean
