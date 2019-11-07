build:
	-cd original && make build
	-cd rlbox && make build
	-npm i
bench:
	node bench.js
	cloc --count-and-diff {original,rlbox}/src/bcrypt_node.cc
clean:
	-cd original && make clean
	-cd rlbox && make clean
