all: modeEval.c
	gcc modeEval.c -o evaluateModes -lssl -lcrypto -Wno-deprecated-declarations -lpthread

run: evaluateModes
	./evaluateModes

clean: 
	rm evaluateModes
