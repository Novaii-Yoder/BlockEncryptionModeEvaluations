all: modeEval.c
	gcc modeEval.c -o modeEval -lssl -lcrypto -Wno-deprecated-declarations

run: modeEval
	./modeEval

clean: 
	rm modeEval
