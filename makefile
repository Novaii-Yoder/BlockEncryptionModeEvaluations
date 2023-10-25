all: modeEval.c
	gcc modeEval.c -o evaluateModes -lssl -lcrypto -Wno-deprecated-declarations -lpthread

run: evaluateModes
	./evaluateModes

clean: 
	rm evaluateModes

thread: tpooltest.c tpool.c tpool.h
	gcc tpooltest.c tpool.c -o tpooltest -lpthread

runthread: tpooltest
	./tpooltest
