CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -maes \
  -march=native -mtune=native -O3 -fomit-frame-pointer

LIBS = -lzmq -lssl -lcrypto -loqs

all: main

main: 
	g++ main.cpp $(LIBS) -o bin/$@

.PHONY: clean

clean:
	rm -f bin/main

