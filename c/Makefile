# Makefile for TAU-256 (C, using pre-generated S-boxes)
CC      ?= cc
CFLAGS  ?= -O2 -std=c99 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes
LDFLAGS ?=

BIN = tau256
SRC = tau256.c
HDR = tau256_sboxes.h

all: $(BIN)

$(BIN): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)
