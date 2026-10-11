# Makefile for building the C Entropy Analyzer Shared Library
# Cross-platform support for Linux, macOS, and Windows

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -std=c99

# Detect operating system
ifeq ($(OS),Windows_NT)
    TARGET = libentropy.dll
    LDFLAGS = -shared -Wl,--out-implib,libentropy.a
    RM = del /Q /F
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        TARGET = libentropy.dylib
        LDFLAGS = -shared -fPIC
    else
        TARGET = libentropy.so
        LDFLAGS = -shared -fPIC
    endif
    RM = rm -f
    CFLAGS += -fPIC
endif

all: $(TARGET)

$(TARGET): entropy_analyzer.c entropy_analyzer.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) entropy_analyzer.c -lm

clean:
	$(RM) $(TARGET) *.o *.a
