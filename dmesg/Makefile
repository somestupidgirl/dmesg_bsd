#
# Makefile for mount_emptyfs
#

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -I../libkvm
LDFLAGS = -L../libkvm -lkvm -lc
SOURCES = $(wildcard *.c)
EXECUTABLE = dmesg
RM= rm

all: debug

release: $(EXECUTABLE)

debug: CFLAGS += -g -DDEBUG
debug: release

$(EXECUTABLE): $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	$(RM) -rf *.o $(EXECUTABLE) *.dSYM

.PHONY: all debug release clean
