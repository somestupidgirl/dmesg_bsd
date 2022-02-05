.PHONY: all clean

all:
	$(MAKE) -C libkvm
	$(MAKE) -C dmesg

clean:
	$(MAKE) -C libkvm clean
	$(MAKE) -C dmesg clean
