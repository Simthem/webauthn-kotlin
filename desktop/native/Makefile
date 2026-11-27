# Builds libpqvault-sk.so and installs it with the helper under your home, without root.

CC ?= cc
CFLAGS ?= -O2 -g
PREFIX ?= $(HOME)/.local/lib/pqvault-ssh
BUILD := ../build/native
HELPER := ../build/install/pqvault-ssh-helper

WARNINGS := -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wconversion -Wno-sign-conversion
HARDENING := -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
LINK := -shared -Wl,-z,relro,-z,now -Wl,--no-undefined -ldl

.PHONY: all helper install uninstall clean

all: $(BUILD)/libpqvault-sk.so

$(BUILD)/libpqvault-sk.so: pqvault-sk.c
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(WARNINGS) $(HARDENING) -o $@ $< $(LDFLAGS) $(LINK)

helper:
	../../gradlew -p .. installHelper

install: all helper
	install -d -m 0755 $(PREFIX) $(PREFIX)/helper
	install -m 0644 $(BUILD)/libpqvault-sk.so $(PREFIX)/libpqvault-sk.so
	rm -rf $(PREFIX)/helper/bin $(PREFIX)/helper/lib $(PREFIX)/helper/runtime
	cp -R $(HELPER)/bin $(HELPER)/lib $(HELPER)/runtime $(PREFIX)/helper/

uninstall:
	rm -f $(PREFIX)/libpqvault-sk.so
	rm -rf $(PREFIX)/helper
	-rmdir $(PREFIX)

clean:
	rm -f $(BUILD)/libpqvault-sk.so
