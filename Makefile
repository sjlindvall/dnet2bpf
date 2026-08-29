PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
SYSTEMD_DIR ?= /etc/systemd/system
DESTDIR ?=

CLANG ?= clang
CC ?= cc
PKG_CONFIG ?= pkg-config
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MULTIARCH ?= $(shell $(CC) -dumpmachine)

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
	-Iinclude -I/usr/include/$(MULTIARCH)

USER_CFLAGS := -O2 -g -Wall -Wextra -Werror -Iinclude \
	$(shell $(PKG_CONFIG) --cflags libbpf)

USER_LIBS := $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

BPF_OBJECTS := build/dnet2_rx.bpf.o build/dnet2_tx.bpf.o

.PHONY: all clean install uninstall check

all: build/dnet2d $(BPF_OBJECTS)

build:
	mkdir -p $@

build/%.bpf.o: bpf/%.bpf.c include/dnet2_shared.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/dnet2d: src/dnet2d.c include/dnet2_shared.h | build
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

check: all
	$(CLANG) --version | head -1
	$(PKG_CONFIG) --modversion libbpf
	file $(BPF_OBJECTS) build/dnet2d

install: all
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(PREFIX)/lib/dnet2-bpf \
		$(DESTDIR)$(PREFIX)/share/doc/dnet2-bpf
	install -m 0755 build/dnet2d $(DESTDIR)$(SBINDIR)/dnet2d
	install -m 0644 $(BPF_OBJECTS) $(DESTDIR)$(PREFIX)/lib/dnet2-bpf/
	install -m 0644 README.md $(DESTDIR)$(PREFIX)/share/doc/dnet2-bpf/README.md
	install -d $(DESTDIR)$(SYSCONFDIR)/dnet2
	@if [ ! -e $(DESTDIR)$(SYSCONFDIR)/dnet2/dnet2.conf ]; then \
		install -m 0644 config/dnet2.conf $(DESTDIR)$(SYSCONFDIR)/dnet2/dnet2.conf; \
	else echo "Preserving existing dnet2.conf"; fi
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -m 0644 systemd/dnet2.service $(DESTDIR)$(SYSTEMD_DIR)/dnet2.service
	@echo "Installed. Review /etc/dnet2/dnet2.conf, then run:"
	@echo "  sudo systemctl daemon-reload && sudo systemctl enable --now dnet2"

uninstall:
	-systemctl stop dnet2.service 2>/dev/null
	rm -f $(DESTDIR)$(SBINDIR)/dnet2d
	rm -f $(DESTDIR)$(PREFIX)/lib/dnet2-bpf/dnet2_rx.bpf.o
	rm -f $(DESTDIR)$(PREFIX)/lib/dnet2-bpf/dnet2_tx.bpf.o
	rmdir $(DESTDIR)$(PREFIX)/lib/dnet2-bpf 2>/dev/null || true
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/dnet2.service
	rm -f $(DESTDIR)$(PREFIX)/share/doc/dnet2-bpf/README.md
	rmdir $(DESTDIR)$(PREFIX)/share/doc/dnet2-bpf 2>/dev/null || true
	@echo "Configuration retained at $(SYSCONFDIR)/dnet2/dnet2.conf"

clean:
	rm -rf build
