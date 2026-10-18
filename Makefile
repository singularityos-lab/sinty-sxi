PREFIX ?= /usr

.PHONY: all build test vet install clean

all: build

build:
	go build -o sxi ./cmd/sxi
	go build -o sxid ./cmd/sxid

test:
	go test ./...

vet:
	go vet ./...

install: build
	install -Dm755 sxi $(DESTDIR)$(PREFIX)/bin/sxi
	install -Dm755 sxid $(DESTDIR)$(PREFIX)/libexec/sxid
	install -Dm644 packaging/sxid.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sxid.service
	install -Dm644 packaging/dev.sinty.SXI1.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/dev.sinty.SXI1.conf
	install -d $(DESTDIR)$(PREFIX)/share/sinty/sxi/roots $(DESTDIR)$(PREFIX)/share/sinty/sxi/sources.d

clean:
	rm -f sxi sxid
