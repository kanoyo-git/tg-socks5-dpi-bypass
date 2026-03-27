CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -shared -ldl -lpthread
TARGET = socks5_dpi_bypass.so
SRC = socks5_dpi_bypass.c

PREFIX ?= /usr/local

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/lib/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET)