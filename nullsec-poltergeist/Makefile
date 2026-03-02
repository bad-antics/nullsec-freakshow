CC = gcc
CFLAGS = -O2 -Wall -Wextra
TARGET = poltergeist

all: $(TARGET)

$(TARGET): poltergeist.c
	$(CC) $(CFLAGS) -o $(TARGET) poltergeist.c

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

clean:
	rm -f $(TARGET)

.PHONY: all install clean
