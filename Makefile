GPGME_CFLAGS ?= $(shell pkg-config --cflags gpgme 2>/dev/null)
GPGME_LIBS ?= $(shell pkg-config --libs gpgme 2>/dev/null)

HELPER_OBJ = src/ext/gpgme_helpers.o

.PHONY: all clean

all: $(HELPER_OBJ)

$(HELPER_OBJ): src/ext/gpgme_helpers.c
	$(CC) $(GPGME_CFLAGS) -fPIC -c $< -o $@

clean:
	rm -f $(HELPER_OBJ)
