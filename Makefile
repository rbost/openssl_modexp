TARGET = modexp
LIBS = -lcrypto
CC = gcc
CFLAGS = -g -Wall
LINKFLAGS =

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

OPENSSL_INCLUDE ?= /usr/local/Cellar/openssl/1.0.2h_1/include/
OPENSSL_LIB ?= /usr/local/Cellar/openssl/1.0.2h_1/lib/

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@ -I$(OPENSSL_INCLUDE)

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LINKFLAGS) $(LIBS) -o $@ -L$(OPENSSL_LIB) -lcrypto

clean:
	-rm -f *.o
	-rm -f $(TARGET)
