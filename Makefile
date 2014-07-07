TARGET = bbgtest
LIBS = -lpbc -lgmp
CC = gcc
CFLAGS = -Wall

.PHONY: clean all default

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

test: all
	./$(TARGET)

clean:
	-rm -f *.o
	-rm -f $(TARGET)