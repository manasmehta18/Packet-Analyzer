CC=gcc
CFLAGS=-lpcap
TARGET=wireview

 
all:	wireview.o
	$(CC) -o $(TARGET) wireview.c $(CFLAGS)
 
clean:
	rm *.o $(TARGET)