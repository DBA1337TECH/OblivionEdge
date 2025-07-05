# Makefile for SMTP/POP3 Server

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = smtp_server
SRC = smtp_server.c
LIBS = 

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) *.o *.gz *.log *.enc debug_email_*.gz

.PHONY: all clean
