CC = gcc
CFLAGS = -Wall -Werror -I../include
LDFLAGS = -L../lib
LIBS = -lpthread -lssl -lcrypto
SRC = main.c config.c server.c logger.c
OBJ = $(SRC:.c=.o)
OUT = main

all: $(OUT)

$(OUT): $(OBJ)
    $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@