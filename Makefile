CC = gcc
CFLAGS = -Wall -Werror -Iinclude
SRC = src/main.c src/config.c
OBJ = $(patsubst src/%.c,build/%.o,$(SRC))
OUT = main

all: $(OUT)
	@cd tests && $(OUT).exe

$(OUT): $(OBJ)
	$(CC) -o tests\$(OUT).exe $^

build/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del build\*.o tests\$(OUT).exe