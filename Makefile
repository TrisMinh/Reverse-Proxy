CC = gcc
CFLAGS = -Wall -Werror -Iinclude
SRC = src/main.c src/utils/config.c src/utils/logger.c 
OBJ = build/main.o build/utils/config.o build/utils/logger.o 
OUT = main

all: $(OUT)
	@cd tests && $(OUT).exe

$(OUT): $(OBJ)
	@if not exist tests mkdir tests
	$(CC) -o tests\$(OUT).exe $^

build/main.o: src/main.c
	@if not exist build mkdir build
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/config.o: src/utils/config.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/logger.o: src/utils/logger.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del build\main.o build\utils\config.o build\utils\logger.o tests\$(OUT).exe