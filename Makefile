CC = gcc
CFLAGS = -Wall -Werror -Iinclude
LDFLAGS = -lws2_32
SRC = src/main.c src/utils/config.c src/utils/logger.c src/core/proxy.c src/core/server.c src/core/client.c src/http/http_processor.c src/core/threadpool.c src/utils/ssl_utils.c src/utils/proxy_routes.c
OBJ = build/main.o build/utils/config.o build/utils/logger.o build/core/proxy.o build/core/server.o build/core/client.o build/http/http_processor.o build/core/threadpool.o build/utils/ssl_utils.c build/utils/proxy_routes.c
OUT = main

all: $(OUT)
	@cd build && $(OUT).exe


$(OUT): $(OBJ)
	@if not exist tests mkdir tests
	$(CC) -o build\$(OUT).exe $^ $(LDFLAGS)

build/main.o: src/main.c
	@if not exist build mkdir build
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/config.o: src/utils/config.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/logger.o: src/utils/logger.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/config.o: src/utils/ssl_utils.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@


build/utils/config.o: src/utils/proxy_routes.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/core/proxy.o: src/core/proxy.c
	@if not exist build\core mkdir build\core
	$(CC) $(CFLAGS) -c $< -o $@

build/core/threadpool.o: src/core/threadpool.c
	@if not exist build\core mkdir build\core
	$(CC) $(CFLAGS) -c $< -o $@

build/core/server.o: src/core/server.c
	@if not exist build\core mkdir build\core
	$(CC) $(CFLAGS) -c $< -o $@

build/core/client.o: src/core/client.c
	@if not exist build\core mkdir build\core
	$(CC) $(CFLAGS) -c $< -o $@

build/http/http_processor.o: src/http/http_processor.c
	@if not exist build\http mkdir build\http
	$(CC) $(CFLAGS) -c $< -o $@	

clean:
	del build\main.o build\utils\config.o build\utils\logger.o 
	build\utils\ssl_utils.o build\utils\proxy_routes.o build\core\proxy.o build\core\server.o build\core\threadpool.o build\core\client.o build\http\http_processor.o build\$(OUT).exe