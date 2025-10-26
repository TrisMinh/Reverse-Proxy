CC = gcc

# === MySQL Connector/C (local) ===
MYSQL_INCLUDE = deps/mysql-c-connector/include
MYSQL_LIB = deps/mysql-c-connector/lib

CFLAGS = -Wall -Werror -Iinclude -I$(MYSQL_INCLUDE)
LDFLAGS = -lws2_32 -lssl -lcrypto -L$(MYSQL_LIB) -llibmysql
SRC = src/main.c \
	src/utils/config.c \
	src/utils/db_config.c \
	src/utils/logger.c \
	src/utils/proxy_routes.c \
	src/utils/ssl_utils.c \
	src/core/proxy.c \
	src/core/server.c \
	src/core/client.c \
	src/http/http_processor.c \
	src/http/acme_webroot.c \
	src/core/threadpool.c \
	src/security/filter_chain.c \
	src/security/filters/rate_limit.c \
	src/security/filters/acl_filter.c \
	src/security/filters/ipset.c
OBJ = build/main.o \
	build/utils/config.o \
	build/utils/db_config.o \
	build/utils/logger.o \
	build/utils/proxy_routes.o \
	build/utils/ssl_utils.o \
	build/core/proxy.o \
	build/core/server.o \
	build/core/client.o \
	build/http/http_processor.o \
	build/http/acme_webroot.o \
	build/core/threadpool.o \
	build/security/filter_chain.o \
	build/security/filters/rate_limit.o \
	build/security/filters/acl_filter.o \
	build/security/filters/ipset.o

OUT = main

all: $(OUT)
	@cd build && $(OUT).exe


$(OUT): $(OBJ)
	@if not exist build mkdir build
	$(CC) -o build\$(OUT).exe $^ $(LDFLAGS)
	@echo [COPY] libmysql.dll -> build\
	@copy /Y deps\mysql-c-connector\bin\libmysql.dll build\ >nul

build/main.o: src/main.c
	@if not exist build mkdir build
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/config.o: src/utils/config.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/db_config.o: src/utils/db_config.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/logger.o: src/utils/logger.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/proxy_routes.o: src/utils/proxy_routes.c
	@if not exist build\utils mkdir build\utils
	$(CC) $(CFLAGS) -c $< -o $@

build/utils/ssl_utils.o: src/utils/ssl_utils.c
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

build/http/acme_webroot.o: src/http/acme_webroot.c
	@if not exist build\http mkdir build\http
	$(CC) $(CFLAGS) -c $< -o $@	

build/security/filter_chain.o: src/security/filter_chain.c
	@if not exist build\security mkdir build\security
	$(CC) $(CFLAGS) -c $< -o $@

build/security/filters/rate_limit.o: src/security/filters/rate_limit.c
	@if not exist build\security\filters mkdir build\security\filters
	$(CC) $(CFLAGS) -c $< -o $@

build/security/filters/acl_filter.o: src/security/filters/acl_filter.c
	@if not exist build\security\filters mkdir build\security\filters
	$(CC) $(CFLAGS) -c $< -o $@

build/security/filters/ipset.o: src/security/filters/ipset.c
	@if not exist build\security\filters mkdir build\security\filters
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del 
	build\main.o 
	build\utils\config.o 
	build\utils\db_config.o 
	build\utils\logger.o 
	build/utils/proxy_routes.o
	build/utils/ssl_utils.o
	build\core\proxy.o 
	build\core\server.o 
	build\core\threadpool.o 
	build\core\client.o 
	build\http\http_processor.o 
	build/http/acme_webroot.o 
	build/security/filter_chain.o 
	build/security/filters/rate_limit.o 
	build/security/filters/acl_filter.o
	build/security/filters/ipset.o
	build\$(OUT).exe
