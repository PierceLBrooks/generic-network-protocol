#pragma once
#define _WITH_DPRINTF

#include <stdio.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <uv.h>
#include "platform.h"

typedef struct server_state server_state_t;
typedef struct connection_handler connection_handler_t;
typedef struct err err_t;
typedef struct tls_uv_connection_state tls_uv_connection_state_t;

#define CONNECTION_STATUS_INIT_DONE 0x1
#define CONNECTION_STATUS_WRITE_AND_ABORT 0x2
#define MSG_SIZE 8192

typedef struct tls_uv_connection_state {
    struct {
        server_state_t* server;
        uv_tcp_t* handle;
        SSL *ssl;
        BIO *read, *write;
        struct {
            tls_uv_connection_state_t** prev_holder;
            tls_uv_connection_state_t* next;
            int in_queue;
            size_t pending_writes_count;
            uv_buf_t* pending_writes_buffer;
        } pending;
        size_t used_buffer, to_scan;
        int flags;
    };
	char user_data[64];
	char buffer[MSG_SIZE];
} tls_uv_connection_state_t;

// commands

typedef struct header {
	char* key;
	char* value;
} header_t;

typedef struct cmd {
	tls_uv_connection_state_t* connection;
	char** argv;
	int argc;
	struct header* headers;
	int headers_count;
	char* sequence;

	char* cmd_buffer;
} cmd_t;

void cmd_drop(cmd_t * cmd);

// error handling

typedef struct err {
	err_t* next;
	char* msg;
	size_t len;
	int code;

	const char* file, *func;
	int line;
} err_t;

void push_error_internal(const char* file, int line, const char *func, int code, const char* format, ...);

#define push_error(code, format, ...) push_error_internal(__FILE__, __LINE__, __func__, code, format, ##__VA_ARGS__)

typedef void(*error_callback)(err_t* e, void * u);

void consume_errors(error_callback cb, void * u);

void print_all_errors(void);

void push_ssl_errors();

void push_libuv_error(int rc, const char* operation, ...);

// ssl

#define THUMBPRINT_HEX_LENGTH 41 // 40 chars + null terminator

typedef struct server_state_init {
	const char* cert;
	const char* key;
	const char* address;
	int port;
	connection_handler_t* handler;
	char* known_thumprints[THUMBPRINT_HEX_LENGTH];
	int known_thumprints_count;

} server_state_init_t;

server_state_t* server_state_create(server_state_init_t* options);

void server_state_drop(server_state_t* s);

typedef struct connection_handler {

	void(*failed_connection)(void);

	void (*connection_error)(tls_uv_connection_state_t* connection);

	tls_uv_connection_state_t*  (*create_connection)(void);

	int (*connection_recv)(tls_uv_connection_state_t* connection, cmd_t* cmd);

} connection_handler_t;

int server_state_run(server_state_t* s);

// network
int connection_reply(cmd_t* c, void* buf, size_t len);

int connection_reply_format(cmd_t* c, const char* format, ...);


// util

int vasprintf(char **strp, const char *format, va_list ap);

int asprintf(char **strp, const char *format, ...);
