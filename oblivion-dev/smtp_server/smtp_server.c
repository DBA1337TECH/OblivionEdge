#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>

#define DEFAULT_PORT 2525
#define POP3_PORT 110
#define BUFFER_SIZE 1024

char encryption_key[BUFFER_SIZE] = "";
char forward_dns[BUFFER_SIZE] = "";
char bind_address[BUFFER_SIZE] = "0.0.0.0";
int enable_pop3 = 0;

void* pop3_thread(void* arg) {
    int pop_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    (void)arg;

    pop_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (pop_sock < 0) {
        perror("POP3 socket creation failed");
        pthread_exit(NULL);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(bind_address);
    server_addr.sin_port = htons(POP3_PORT);

    if (bind(pop_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("POP3 bind failed");
        close(pop_sock);
        pthread_exit(NULL);
    }

    if (listen(pop_sock, 5) < 0) {
        perror("POP3 listen failed");
        close(pop_sock);
        pthread_exit(NULL);
    }

    printf("POP3 server listening on %s:%d...\n", bind_address, POP3_PORT);

    while (1) {
        client_sock = accept(pop_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("POP3 accept failed");
            continue;
        }

        send(client_sock, "+OK POP3 Server Ready\r\n", 24, 0);

        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            int len = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
            if (len <= 0) break;
            buffer[len] = '\0';
            printf("POP3 Client: %s", buffer);

            if (strncmp(buffer, "USER", 4) == 0) {
                send(client_sock, "+OK User accepted\r\n", 20, 0);
            } else if (strncmp(buffer, "PASS", 4) == 0) {
                send(client_sock, "+OK Pass accepted\r\n", 20, 0);
            } else if (strncmp(buffer, "STAT", 4) == 0) {
                send(client_sock, "+OK 0 0\r\n", 8, 0);
            } else if (strncmp(buffer, "LIST", 4) == 0) {
                send(client_sock, "+OK\r\n.\r\n", 8, 0);
            } else if (strncmp(buffer, "RETR", 4) == 0) {
                send(client_sock, "+OK Message follows\r\n\r\nHello!\r\n.\r\n", 36, 0);
            } else if (strncmp(buffer, "QUIT", 4) == 0) {
                send(client_sock, "+OK Bye\r\n", 9, 0);
                break;
            } else {
                send(client_sock, "-ERR Unrecognized command\r\n", 28, 0);
            }
        }

        close(client_sock);
        printf("POP3 connection closed.\n");
    }

    close(pop_sock);
    pthread_exit(NULL);
}

void handle_client(int client_sock, struct sockaddr_in client_info) {
    char buffer[BUFFER_SIZE];
    char mail_from[BUFFER_SIZE] = "";
    char rcpt_to[BUFFER_SIZE] = "";
    char raw_email[BUFFER_SIZE * 16] = "";
    size_t email_offset = 0;

    send(client_sock, "220 Simple SMTP Server Ready\r\n", 31, 0);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int len = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
        if (len <= 0) break;

        buffer[len] = '\0';
        printf("Client: %s", buffer);

        if (strncmp(buffer, "EHLO", 4) == 0 || strncmp(buffer, "HELO", 4) == 0) {
            send(client_sock, "250-Hello\r\n250 OK\r\n", 20, 0);
        } else if (strncmp(buffer, "MAIL FROM:", 10) == 0) {
            strncpy(mail_from, buffer + 10, BUFFER_SIZE - 1);
            send(client_sock, "250 OK\r\n", 8, 0);
        } else if (strncmp(buffer, "RCPT TO:", 8) == 0) {
            strncpy(rcpt_to, buffer + 8, BUFFER_SIZE - 1);
            send(client_sock, "250 OK\r\n", 8, 0);
        } else if (strncmp(buffer, "DATA", 4) == 0) {
            send(client_sock, "354 End data with <CR><LF>.<CR><LF>\r\n", 38, 0);
            while (1) {
                memset(buffer, 0, BUFFER_SIZE);
                len = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
                if (len <= 0) break;
                buffer[len] = '\0';
                if (strcmp(buffer, ".\r\n") == 0) break;

                size_t blen = strlen(buffer);
                if (email_offset + blen < sizeof(raw_email)) {
                    memcpy(raw_email + email_offset, buffer, blen);
                    email_offset += blen;
                }
            }

            send(client_sock, "250 OK: message accepted\r\n", 27, 0);

            if (strlen(forward_dns) > 0) {
                char gzfile[128];
                time_t now = time(NULL);
                struct tm *t = localtime(&now);
                snprintf(gzfile, sizeof(gzfile), "debug_email_%04d%02d%02d_%02d%02d%02d.gz",
                         t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                         t->tm_hour, t->tm_min, t->tm_sec);

                FILE *gzip = popen("gzip > debug_email.tmp", "w");
                if (gzip) {
                    fwrite(raw_email, 1, email_offset, gzip);
                    pclose(gzip);
                    rename("debug_email.tmp.gz", gzfile);
                }

                char jsonbuf[BUFFER_SIZE * 4];
                snprintf(jsonbuf, sizeof(jsonbuf),
                         "{\n"
                         "  \"FROM\": \"%s\",\n"
                         "  \"TO\": \"%s\",\n"
                         "  \"src_ip\": \"%s\",\n"
                         "  \"dst_dns\": \"%s\",\n"
                         "  \"Contents\": \"%s\"\n"
                         "}\n",
                         mail_from, rcpt_to,
                         inet_ntoa(client_info.sin_addr),
                         forward_dns, gzfile);

                if (strlen(encryption_key) > 0) {
                    char cmd[BUFFER_SIZE * 2];
                    snprintf(cmd, sizeof(cmd),
         "openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:%s >> smtp_debug.json.enc", encryption_key);

                    FILE *enc = popen(cmd, "w");
                    if (enc) {
                        fwrite(jsonbuf, 1, strlen(jsonbuf), enc);
                        pclose(enc);
                    }
                } else {
                    FILE *jsonlog = fopen("smtp_debug.log", "a");
                    if (jsonlog) {
                        fwrite(jsonbuf, 1, strlen(jsonbuf), jsonlog);
                        fflush(jsonlog);
                        fclose(jsonlog);
                    }
                }
            }
        } else if (strncmp(buffer, "QUIT", 4) == 0) {
            send(client_sock, "221 Bye\r\n", 10, 0);
            break;
        } else {
            send(client_sock, "500 Unrecognized command\r\n", 27, 0);
        }
    }

    close(client_sock);
    printf("Connection closed.\n");
}

int main(int argc, char *argv[]) {
    int server_sock, client_sock, port = DEFAULT_PORT;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pthread_t pop3_tid;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc) {
            strncpy(forward_dns, argv[i + 1], BUFFER_SIZE - 1);
            i++;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            strncpy(bind_address, argv[i + 1], BUFFER_SIZE - 1);
            i++;
        } else if (strcmp(argv[i], "--pop3") == 0) {
            enable_pop3 = 1;
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            strncpy(encryption_key, argv[i + 1], BUFFER_SIZE - 1);
            i++;
        } else {
            printf("Usage: %s [--dns <forward_dns>] [--port <port>] [--bind <bind_address>] [--pop3] [--key <encryption_key>]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (enable_pop3) {
        if (pthread_create(&pop3_tid, NULL, pop3_thread, NULL) != 0) {
            perror("Failed to start POP3 thread");
            exit(EXIT_FAILURE);
        }
    }

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(bind_address);
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("SMTP server listening on %s:%d...\n", bind_address, port);
    if (strlen(forward_dns) > 0) {
        printf("Configured to forward messages via DNS resolution at: %s\n", forward_dns);
    }

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));
        handle_client(client_sock, client_addr);
    }

    close(server_sock);
    return 0;
}
