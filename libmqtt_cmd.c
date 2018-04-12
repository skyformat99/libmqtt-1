/*
 * libmqtt_cmd.c -- sample mqtt client tool in command line.
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define LIBMQTT_IMPLEMENTATION
#include "libmqtt.h"

#include "lib/ae.h"
#include "lib/anet.h"

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

struct ae_io {
    int fd;
    long long timer_id;
    struct libmqtt *mqtt;
};

static char *host = "127.0.0.1";
static int port = 1883;

static void
__connack(struct libmqtt *mqtt, void *ud, int ack_flags, enum mqtt_connack return_code) {
    (void)mqtt;
    (void)ud;
    (void)ack_flags;

    if (return_code != CONNACK_ACCEPTED) {
        fprintf(stderr, "%s\n", MQTT_CONNACK_NAMES[return_code]);
        return;
    }

    printf("Connected (ack_flags: %d, return_code: %d)\n", ack_flags, return_code);
}

static void
__puback(struct libmqtt *mqtt, void *ud, uint16_t id) {
    (void)mqtt;
    (void)ud;

    printf("Published (id: %d)\n", id);
}

static void
__suback(struct libmqtt *mqtt, void *ud, uint16_t id, int count, enum mqtt_qos *qos) {
    int i;
    (void)mqtt;
    (void)ud;

    printf("Subscribed (id: %d): %d", id, qos[0]);
    for (i = 1; i < count; i++) {
        printf(", %d", qos[i]);
    }
    printf("\n");
}

static void
__publish(struct libmqtt *mqtt, void *ud, uint16_t id, const char *topic, enum mqtt_qos qos, int retain, const char *payload, int length) {
    (void)mqtt;
    (void)ud;
    (void)id;
    (void)topic;
    (void)qos;
    (void)retain;
    (void)payload;
    (void)length;

    printf("%.*s\n", length, payload);
}

static void
__close(aeEventLoop *el, struct ae_io *io) {
    if (AE_ERR != io->fd) {
        aeDeleteFileEvent(el, io->fd, AE_READABLE);
        close(io->fd);
    }
    if (AE_ERR != io->timer_id)
        aeDeleteTimeEvent(el, io->timer_id);
    free(io);
}

static void
__read(aeEventLoop *el, int fd, void *privdata, int mask) {
    struct ae_io *io;
    int nread;
    char buff[4096];
    int rc;
    (void)mask;

    io = (struct ae_io *)privdata;
    nread = read(fd, buff, sizeof(buff));
    if (nread == -1 && errno == EAGAIN) {
        return;
    }
    rc = LIBMQTT_SUCCESS;
    if (nread <= 0 || LIBMQTT_SUCCESS != (rc = libmqtt__read(io->mqtt, buff, nread))) {
        if (rc != LIBMQTT_SUCCESS)
            fprintf(stderr, "libmqtt__read: %s\n", libmqtt__strerror(rc));
        __close(el, io);
        aeStop(el);
    }
}

static int
__write(void *p, const char *data, int size) {
    struct ae_io *io;

    io = (struct ae_io *)p;
    return write(io->fd, data, size) > 0 ? 0 : -1;
}

static int
__update(aeEventLoop *el, long long id, void *privdata) {
    struct ae_io *io;
    int rc;
    (void)el;
    (void)id;

    io = (struct ae_io *)privdata;
    if (LIBMQTT_SUCCESS != (rc = libmqtt__update(io->mqtt))) {
        fprintf(stderr, "libmqtt__update: %s\n", libmqtt__strerror(rc));
        shutdown(io->fd, SHUT_WR);
        return AE_NOMORE;
    }
    return 1000;
}


static struct ae_io *
__connect(aeEventLoop *el, char *host, int port) {
    struct ae_io *io;
    int fd;
    long long timer_id;
    char err[ANET_ERR_LEN];

    fd = anetTcpConnect(err, host, port);
    if (ANET_ERR == fd) {
        fprintf(stderr, "anetTcpConnect: %s\n", err);
        goto e1;
    }
    anetNonBlock(0, fd);
    anetEnableTcpNoDelay(0, fd);
    anetTcpKeepAlive(0, fd);

    io = (struct ae_io *)malloc(sizeof *io);
    memset(io, 0, sizeof *io);

    if (AE_ERR == aeCreateFileEvent(el, fd, AE_READABLE, __read, io)) {
        fprintf(stderr, "aeCreateFileEvent: error\n");
        goto e2;
    }

    timer_id = aeCreateTimeEvent(el, 1000, __update, io, 0);
    if (AE_ERR == timer_id) {
        fprintf(stderr, "aeCreateTimeEvent: error\n");
        goto e3;
    }

    io->fd = fd;
    io->timer_id = timer_id;
    return io;

e3:
    aeDeleteFileEvent(el, fd, AE_READABLE);
e2:
    close(fd);
e1:
    return 0;
}

static void
__cmd_disconnect(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;
    (void)argc;
    (void)argv;

    libmqtt__disconnect(mqtt);
}

static void
__cmd_publish(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    uint16_t id;
    int rc;
    (void)el;

    if (argc < 4) {
        printf("Error argc\n");
        return;
    }

    rc = libmqtt__publish(mqtt, &id, atoi(argv[0]), atoi(argv[1]), argv[2], argv[3], strlen(argv[3]));
    if (rc != LIBMQTT_SUCCESS) {
        fprintf(stderr, "%s\n", libmqtt__strerror(rc));
        return;
    }
}

static void
__cmd_unsubscribe(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    uint16_t id;
    int rc;
    (void)el;

    if (argc > MQTT_MAX_SUB) {
        printf("Error argc\n");
        return;
    }

    rc = libmqtt__unsubscribe(mqtt, &id, argc, (const char **)argv);
    if (rc != LIBMQTT_SUCCESS) {
        fprintf(stderr, "%s\n", libmqtt__strerror(rc));
        return;
    }
}

static void
__cmd_subscribe(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    uint16_t id;
    int i, n, rc;
    const char *topic[MQTT_MAX_SUB];
    enum mqtt_qos qos[MQTT_MAX_SUB];
    (void)el;

    n = argc / 2;
    if (argc % 2 || n > MQTT_MAX_SUB) {
        printf("Error argc\n");
        return;
    }
    for (i = 0; i < n; i++) {
        topic[i] = argv[i*2];
        qos[i] = atoi(argv[i*2+1]);
    }

    rc = libmqtt__subscribe(mqtt, &id, n, topic, qos);
    if (rc != LIBMQTT_SUCCESS) {
        fprintf(stderr, "%s\n", libmqtt__strerror(rc));
        return;
    }
}

static void
__cmd_connect(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    struct ae_io *io;
    char *h;
    int p;
    int rc;

    if (argc >= 2) {
        h = argv[0];
        p = atoi(argv[1]);
    } else {
        h = host;
        p = port;
    }

    io = __connect(el, h, p);
    if (!io) {
        return;
    }
    io->mqtt = mqtt;
    rc = libmqtt__connect(mqtt, io, __write);
    if (rc != LIBMQTT_SUCCESS) {
        fprintf(stderr, "%s\n", libmqtt__strerror(rc));
        return;
    }
}

static void
__cmd_auth(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;

    if (argc < 2) {
        printf("Error argc\n");
        return;
    }

    libmqtt__auth(mqtt, argv[0], argv[1]);
}

static void
__cmd_will(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;

    if (argc < 4) {
        printf("Error argc\n");
        return;
    }

    libmqtt__will(mqtt, atoi(argv[0]), atoi(argv[1]), argv[2], argv[3], strlen(argv[3]));
}

static void
__cmd_keep_alive(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;

    if (argc < 1) {
        printf("Error argc\n");
        return;
    }

    libmqtt__keep_alive(mqtt, atoi(argv[0]));
}

static void
__cmd_clean_session(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;

    if (argc < 1) {
        printf("Error argc\n");
        return;
    }

    libmqtt__clean_session(mqtt, atoi(argv[0]));
}

static void
__cmd_version(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;

    if (argc < 1) {
        printf("Error argc\n");
        return;
    }

    if (!strcmp(argv[0], "mqttv31"))
        libmqtt__version(mqtt, MQTT_PROTO_V3);
    else if (!strcmp(argv[0], "mqttv311"))
        libmqtt__version(mqtt, MQTT_PROTO_V4);
    else {
        printf("Unknown mqtt version\n");
    }
}

static void
__cmd_exit(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)mqtt;
    (void)argc;
    (void)argv;

    aeStop(el);
}

static void
__cmd_help(aeEventLoop *el, struct libmqtt *mqtt, int argc, char *argv[]) {
    (void)el;
    (void)mqtt;
    (void)argc;
    (void)argv;

    printf("Possible command:\n\n"
           "\tversion <version>                         set mqtt version, mqttv31 or mqttv311, default: mqttv311.\n"
           "\tcleansession <clean_session>              set clean session flag for mqtt connection, 0 or 1, default: 1.\n"
           "\tkeepalive <keep_alive>                    set keep alive for mqtt connection, number, default: 30.\n"
           "\twill <retain> <qos> <topic> <payload>     set will message for mqtt connection, retain, qos, topic, payload.\n"
           "\tauth <username> <password>                set auth information for mqtt connection, username, password.\n"
           "\tconnect <host> <port>                     connect to mqtt broker, host port.\n"
           "\tsubscribe <topic> <qos> ...               subscribe topic/qos, topic qos ... .\n"
           "\tunsubscribe <topic> ...                   unsubscribe topic, topic ... .\n"
           "\tpublish <retain> <qos> <topic> <payload>  publish a message, topic qos retain payload.\n"
           "\tdisconnect                                disconnect from mqtt broker.\n"
          );
}

static struct cmd_handler {
    const char *cmd;
    void (*func)(aeEventLoop *, struct libmqtt *, int argc, char *argv[]);
} cmd_handlers[] = {
    {"help", __cmd_help},
    {"exit", __cmd_exit},
    {"version", __cmd_version},
    {"cleansession", __cmd_clean_session},
    {"keepalive", __cmd_keep_alive},
    {"will", __cmd_will},
    {"auth", __cmd_auth},
    {"connect", __cmd_connect},
    {"subscribe", __cmd_subscribe},
    {"unsubscribe", __cmd_unsubscribe},
    {"publish", __cmd_publish},
    {"disconnect", __cmd_disconnect},
};

static void
__eval(aeEventLoop *el, struct libmqtt *mqtt, char *cmdline) {
    char *cmd, *arg;
    char *argv[128];
    int argc;
    size_t i, n;

    cmd = strtok(cmdline, " ");
    if (!cmd) {
        return;
    }

    argc = 0;
    arg = strtok(0, " ");
    while (arg) {
        argv[argc++] = arg;
        arg = strtok(0, " ");
    }
    n = sizeof(cmd_handlers)/sizeof(struct cmd_handler);
    for (i = 0; i < n; i++) {
        if (0 == strcmp(cmd_handlers[i].cmd, cmd)) {
            cmd_handlers[i].func(el, mqtt, argc, argv);
            break;
        }
    }
    if (i == n) {
        printf("Unknown command\n");
    }
}

static void
__input(aeEventLoop *el, int fd, void *privdata, int mask) {
    struct libmqtt *mqtt;
    int nread;
    char cmdline[4096];
    (void)mask;

    mqtt = (struct libmqtt *)privdata;

    nread = read(fd, cmdline, sizeof(cmdline));
    if (nread == -1 && errno == EAGAIN) {
        return;
    }
    if (cmdline[nread-1] == '\r')
        cmdline[--nread] = '\0';
    if (cmdline[nread-1] == '\n')
        cmdline[--nread] = '\0';
    __eval(el, mqtt, cmdline);
}

static void
usage(const char *bin) {
    fprintf(stderr, "Usage: %s <client_id> [<options>]\n\n"
            "Possible options:\n\n"
            "\t-b <host>:<port>             Remote mqtt broker host and port to connect.\n"
            "\t-u <username>:<password>     Username and password auth information.\n"
            "\t-v <version>                 Version of mqtt session, mqttv31 or mqttv311, default mqttv311.\n"
            "\t-k <keep_alive>              KeepAlive of mqtt session, default 30.\n"
            "\t-c <clean_session>           CleanSession of mqtt session, default 1.\n"
            "\t-d                           Enable debug log.\n"
            "\t-h                           Print this message.\n",
            bin);
    exit(1);
}

int
main(int argc, char *argv[]) {
    struct libmqtt *mqtt;
    struct libmqtt_cb cb = {
        .connack = __connack,
        .puback = __puback,
        .suback = __suback,
        .publish = __publish,
    };
    extern char *optarg;
    char *c, *u, *p;
    int opt;

    if (argc < 2) {
        usage(argv[0]);
    }
    libmqtt__create(&mqtt, argv[1], 0, &cb);

    while ((opt = getopt(argc-1, argv+1, "b:u:v:k:c:dh")) != EOF) {
        switch (opt) {
        case 'b':
            c = strtok(optarg, ":");
            if (!c) {
                fprintf(stderr, "Illegal host:port.\n");
                exit(1);
            }
            host = c;
            c = strtok(0, ":");
            if (c)
                port = atoi(c);
            break;
        case 'u':
            u = strtok(optarg, ":");
            if (!u) {
                fprintf(stderr, "Illegal username:password.\n");
                exit(1);
            }
            p = strtok(0, ":");
            if (!p) {
                fprintf(stderr, "Illegal username:password.\n");
                exit(1);
            }
            libmqtt__auth(mqtt, u, p);
            break;
        case 'v':
            if (!strcmp(optarg, "mqttv31"))
                libmqtt__version(mqtt, MQTT_PROTO_V3);
            else if (!strcmp(optarg, "mqttv311"))
                libmqtt__version(mqtt, MQTT_PROTO_V4);
            else {
                fprintf(stderr, "Unknown mqtt version.\n");
                exit(1);
            }
            break;
        case 'k':
            libmqtt__keep_alive(mqtt, atoi(optarg));
            break;
        case 'c':
            libmqtt__clean_session(mqtt, atoi(optarg));
            break;
        case 'd':
            libmqtt__set_log_level(mqtt, LIBMQTT_LOG_DEBUG);
            break;
        case 'h':
        case '?':
            usage(argv[0]);
        }
    }

    aeEventLoop *el;

    el = aeCreateEventLoop(128);

    if (AE_ERR == aeCreateFileEvent(el, STDIN_FILENO, AE_READABLE, __input, mqtt)) {
        fprintf(stderr, "aeCreateFileEvent: error\n");
        exit(1);
    }

    aeMain(el);
    aeDeleteEventLoop(el);
    libmqtt__destroy(mqtt);
    return 0;
}

