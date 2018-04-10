/*
 * libmqtt.h -- mqtt client library writen in c support mqttv31 and mqttv311.
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

#ifndef _LIBMQTT_H_
#define _LIBMQTT_H_

#ifdef __cplusplus
extern "C" {
#endif

/* generic includes. */
#include <stdint.h>
#include <sys/types.h>

#include "mqtt.h"

#if defined(__GNUC__) && (__GNUC__ >= 4)
# define LIBMQTT_API __attribute__((visibility("default")))
#else
# define LIBMQTT_API
#endif


#define LIBMQTT_SUCCESS             0       /* success. */

/* define errors. */
#define LIBMQTT_ERROR_NULL          -1      /* mqtt null pointer access. */
#define LIBMQTT_ERROR_QOS           -2      /* mqtt qos error. */
#define LIBMQTT_ERROR_WRITE         -3      /* mqtt io write error. */
#define LIBMQTT_ERROR_PARSE         -4		/* mqtt packet parse error. */
#define LIBMQTT_ERROR_TIMEOUT       -5		/* mqtt timeout error. */
#define LIBMQTT_ERROR_MAXSUB        -6      /* mqtt max topic/qos per subscribe or unsubscribe. */

/* default mqtt keep alive. */
#define LIBMQTT_DEF_KEEPALIVE       30

/* default mqtt packet retry time. */
#define LIBMQTT_DEF_TIMERETRY       3

/* libmqtt data structure. */
struct libmqtt;

/* libmqtt io write. */
typedef int (* libmqtt__io_write)(void *io, const char *data, int size);

/* libmqtt callbacks. */
typedef void (* libmqtt__on_connack)(struct libmqtt *, void *ud, int ack_flags, enum mqtt_connack return_code);
typedef void (* libmqtt__on_suback)(struct libmqtt *, void *ud, uint16_t id, int count, enum mqtt_qos *qos);
typedef void (* libmqtt__on_unsuback)(struct libmqtt *, void *ud, uint16_t id);
typedef void (* libmqtt__on_puback)(struct libmqtt *, void *ud, uint16_t id);
typedef void (* libmqtt__on_publish)(struct libmqtt *, void *ud, uint16_t id, const char *topic, enum mqtt_qos qos, int retain, const char *payload, int length);

/* libmqtt callback structure. */
struct libmqtt_cb {
    libmqtt__on_connack connack;
    libmqtt__on_suback suback;
    libmqtt__on_unsuback unsuback;
    libmqtt__on_puback puback;
    libmqtt__on_publish publish;
};

/* string error message for a libmqtt return code. */
extern LIBMQTT_API const char *libmqtt__strerror(int rc);

/* libmqtt log level enum. */
enum libmqtt_log_level {
    LIBMQTT_LOG_DEBUG,
    LIBMQTT_LOG_INFO,
    LIBMQTT_LOG_WARN,
    LIBMQTT_LOG_ERROR,
};

/* set a log for libmqtt. */
extern LIBMQTT_API void libmqtt__set_log(struct libmqtt *mqtt, void (* log)(void *ud, const char *str));
extern LIBMQTT_API void libmqtt__set_log_level(struct libmqtt *mqtt, enum libmqtt_log_level log_level);

/* generic libmqtt functions. */
extern LIBMQTT_API int libmqtt__create(struct libmqtt **mqtt, const char *client_id, void *ud, struct libmqtt_cb *cb);
extern LIBMQTT_API void libmqtt__destroy(struct libmqtt *mqtt);

extern LIBMQTT_API void libmqtt__time_retry(struct libmqtt *mqtt, int time_retry);
extern LIBMQTT_API void libmqtt__keep_alive(struct libmqtt *mqtt, uint16_t keep_alive);
extern LIBMQTT_API void libmqtt__clean_session(struct libmqtt *mqtt, int clean_session);
extern LIBMQTT_API void libmqtt__version(struct libmqtt *mqtt, enum mqtt_vsn vsn);
extern LIBMQTT_API void libmqtt__auth(struct libmqtt *mqtt, const char *username, const char *password);
extern LIBMQTT_API void libmqtt__will(struct libmqtt *mqtt, int retain, enum mqtt_qos qos, const char *topic, const char *payload, int payload_len);

extern LIBMQTT_API int libmqtt__connect(struct libmqtt *mqtt, void *io, libmqtt__io_write write);
extern LIBMQTT_API int libmqtt__disconnect(struct libmqtt *mqtt);

extern LIBMQTT_API int libmqtt__subscribe(struct libmqtt *mqtt, uint16_t *id, int count, const char *topic[], enum mqtt_qos qos[]);
extern LIBMQTT_API int libmqtt__unsubscribe(struct libmqtt *mqtt, uint16_t *id, int count, const char *topic[]);
extern LIBMQTT_API int libmqtt__publish(struct libmqtt *mqtt, uint16_t *id, const char *topic, enum mqtt_qos qos, int retain, const char *payload, int length);

extern LIBMQTT_API int libmqtt__read(struct libmqtt *mqtt, const char *data, int size);
extern LIBMQTT_API int libmqtt__update(struct libmqtt *mqtt);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMQTT_H_ */


#ifdef LIBMQTT_IMPLEMENTATION

#define MQTT_IMPLEMENTATION
#include "mqtt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#define LIBMQTT_LOG_BUFF    4096

#define __LIBMQTT_DEBUG(...) __libmqtt_log(mqtt, LIBMQTT_LOG_DEBUG, __VA_ARGS__)
#define __LIBMQTT_INFO(...) __libmqtt_log(mqtt, LIBMQTT_LOG_INFO, __VA_ARGS__)
#define __LIBMQTT_WARN(...) __libmqtt_log(mqtt, LIBMQTT_LOG_WARN, __VA_ARGS__)
#define __LIBMQTT_ERROR(...) __libmqtt_log(mqtt, LIBMQTT_LOG_ERROR, __VA_ARGS__)


enum libmqtt_state {
    LIBMQTT_ST_SEND_PUBLUSH,
    LIBMQTT_ST_SEND_PUBACK,
    LIBMQTT_ST_SEND_PUBREC,
    LIBMQTT_ST_SEND_PUBREL,
    LIBMQTT_ST_SEND_PUBCOMP,
    LIBMQTT_ST_WAIT_PUBACK,
    LIBMQTT_ST_WAIT_PUBREC,
    LIBMQTT_ST_WAIT_PUBREL,
    LIBMQTT_ST_WAIT_PUBCOMP
};

enum libmqtt_dir {
    LIBMQTT_DIR_IN,
    LIBMQTT_DIR_OUT
};

struct libmqtt_pub {
    struct {
        uint16_t packet_id;
        char *topic;
        enum mqtt_qos qos;
        int retain;
        char *payload;
        int length;
    } p;
    enum libmqtt_state s;
    enum libmqtt_dir d;
    int t;

    struct libmqtt_pub *next;
};

struct libmqtt {
    struct mqtt_p_connect c;
    struct mqtt_parser p;
    uint16_t packet_id;

    struct {
        int now;
        int ping;
        int send;
    } t;

    int time_retry;

    struct {
        struct libmqtt_pub *head;
        struct libmqtt_pub *tail;
    } pub;

    void *ud;
    struct libmqtt_cb cb;

    void (* log)(void *ud, const char *str);
    enum libmqtt_log_level log_level;

    void *io;
    libmqtt__io_write io_write;
};


static int
__libmqtt_write(struct libmqtt *mqtt, const char *data, int size) {
    if (-1 == mqtt->io_write(mqtt->io, data, size)) {
        return -1;
    }
    mqtt->t.send = mqtt->t.now;
    return 0;
}

static void
__libmqtt_default_log(void *ud, const char *str) {
    (void)ud;

    fprintf(stdout, "%s\n", str);
}

static void
__libmqtt_log(struct libmqtt *mqtt, enum libmqtt_log_level level, const char *fmt, ...) {
    int n;
    va_list ap;
    char logbuf[LIBMQTT_LOG_BUFF] = {0};
    static const char *__libmqtt_log_tags[] = {
        "DEBUG",
        "INFO",
        "WARN",
        "ERROR",
    };

    if (!mqtt->log || level < mqtt->log_level) return;
    n = snprintf(logbuf, LIBMQTT_LOG_BUFF, "[LIBMQTT] %s Client %.*s ", __libmqtt_log_tags[level], mqtt->c.client_id.n, mqtt->c.client_id.s);
    va_start(ap, fmt);
    n += vsnprintf(logbuf+n, LIBMQTT_LOG_BUFF-n, fmt, ap);
    va_end(ap);
    logbuf[n] = '\0';
    mqtt->log(mqtt->ud, logbuf);
}

static void
__libmqtt_check_retry(struct libmqtt *mqtt) {
    struct libmqtt_pub **pp;

    pp = &mqtt->pub.head;
    while (*pp) {
        struct libmqtt_pub *pub;
        pub = *pp;
        if (mqtt->t.now - pub->t > mqtt->time_retry) {
            switch (pub->s) {
            case LIBMQTT_ST_SEND_PUBLUSH:
            case LIBMQTT_ST_WAIT_PUBACK:
            case LIBMQTT_ST_WAIT_PUBREC:
                {
                    struct mqtt_packet p;
                    struct mqtt_b b;

                    memset(&p, 0, sizeof p);
                    p.h.type = PUBLISH;
                    p.h.dup = 1;
                    p.h.retain = pub->p.retain;
                    p.h.qos = pub->p.qos;
                    p.v.publish.packet_id = pub->p.packet_id;
                    p.v.publish.topic.s = pub->p.topic;
                    p.v.publish.topic.n = strlen(pub->p.topic);
                    p.payload.s = pub->p.payload;
                    p.payload.n = pub->p.length;

                    mqtt__serialize(&p, &b);
                    if (0 == __libmqtt_write(mqtt, b.s, b.n)) {
                        __LIBMQTT_INFO("sending PUBLISH (d%d, q%d, r%d, m%"PRIu16", \'%s\', ...(%d bytes))",
                              1, pub->p.qos, pub->p.retain, pub->p.packet_id, pub->p.topic, pub->p.length);
                        if (pub->p.qos == MQTT_QOS_0) {
                            *pp = (*pp)->next;
                            free(pub->p.topic);
                            if (pub->p.payload)
                                free(pub->p.payload);
                            free(pub);
                            pub = 0;
                            break;
                        } else if (pub->p.qos == MQTT_QOS_1) {
                            pub->s = LIBMQTT_ST_WAIT_PUBACK;
                        } else {
                            pub->s = LIBMQTT_ST_WAIT_PUBREC;
                        }
                    }
                    pub->t = mqtt->t.now;
                    mqtt_b_free(&b);
                }
                break;
            case LIBMQTT_ST_SEND_PUBACK:
                {
                    char puback[] = MQTT_PUBACK(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, puback, sizeof puback)) {
                        __LIBMQTT_INFO("sending PUBACK (id: %"PRIu16")", pub->p.packet_id);
                        *pp = (*pp)->next;
                        free(pub->p.topic);
                        if (pub->p.payload)
                            free(pub->p.payload);
                        free(pub);
                        pub = 0;
                    } else {
                        pub->t = mqtt->t.now;
                    }
                }
                break;
            case LIBMQTT_ST_SEND_PUBREC:
                {
                    char pubrec[] = MQTT_PUBREC(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, pubrec, sizeof pubrec)) {
                        __LIBMQTT_INFO("sending PUBREC (id: %"PRIu16")", pub->p.packet_id);
                        pub->s = LIBMQTT_ST_WAIT_PUBREL;
                    }
                    pub->t = mqtt->t.now;
                }
                break;
            case LIBMQTT_ST_SEND_PUBREL:
                {
                    char pubrel[] = MQTT_PUBREL(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, pubrel, sizeof pubrel)) {
                        __LIBMQTT_INFO("sending PUBREL (id: %"PRIu16")", pub->p.packet_id);
                        pub->s = LIBMQTT_ST_WAIT_PUBCOMP;
                    }
                    pub->t = mqtt->t.now;
                }
                break;
            case LIBMQTT_ST_SEND_PUBCOMP:
                {
                    char pubcomp[] = MQTT_PUBCOMP(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, pubcomp, sizeof pubcomp)) {
                        __LIBMQTT_INFO("sending PUBCOMP (id: %"PRIu16")", pub->p.packet_id);
                        *pp = (*pp)->next;
                        free(pub->p.topic);
                        if (pub->p.payload)
                            free(pub->p.payload);
                        free(pub);
                        pub = 0;
                    } else {
                        pub->t = mqtt->t.now;
                    }
                }
                break;
            case LIBMQTT_ST_WAIT_PUBREL:
                {
                    char pubrec[] = MQTT_PUBREC(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, pubrec, sizeof pubrec)) {
                        __LIBMQTT_INFO("sending PUBREC (id: %"PRIu16")", pub->p.packet_id);
                    }
                    pub->t = mqtt->t.now;
                }
                break;
            case LIBMQTT_ST_WAIT_PUBCOMP:
                {
                    char pubrel[] = MQTT_PUBREL(pub->p.packet_id);
                    if (0 == __libmqtt_write(mqtt, pubrel, sizeof pubrel)) {
                        __LIBMQTT_INFO("sending PUBREL (id: %"PRIu16")", pub->p.packet_id);
                    }
                    pub->t = mqtt->t.now;
                }
                break;
            }
        }
        if (pub)
            pp = &(*pp)->next;
    }
}

static uint16_t
__libmqtt_generate_packet_id(struct libmqtt *mqtt) {
    uint16_t id;

    id = ++mqtt->packet_id;
    if (id == 0)
        id = ++mqtt->packet_id;
    return id;
}

const char *
libmqtt__strerror(int rc) {
    static const char *__libmqtt_error_strings[] = {
        "success",
        "mqtt null pointer access",
        "mqtt qos error",
        "mqtt io write error",
        "mqtt packet parse error",
        "mqtt timeout error",
        "mqtt max topic/qos per subscribe or unsubscribe",
    };

    if (-rc <= 0 || (size_t)-rc > sizeof(__libmqtt_error_strings)/sizeof(char *))
        return 0;
    return __libmqtt_error_strings[-rc];
}

static void
__libmqtt_insert_pub(struct libmqtt *mqtt, struct mqtt_packet *p, enum libmqtt_dir d,
             enum libmqtt_state s) {
    struct libmqtt_pub *pub;

    pub = (struct libmqtt_pub *)malloc(sizeof *pub);
    memset(pub, 0, sizeof *pub);
    pub->p.packet_id = p->v.publish.packet_id;
    pub->p.qos = p->h.qos;
    pub->p.retain = p->h.retain;
    pub->p.topic = strndup(p->v.publish.topic.s, p->v.publish.topic.n);
    if (p->payload.n > 0) {
        pub->p.payload = malloc(p->payload.n);
        memcpy(pub->p.payload, p->payload.s, p->payload.n);
    }
    pub->p.length = p->payload.n;
    pub->d = d;
    pub->s = s;
    pub->t = mqtt->t.now;

    if (!mqtt->pub.head) {
        mqtt->pub.head = mqtt->pub.tail = pub;
    } else {
        mqtt->pub.tail->next = pub;
        mqtt->pub.tail = pub;
    }
}

static void
__libmqtt_delete_pub(struct libmqtt *mqtt, struct libmqtt_pub *pub) {
    struct libmqtt_pub **pp;

    pp = &mqtt->pub.head;
    while (*pp) {
        if (*pp == pub) {
            *pp = (*pp)->next;
            free(pub->p.topic);
            if (pub->p.payload)
                free(pub->p.payload);
            free(pub);
        } else {
            pp = &(*pp)->next;
        }
    }
}

static void
__libmqtt_update_pub(struct libmqtt *mqtt, struct libmqtt_pub *pub, enum libmqtt_state s) {
    pub->s = s;
    pub->t = mqtt->t.now;
}

static struct libmqtt_pub *
__libmqtt_find_pub(struct libmqtt *mqtt, uint16_t packet_id, enum libmqtt_dir d,
           enum libmqtt_state s) {
    struct libmqtt_pub *pub;

    pub = mqtt->pub.head;
    while (pub) {
        if (pub->p.packet_id == packet_id && pub->d == d && pub->s == s) {
            return pub;
        }
        pub = pub->next;
    }

    return 0;
}

static int
__libmqtt_on_connack(struct libmqtt *mqtt, struct mqtt_packet *p) {
    __LIBMQTT_INFO("received CONNACK (a%d, c%d)", p->v.connack.ack_flags, p->v.connack.return_code);
    if (mqtt->cb.connack)
        mqtt->cb.connack(mqtt, mqtt->ud, p->v.connack.ack_flags, p->v.connack.return_code);
    return 0;
}

static int
__libmqtt_on_suback(struct libmqtt *mqtt, struct mqtt_packet *p) {
    int i;

    for (i = 0; i < p->v.suback.n; i++) {
        __LIBMQTT_INFO("received SUBACK (id: %"PRIu16", QoS: %d)", p->v.suback.packet_id, p->v.suback.qos[i]);
    }
    if (mqtt->cb.suback)
        mqtt->cb.suback(mqtt, mqtt->ud, p->v.suback.packet_id, p->v.suback.n, p->v.suback.qos);
    return 0;
}

static int
__libmqtt_on_unsuback(struct libmqtt *mqtt, struct mqtt_packet *p) {
    __LIBMQTT_INFO("received UNSUBACK (id: %"PRIu16")", p->v.unsuback.packet_id);
    if (mqtt->cb.unsuback)
        mqtt->cb.unsuback(mqtt, mqtt->ud, p->v.unsuback.packet_id);
    return 0;
}

static int
__libmqtt_on_publish(struct libmqtt *mqtt, struct mqtt_packet *p) {
    char puback[] = MQTT_PUBACK(p->v.publish.packet_id);
    char pubrec[] = MQTT_PUBREC(p->v.publish.packet_id);
    char topic[p->v.publish.topic.n+1];

    strncpy(topic, p->v.publish.topic.s, p->v.publish.topic.n);
    topic[p->v.publish.topic.n] = '\0';
    __LIBMQTT_INFO("received PUBLISH (d%d, q%d, r%d, m%"PRIu16", \'%s\', ...(%d bytes))",
          p->h.dup, p->h.qos, p->h.retain, p->v.publish.packet_id, topic, p->payload.n);
    switch (p->h.qos) {
        case MQTT_QOS_0:
            if (mqtt->cb.publish)
                mqtt->cb.publish(mqtt, mqtt->ud, p->v.publish.packet_id, topic, p->h.qos, p->h.retain, p->payload.s, p->payload.n);
            return 0;
        case MQTT_QOS_1:
            if (mqtt->cb.publish)
                mqtt->cb.publish(mqtt, mqtt->ud, p->v.publish.packet_id, topic, p->h.qos, p->h.retain, p->payload.s, p->payload.n);
            if (__libmqtt_write(mqtt, puback, sizeof puback)) {
                __libmqtt_insert_pub(mqtt, p, LIBMQTT_DIR_IN, LIBMQTT_ST_SEND_PUBACK);
                return 0;
            }
            __LIBMQTT_INFO("sending PUBACK (id: %"PRIu16")", p->v.publish.packet_id);
            return 0;
        case MQTT_QOS_2:
            if (__libmqtt_write(mqtt, pubrec, sizeof pubrec)) {
                __libmqtt_insert_pub(mqtt, p, LIBMQTT_DIR_IN, LIBMQTT_ST_SEND_PUBREC);
                return 0;
            }
            __LIBMQTT_INFO("sending PUBREC (id: %"PRIu16")", p->v.publish.packet_id);
            __libmqtt_insert_pub(mqtt, p, LIBMQTT_DIR_IN, LIBMQTT_ST_WAIT_PUBREL);
            return 0;
        case MQTT_QOS_F:
            return -1;
    }
    return 0;
}

static int
__libmqtt_on_puback(struct libmqtt *mqtt, struct mqtt_packet *p) {
    struct libmqtt_pub *pub;
    uint16_t packet_id = p->v.puback.packet_id;

    __LIBMQTT_INFO("received PUBACK (id: %"PRIu16")", packet_id);
    pub = __libmqtt_find_pub(mqtt, packet_id, LIBMQTT_DIR_OUT, LIBMQTT_ST_WAIT_PUBACK);
    if (pub) {
        if (mqtt->cb.puback)
            mqtt->cb.puback(mqtt, mqtt->ud, packet_id);
        __libmqtt_delete_pub(mqtt, pub);
        return 0;
    }
    return -1;
}

static int
__libmqtt_on_pubrec(struct libmqtt *mqtt, struct mqtt_packet *p) {
    struct libmqtt_pub *pub;
    uint16_t packet_id = p->v.pubrec.packet_id;

    __LIBMQTT_INFO("received PUBREC (id: %"PRIu16")", packet_id);
    pub = __libmqtt_find_pub(mqtt, packet_id, LIBMQTT_DIR_OUT, LIBMQTT_ST_WAIT_PUBREC);
    if (pub) {
        char pubrel[] = MQTT_PUBREL(packet_id);
        if (__libmqtt_write(mqtt, pubrel, sizeof pubrel)) {
            __libmqtt_update_pub(mqtt, pub, LIBMQTT_ST_SEND_PUBREL);
        } else {
            __LIBMQTT_INFO("sending PUBREL (id: %"PRIu16")", packet_id);
            __libmqtt_update_pub(mqtt, pub, LIBMQTT_ST_WAIT_PUBCOMP);
        }
        return 0;
    }
    return -1;
}

static int
__libmqtt_on_pubrel(struct libmqtt *mqtt, struct mqtt_packet *p) {
    struct libmqtt_pub *pub;
    uint16_t packet_id = p->v.pubrel.packet_id;

    __LIBMQTT_INFO("received PUBREL (id: %"PRIu16")", packet_id);
    pub = __libmqtt_find_pub(mqtt, packet_id, LIBMQTT_DIR_IN, LIBMQTT_ST_WAIT_PUBREL);
    if (pub) {
        char pubcomp[] = MQTT_PUBCOMP(packet_id);
        if (mqtt->cb.publish)
            mqtt->cb.publish(mqtt, mqtt->ud, packet_id, pub->p.topic, pub->p.qos, pub->p.retain, pub->p.payload, pub->p.length);
        if (__libmqtt_write(mqtt, pubcomp, sizeof pubcomp)) {
            __libmqtt_update_pub(mqtt, pub, LIBMQTT_ST_SEND_PUBCOMP);
        } else {
            __LIBMQTT_INFO("sending PUBCOMP (id: %"PRIu16")", packet_id);
            __libmqtt_delete_pub(mqtt, pub);
        }
        return 0;
    }
    return -1;
}

static int
__libmqtt_on_pubcomp(struct libmqtt *mqtt, struct mqtt_packet *p) {
    struct libmqtt_pub *pub;
    uint16_t packet_id = p->v.pubcomp.packet_id;

    __LIBMQTT_INFO("received PUBCOMP (id: %"PRIu16")", packet_id);
    pub = __libmqtt_find_pub(mqtt, packet_id, LIBMQTT_DIR_OUT, LIBMQTT_ST_WAIT_PUBCOMP);
    if (pub) {
        if (mqtt->cb.puback)
            mqtt->cb.puback(mqtt, mqtt->ud, packet_id);
        __libmqtt_delete_pub(mqtt, pub);
        return 0;
    }
    return -1;
}

static int
__libmqtt_on_pingresp(struct libmqtt *mqtt, struct mqtt_packet *p) {
    (void)p;

    __LIBMQTT_INFO("received PINGRESP");
    mqtt->t.ping = 0;
    return 0;
}

void
libmqtt__set_log(struct libmqtt *mqtt, void (* log)(void *ud, const char *str)) {
    mqtt->log = log;
}

void
libmqtt__set_log_level(struct libmqtt *mqtt, enum libmqtt_log_level log_level) {
    mqtt->log_level = log_level;
}

int
libmqtt__create(struct libmqtt **mqtt, const char *client_id, void *ud, struct libmqtt_cb *cb) {
    struct libmqtt *m;

    if (!client_id || strlen(client_id) == 0 || !cb) {
        return LIBMQTT_ERROR_NULL;
    }

    m = (struct libmqtt *)malloc(sizeof *m);
    memset(m, 0, sizeof *m);

    mqtt_b_dup(&m->c.client_id, client_id);

    mqtt__parse_init(&m->p);

    m->ud = ud;
    m->cb = *cb;
    m->t.ping = 0;
    m->t.send = 0;
    m->time_retry = LIBMQTT_DEF_TIMERETRY;
    m->c.keep_alive = LIBMQTT_DEF_KEEPALIVE;
    m->c.clean_session = 1;
    m->c.proto_ver = MQTT_PROTO_V4;
    m->log = __libmqtt_default_log;
    m->log_level = LIBMQTT_LOG_WARN;

    *mqtt = m;
    return LIBMQTT_SUCCESS;
}

void
libmqtt__destroy(struct libmqtt *mqtt) {
    if (!mqtt) return;

    mqtt__parse_unit(&mqtt->p);
    mqtt_b_free(&mqtt->c.client_id);
    mqtt_b_free(&mqtt->c.username);
    mqtt_b_free(&mqtt->c.password);
    mqtt_b_free(&mqtt->c.will_topic);
    mqtt_b_free(&mqtt->c.will_payload);
    free(mqtt);
}

void
libmqtt__time_retry(struct libmqtt *mqtt, int time_retry) {
    if (!mqtt) return;

    mqtt->time_retry = time_retry;
}

void
libmqtt__keep_alive(struct libmqtt *mqtt, uint16_t keep_alive) {
    if (!mqtt) return;

    mqtt->c.keep_alive = keep_alive;
}

void
libmqtt__clean_session(struct libmqtt *mqtt, int clean_session) {
    if (!mqtt) return;

    mqtt->c.clean_session = clean_session;
}

void
libmqtt__version(struct libmqtt *mqtt, enum mqtt_vsn vsn) {
    if (!mqtt) return;

    if (MQTT_IS_VER(vsn)) {
        mqtt->c.proto_ver = vsn;
    }    
}

void
libmqtt__auth(struct libmqtt *mqtt, const char *username, const char *password) {
    if (!mqtt) return;

    mqtt_b_free(&mqtt->c.username);
    mqtt_b_free(&mqtt->c.password);
    if (username) {
        mqtt_b_dup(&mqtt->c.username, username);
    }
    if (password) {
        mqtt_b_dup(&mqtt->c.password, password);
    }
}

void
libmqtt__will(struct libmqtt *mqtt, int retain, enum mqtt_qos qos, const char *topic,
                  const char *payload, int payload_len) {
    if (!topic) {
        mqtt->c.will_flag = 0;
        return;
    }
    mqtt->c.will_flag = 1;
    mqtt->c.will_retain = retain;
    mqtt->c.will_qos = qos;
    mqtt_b_free(&mqtt->c.will_topic);
    mqtt_b_free(&mqtt->c.will_payload);
    mqtt_b_dup(&mqtt->c.will_topic, topic);
    if (payload && payload_len > 0) {
        mqtt->c.will_payload.s = malloc(payload_len);
        memcpy(mqtt->c.will_payload.s, payload, payload_len);
        mqtt->c.will_payload.n = payload_len;
    }
}

int
libmqtt__connect(struct libmqtt *mqtt, void *io, libmqtt__io_write write) {
    struct mqtt_packet p;
    struct mqtt_b b;
    int rc;

    if (!mqtt) return LIBMQTT_ERROR_NULL;

    mqtt->io = io;
    mqtt->io_write = write;

    memset(&p, 0, sizeof p);
    p.h.type = CONNECT;
    p.v.connect = mqtt->c;
    p.v.connect.proto_name.s = (char *)MQTT_PROTOCOL_NAMES[mqtt->c.proto_ver];
    p.v.connect.proto_name.n = strlen(p.v.connect.proto_name.s);

    mqtt__serialize(&p, &b);
    rc = __libmqtt_write(mqtt, b.s, b.n);
    mqtt_b_free(&b);
    if (rc) return LIBMQTT_ERROR_WRITE;

    __LIBMQTT_INFO("sending CONNECT (%s, c%d, k%d, u\'%.*s\', p\'%.*s\')", MQTT_PROTOCOL_NAMES[mqtt->c.proto_ver],
          mqtt->c.clean_session, mqtt->c.keep_alive, mqtt->c.username.n, mqtt->c.username.s,
          mqtt->c.password.n, mqtt->c.password.s);
    return LIBMQTT_SUCCESS;
}

int
libmqtt__subscribe(struct libmqtt *mqtt, uint16_t *id, int count, const char *topic[], enum mqtt_qos qos[]) {
    struct mqtt_packet p;
    struct mqtt_b b;
    int rc, i;

    if (!mqtt) return LIBMQTT_ERROR_NULL;
    if (count > MQTT_MAX_SUB) return LIBMQTT_ERROR_MAXSUB;

    memset(&p, 0, sizeof p);
    p.h.type = SUBSCRIBE;
    p.v.subscribe.packet_id = __libmqtt_generate_packet_id(mqtt);
    for (i = 0; i < count; i++) {
        p.v.subscribe.topic[i].s = (char *)topic[i];
        p.v.subscribe.topic[i].n = strlen(topic[i]);
        p.v.subscribe.qos[i] = qos[i];
    }
    p.v.subscribe.n = count;

    mqtt__serialize(&p, &b);
    if (id) {
        *id = p.v.subscribe.packet_id;
    }
    rc = __libmqtt_write(mqtt, b.s, b.n);
    mqtt_b_free(&b);
    if (rc) return LIBMQTT_ERROR_WRITE;

    for (i = 0; i < count; i++) {
        __LIBMQTT_INFO("Sending SUBSCRIBE (id: %"PRIu16", topic: %s, qos: %d)",
              p.v.subscribe.packet_id, topic[i], qos[i]);
    }
    return LIBMQTT_SUCCESS;
}

int
libmqtt__unsubscribe(struct libmqtt *mqtt, uint16_t *id, int count, const char *topic[]) {
    struct mqtt_packet p;
    struct mqtt_b b;
    int rc, i;

    if (!mqtt) return LIBMQTT_ERROR_NULL;
    if (count > MQTT_MAX_SUB) return LIBMQTT_ERROR_MAXSUB;

    memset(&p, 0, sizeof p);
    p.h.type = UNSUBSCRIBE;
    p.v.unsubscribe.packet_id = __libmqtt_generate_packet_id(mqtt);
    for (i = 0; i < count; i++) {
        p.v.unsubscribe.topic[i].s = (char *)topic[i];
        p.v.unsubscribe.topic[i].n = strlen(topic[i]);
    }
    p.v.unsubscribe.n = count;

    mqtt__serialize(&p, &b);
    if (id) {
        *id = p.v.unsubscribe.packet_id;
    }
    rc = __libmqtt_write(mqtt, b.s, b.n);
    mqtt_b_free(&b);
    if (rc) {
        return LIBMQTT_ERROR_WRITE;
    }
    for (i = 0; i < count; i++) {
        __LIBMQTT_INFO("Sending UNSUBSCRIBE (id: %"PRIu16", topic: %s)",
              p.v.unsubscribe.packet_id, topic[i]);
    }
    return LIBMQTT_SUCCESS;
}

int
libmqtt__publish(struct libmqtt *mqtt, uint16_t *id, const char *topic,
                     enum mqtt_qos qos, int retain, const char *payload, int length) {
    struct mqtt_packet p;
    struct mqtt_b b;
    enum libmqtt_state s;
    int rc;

    if (!mqtt) return LIBMQTT_ERROR_NULL;
    if (!MQTT_IS_QOS(qos)) return LIBMQTT_ERROR_QOS;

    memset(&p, 0, sizeof p);
    p.h.type = PUBLISH;
    p.h.dup = 0;
    p.h.retain = retain;
    p.h.qos = qos;
    if (qos > MQTT_QOS_0) {
        p.v.publish.packet_id = __libmqtt_generate_packet_id(mqtt);
    }
    p.v.publish.topic.s = (char *)topic;
    p.v.publish.topic.n = strlen(topic);
    p.payload.s = (char *)payload;
    p.payload.n = length;

    mqtt__serialize(&p, &b);
    if (qos > MQTT_QOS_0 && id) {
        *id = p.v.publish.packet_id;
    }
    rc = __libmqtt_write(mqtt, b.s, b.n);
    mqtt_b_free(&b);
    if (!rc) {
        __LIBMQTT_INFO("sending PUBLISH (d%d, q%d, r%d, m%"PRIu16", \'%s\', ...(%d bytes))",
              0, qos, retain, p.v.publish.packet_id, topic, length);
    }
    if (!rc && qos == MQTT_QOS_0) {
        if (mqtt->cb.puback)
            mqtt->cb.puback(mqtt, mqtt->ud, p.v.publish.packet_id);
        return LIBMQTT_SUCCESS;
    }
    if (rc) {
        s = LIBMQTT_ST_SEND_PUBLUSH;
    } else if (qos == MQTT_QOS_1) {
        s = LIBMQTT_ST_WAIT_PUBACK;
    } else if (qos == MQTT_QOS_2) {
        s = LIBMQTT_ST_WAIT_PUBREC;
    } else {
        return LIBMQTT_ERROR_QOS;
    }
    __libmqtt_insert_pub(mqtt, &p, LIBMQTT_DIR_OUT, s);
    return LIBMQTT_SUCCESS;
}

int
libmqtt__disconnect(struct libmqtt *mqtt) {
    char b[] = MQTT_DISCONNECT;

    if (!mqtt) return LIBMQTT_ERROR_NULL;

    if (__libmqtt_write(mqtt, b, sizeof b)) {
        return LIBMQTT_ERROR_WRITE;
    }
    __LIBMQTT_INFO("sending DISCONNECT");
    return LIBMQTT_SUCCESS;
}

int
libmqtt__read(struct libmqtt *mqtt, const char *data, int size) {
    struct mqtt_b b;
    struct mqtt_packet pkt;
    int rc;

    if (!mqtt) return LIBMQTT_ERROR_NULL;

    b.s = (char *)data;
    b.n = size;

    while ((rc = mqtt__parse(&mqtt->p, &b, &pkt)) > 0) {
        int r = 0;
        switch (pkt.h.type) {
        case CONNECT:
            break;
        case CONNACK:
            r = __libmqtt_on_connack(mqtt, &pkt);
            break;
        case PUBLISH:
            r = __libmqtt_on_publish(mqtt, &pkt);
            break;
        case PUBACK:
            r = __libmqtt_on_puback(mqtt, &pkt);
            break;
        case PUBREC:
            r = __libmqtt_on_pubrec(mqtt, &pkt);
            break;
        case PUBREL:
            r = __libmqtt_on_pubrel(mqtt, &pkt);
            break;
        case PUBCOMP:
            r = __libmqtt_on_pubcomp(mqtt, &pkt);
            break;
        case SUBSCRIBE:
            break;
        case SUBACK:
            r = __libmqtt_on_suback(mqtt, &pkt);
            break;
        case UNSUBSCRIBE:
            break;
        case UNSUBACK:
            r = __libmqtt_on_unsuback(mqtt, &pkt);
            break;
        case PINGREQ:
            break;
        case PINGRESP:
            r = __libmqtt_on_pingresp(mqtt, &pkt);
            break;
        case DISCONNECT:
            break;
        case RESERVED:
            break;
        }
        if (r) {
            rc = r;
            break;
        }
    }
    return rc == 0 ? LIBMQTT_SUCCESS : LIBMQTT_ERROR_PARSE;
}

int
libmqtt__update(struct libmqtt *mqtt) {
    if (!mqtt) return LIBMQTT_ERROR_NULL;
    
    mqtt->t.now += 1;

    if (mqtt->c.keep_alive > 0) {
        if (mqtt->t.ping > 0 && (mqtt->t.now - mqtt->t.ping) > mqtt->c.keep_alive) {
            return LIBMQTT_ERROR_TIMEOUT;
        }

        if (mqtt->t.ping == 0 && (mqtt->t.now - mqtt->t.send) >= mqtt->c.keep_alive) {
            char b[] = MQTT_PINGREQ;
            if (0 == __libmqtt_write(mqtt, b, sizeof b)) {
                mqtt->t.ping = mqtt->t.now;
                __LIBMQTT_INFO("sending PINGREQ");
            }
        }
    }

    __libmqtt_check_retry(mqtt);
    return LIBMQTT_SUCCESS;
}


#endif /* LIBMQTT_IMPLEMENTATION */