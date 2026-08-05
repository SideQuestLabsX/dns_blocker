#ifndef DNS_BLOCKER_MSG_H
#define DNS_BLOCKER_MSG_H

#include "wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSG_RCODE_NOERROR   0
#define MSG_RCODE_FORMERR   1
#define MSG_RCODE_SERVFAIL  2
#define MSG_RCODE_NXDOMAIN  3
#define MSG_RCODE_NOTIMP    4
#define MSG_RCODE_REFUSED   5

#define MSG_FLAG_QR         0x8000u
#define MSG_FLAG_TC         0x0200u
#define MSG_FLAG_RD         0x0100u
#define MSG_FLAG_RA         0x0080u

uint16_t MsgId(const uint8_t *msg, size_t len);

/* A cached response carries the transaction ID it arrived with. Serving it
   without this replays a stale ID and the client discards the answer. */
void MsgSetId(uint8_t *msg, size_t len, uint16_t id);

uint16_t MsgFlags(const uint8_t *msg, size_t len);

/* Byte offset just past the question section, or 0 when the message does not
   parse that far. */
size_t MsgQuestionEnd(const uint8_t *msg, size_t len);

/* Response echoing the query's question and carrying no records. Used for
   blocked names, and for every failure the daemon reports itself. */
bool MsgBuildReply(uint8_t *out, size_t cap, const uint8_t *query,
                   size_t queryLen, uint16_t rcode, size_t *outLen);

/* Header and question with TC set, so a conforming client retries over TCP. */
bool MsgBuildTruncated(uint8_t *out, size_t cap, const uint8_t *query,
                       size_t queryLen, size_t *outLen);

#endif
