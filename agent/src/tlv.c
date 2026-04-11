#include <string.h>
#include "tracefox.h"

#define TLV_HEADER_MIN_SIZE (12)

static inline void tlv_put_u8(struct tlv_writer * wrt, uint8_t byte)
{
	wrt->buffer[wrt->len] = byte;
	wrt->len++;
}

static inline void tlv_put_be_u16(struct tlv_writer * wrt, uint16_t val)
{
	wrt->buffer[wrt->len] = (uint8_t)((val >> 8) & TF_BYTE_MASK);
	wrt->len++;
	wrt->buffer[wrt->len] = (uint8_t)(val & TF_BYTE_MASK);
	wrt->len++;
}

static inline void tlv_put_be_u32(struct tlv_writer * wrt, uint32_t val)
{
	wrt->buffer[wrt->len] = (uint8_t)((val >> 24) & TF_BYTE_MASK);
	wrt->len++;
	wrt->buffer[wrt->len] = (uint8_t)((val >> 16) & TF_BYTE_MASK);
	wrt->len++;
	wrt->buffer[wrt->len] = (uint8_t)((val >> 8) & TF_BYTE_MASK);
	wrt->len++;
	wrt->buffer[wrt->len] = (uint8_t)(val & TF_BYTE_MASK);
	wrt->len++;
}

int tlv_init(struct tlv_writer * writer, uint8_t * buf, size_t cap, uint32_t timestamp, uint32_t seq) /* NOLINT(bugprone-easily-swappable-parameters) */
{
	if (!writer || !buf || cap < TLV_HEADER_MIN_SIZE) {
		return -1;
	}

	writer->buffer = buf;
	writer->cap    = cap;
	writer->len    = 0U;

	tlv_put_be_u16(writer, TF_MAGIC);
	tlv_put_u8(writer, TF_VERSION);
	tlv_put_u8(writer, 0U);
	tlv_put_be_u32(writer, timestamp);
	tlv_put_be_u32(writer, seq);

	return 0;
}

int tlv_put(struct tlv_writer * writer, uint8_t type, const void * value, uint8_t len)
{
	if (!writer || !value) {
		return -1;
	}

	if (writer->len + 2U + (size_t)len > writer->cap) {
		return -1;
	}

	tlv_put_u8(writer, type);
	tlv_put_u8(writer, len);
	memcpy(writer->buffer + writer->len, value, (size_t)len);
	writer->len += (size_t)len;

	return 0;
}
