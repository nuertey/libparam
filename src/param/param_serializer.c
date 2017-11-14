/*
 * param_serializer.c
 *
 *  Created on: Sep 28, 2016
 *      Author: johan
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <param/param.h>
#include <param/param_server.h>
#include "param_serializer.h"

#include <csp/arch/csp_time.h>
#include <csp/csp_endian.h>
#include <csp/csp.h>
#include <param/param_list.h>

#include <mpack/mpack.h>

static inline uint16_t param_get_short_id(param_t * param, unsigned int isarray, unsigned int reserved) {
	uint16_t node = (param->node == 255) ? csp_get_address() : param->node;
	return (node << 11) | ((isarray & 0x1) << 10) | ((reserved & 0x1) << 2) | ((param->id) & 0x1FF);
}

static inline uint8_t param_parse_short_id_flag_isarray(uint16_t short_id) {
	return (short_id >> 10) & 0x1;
}

static inline uint8_t param_parse_short_id_node(uint16_t short_id) {
	return (short_id >> 11) & 0x1F;
}

static inline uint16_t param_parse_short_id_paramid(uint16_t short_id) {
	return short_id & 0x1FF;
}

void param_serialize_id(mpack_writer_t *writer, param_t * param, int offset) {
	if (offset >= 0) {
		mpack_write_u16(writer, param_get_short_id(param, 1, 0));
		char _offset = offset;
		mpack_write_bytes(writer, &_offset, 1);
	} else {
		mpack_write_u16(writer, param_get_short_id(param, 0, 0));
	}
}

void param_deserialize_id(mpack_reader_t *reader, int *id, int *node, int *offset) {
	uint16_t short_id = mpack_expect_u16(reader);

	if (mpack_reader_error(reader) != mpack_ok)
		return;

	if (param_parse_short_id_flag_isarray(short_id)) {
		char _offset;
		mpack_read_bytes(reader, &_offset, 1);
		*offset = _offset;
	}

	*id = param_parse_short_id_paramid(short_id);
	*node = param_parse_short_id_node(short_id);

}

int param_serialize_to_mpack(param_t * param, int offset, mpack_writer_t * writer, void * value) {

	/* Remember the initial position if we need to abort later due to buffer full */
	unsigned int init_pos = writer->used;

	param_serialize_id(writer, param, offset);

	if (mpack_writer_error(writer) != mpack_ok)
		return -1;


	unsigned int count = (param->size > 0) ? param->size : 1;

	/* Treat data and strings as single parameters */
	if (param->type == PARAM_TYPE_DATA || param->type == PARAM_TYPE_STRING)
		count = 1;

	/* If offset is set, adjust count to only display one value */
	if (offset >= 0) {
		count = 1;
	}

	/* If offset is unset, start at zero and display all values */
	if (offset < 0) {
		offset = 0;
	}

	if (count > 1) {
		mpack_start_array(writer, count);
	}

	for(int i = offset; i < offset + count; i++) {

		switch (param->type) {
		case PARAM_TYPE_UINT8:
		case PARAM_TYPE_XINT8:
			if (value) {
				mpack_write_uint(writer, *(uint8_t *) value);
			} else {
				mpack_write_uint(writer, param_get_uint8_array(param, i));
			}
			break;
		case PARAM_TYPE_UINT16:
		case PARAM_TYPE_XINT16:
			if (value) {
				mpack_write_uint(writer, *(uint16_t *) value);
			} else {
				mpack_write_uint(writer, param_get_uint16_array(param, i));
			}
			break;
		case PARAM_TYPE_UINT32:
		case PARAM_TYPE_XINT32:
			if (value) {
				mpack_write_uint(writer, *(uint32_t *) value);
			} else {
				mpack_write_uint(writer, param_get_uint32_array(param, i));
			}
			break;
		case PARAM_TYPE_UINT64:
		case PARAM_TYPE_XINT64:
			if (value) {
				mpack_write_uint(writer, *(uint64_t *) value);
			} else {
				mpack_write_uint(writer, param_get_uint64_array(param, i));
			}
			break;
		case PARAM_TYPE_INT8:
			if (value) {
				mpack_write_int(writer, *(int8_t *) value);
			} else {
				mpack_write_int(writer, param_get_int8_array(param, i));
			}
			break;
		case PARAM_TYPE_INT16:
			if (value) {
				mpack_write_int(writer, *(int16_t *) value);
			} else {
				mpack_write_int(writer, param_get_int16_array(param, i));
			}
			break;
		case PARAM_TYPE_INT32:
			if (value) {
				mpack_write_int(writer, *(int32_t *) value);
			} else {
				mpack_write_int(writer, param_get_int32_array(param, i));
			}
			break;
		case PARAM_TYPE_INT64:
			if (value) {
				mpack_write_int(writer, *(int64_t *) value);
			} else {
				mpack_write_int(writer, param_get_int64_array(param, i));
			}
			break;
		case PARAM_TYPE_FLOAT:
			if (value) {
				mpack_write_float(writer, *(float *) value);
			} else {
				mpack_write_float(writer, param_get_float_array(param, i));
			}
			break;
		case PARAM_TYPE_DOUBLE:
			if (value) {
				mpack_write_double(writer, *(double *) value);
			} else {
				mpack_write_double(writer, param_get_double_array(param, i));
			}
			break;

		case PARAM_TYPE_STRING: {
			int len;
			if (value) {
				len = strnlen(value, param->size);

				mpack_start_str(writer, len);

				if (writer->size - writer->used < len) {
					writer->error = mpack_error_too_big;
					break;
				}

				memcpy(writer->buffer + writer->used, (char *) value, len);

			} else {
				char tmp[param->size];
				param_get_data(param, tmp, param->size);
				len = strnlen(tmp, param->size);

				mpack_start_str(writer, len);

				if (writer->size - writer->used < len) {
					writer->error = mpack_error_too_big;
					break;
				}

				memcpy(writer->buffer + writer->used, tmp, len);

			}
			writer->used += len;
			mpack_finish_str(writer);
			break;
		}

		case PARAM_TYPE_DATA:

			mpack_start_bin(writer, param->size);

			if (writer->size - writer->used < param->size) {
				writer->error = mpack_error_too_big;
				break;
			}

			if (value) {
				memcpy(writer->buffer + writer->used, value, param->size);
			} else {
				param_get_data(param, writer->buffer + writer->used, param->size);
			}
			writer->used += param->size;
			mpack_finish_bin(writer);
			break;

		default:
		case PARAM_TYPE_VECTOR3:
			break;
		}

		if (mpack_writer_error(writer) != mpack_ok) {
			writer->used = init_pos;
			return -1;
		}

	}

	if (count > 1) {
		mpack_finish_array(writer);
	}

	return 0;

}

void param_deserialize_from_mpack_to_param(void * queue, param_t * param, int offset, mpack_reader_t * reader) {

	if (offset < 0)
		offset = 0;

	uint32_t count = 1;

	/* Inspect for array */
	mpack_tag_t tag = mpack_peek_tag(reader);
	if (tag.type == mpack_type_array) {
		count = mpack_expect_array(reader);
	}

	for (int i = offset; i < offset + count; i++) {

		switch (param->type) {
		case PARAM_TYPE_UINT8:
		case PARAM_TYPE_XINT8:
			param_set_uint8_array(param, i, (uint8_t) mpack_expect_uint(reader)); break;
		case PARAM_TYPE_UINT16:
		case PARAM_TYPE_XINT16:
			param_set_uint16_array(param, i, (uint16_t) mpack_expect_uint(reader)); break;
		case PARAM_TYPE_UINT32:
		case PARAM_TYPE_XINT32:
			param_set_uint32_array(param, i, (uint32_t) mpack_expect_uint(reader)); break;
		case PARAM_TYPE_UINT64:
		case PARAM_TYPE_XINT64:
			param_set_uint64_array(param, i, mpack_expect_u64(reader)); break;
		case PARAM_TYPE_INT8:
			param_set_int8_array(param, i, (int8_t) mpack_expect_int(reader)); break;
		case PARAM_TYPE_INT16:
			param_set_int16_array(param, i, (int16_t) mpack_expect_int(reader)); break;
		case PARAM_TYPE_INT32:
			param_set_int32_array(param, i, (int32_t) mpack_expect_int(reader)); break;
		case PARAM_TYPE_INT64:
			param_set_int64_array(param, i, mpack_expect_i64(reader)); break;
		case PARAM_TYPE_FLOAT:
			param_set_float_array(param, i, mpack_expect_float(reader)); break;
		case PARAM_TYPE_DOUBLE:
			param_set_double_array(param, i, mpack_expect_double(reader)); break;
		case PARAM_TYPE_STRING: {
			int len = mpack_expect_str(reader);
			param_set_string(param, &reader->buffer[reader->pos], len);
			reader->pos += len;
			reader->left -= len;
			mpack_done_str(reader);
			break;
		}
		case PARAM_TYPE_DATA: {
			int len = mpack_expect_bin(reader);
			param_set_data(param, &reader->buffer[reader->pos], len);
			reader->pos += len;
			reader->left -= len;
			mpack_done_bin(reader);
			break;
		}

		default:
		case PARAM_TYPE_VECTOR3:
			mpack_discard(reader);
			break;
		}

		if (mpack_reader_error(reader) != mpack_ok) {
			printf("Reader error\n");
			return;
		}

	}

}
