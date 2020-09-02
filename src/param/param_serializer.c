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

/* Find the length of STRING, but scan at most MAXLEN characters.
   Copyright (C) 1991-2019 Free Software Foundation, Inc.
   Contributed by Jakub Jelinek <jakub@redhat.com>.
   Based on strlen written by Torbjorn Granlund (tege@sics.se),
   with help from Dan Sahlin (dan@sics.se);
   commentary by Jim Blandy (jimb@ai.mit.edu).
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If
   not, see <http://www.gnu.org/licenses/>.  */

/* Find the length of S, but scan at most MAXLEN characters.  If no
   '\0' terminator is found in that many characters, return MAXLEN.  */

size_t strnlen (const char *str, size_t maxlen)
{
  const char *char_ptr, *end_ptr = str + maxlen;
  const unsigned long int *longword_ptr;
  unsigned long int longword, himagic, lomagic;
  if (maxlen == 0)
    return 0;
  if (end_ptr < str)
    end_ptr = (const char *) ~0UL;
  /* Handle the first few characters by reading one character at a time.
     Do this until CHAR_PTR is aligned on a longword boundary.  */
  for (char_ptr = str; ((unsigned long int) char_ptr
                        & (sizeof (longword) - 1)) != 0;
       ++char_ptr)
    if (*char_ptr == '\0')
      {
        if (char_ptr > end_ptr)
          char_ptr = end_ptr;
        return char_ptr - str;
      }
  /* All these elucidatory comments refer to 4-byte longwords,
     but the theory applies equally well to 8-byte longwords.  */
  longword_ptr = (unsigned long int *) char_ptr;
  /* Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
     the "holes."  Note that there is a hole just to the left of
     each byte, with an extra at the end:
     bits:  01111110 11111110 11111110 11111111
     bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
     The 1-bits make sure that carries propagate to the next 0-bit.
     The 0-bits provide holes for carries to fall into.  */
  himagic = 0x80808080L;
  lomagic = 0x01010101L;
  if (sizeof (longword) > 4)
    {
      /* 64-bit version of the magic.  */
      /* Do the shift in two steps to avoid a warning if long has 32 bits.  */
      himagic = ((himagic << 16) << 16) | himagic;
      lomagic = ((lomagic << 16) << 16) | lomagic;
    }
  if (sizeof (longword) > 8)
    return 0;
  /* Instead of the traditional loop which tests each character,
     we will test a longword at a time.  The tricky part is testing
     if *any of the four* bytes in the longword in question are zero.  */
  while (longword_ptr < (unsigned long int *) end_ptr)
    {
      /* We tentatively exit the loop if adding MAGIC_BITS to
         LONGWORD fails to change any of the hole bits of LONGWORD.
         1) Is this safe?  Will it catch all the zero bytes?
         Suppose there is a byte with all zeros.  Any carry bits
         propagating from its left will fall into the hole at its
         least significant bit and stop.  Since there will be no
         carry from its most significant bit, the LSB of the
         byte to the left will be unchanged, and the zero will be
         detected.
         2) Is this worthwhile?  Will it ignore everything except
         zero bytes?  Suppose every byte of LONGWORD has a bit set
         somewhere.  There will be a carry into bit 8.  If bit 8
         is set, this will carry into bit 16.  If bit 8 is clear,
         one of bits 9-15 must be set, so there will be a carry
         into bit 16.  Similarly, there will be a carry into bit
         24.  If one of bits 24-30 is set, there will be a carry
         into bit 31, so all of the hole bits will be changed.
         The one misfire occurs when bits 24-30 are clear and bit
         31 is set; in this case, the hole at bit 31 is not
         changed.  If we had access to the processor carry flag,
         we could close this loophole by putting the fourth hole
         at bit 32!
         So it ignores everything except 128's, when they're aligned
         properly.  */
      longword = *longword_ptr++;
      if ((longword - lomagic) & himagic)
        {
          /* Which of the bytes was the zero?  If none of them were, it was
             a misfire; continue the search.  */
          const char *cp = (const char *) (longword_ptr - 1);
          char_ptr = cp;
          if (cp[0] == 0)
            break;
          char_ptr = cp + 1;
          if (cp[1] == 0)
            break;
          char_ptr = cp + 2;
          if (cp[2] == 0)
            break;
          char_ptr = cp + 3;
          if (cp[3] == 0)
            break;
          if (sizeof (longword) > 4)
            {
              char_ptr = cp + 4;
              if (cp[4] == 0)
                break;
              char_ptr = cp + 5;
              if (cp[5] == 0)
                break;
              char_ptr = cp + 6;
              if (cp[6] == 0)
                break;
              char_ptr = cp + 7;
              if (cp[7] == 0)
                break;
            }
        }
      char_ptr = end_ptr;
    }
  if (char_ptr > end_ptr)
    char_ptr = end_ptr;
  return char_ptr - str;
}


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


	int count = (param->array_size > 0) ? param->array_size : 1;

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
			size_t len;
			if (value) {
				len = strnlen(value, param->array_size);

				mpack_start_str(writer, len);

				if (writer->size - writer->used < len) {
					writer->error = mpack_error_too_big;
					break;
				}

				memcpy(writer->buffer + writer->used, (char *) value, len);

			} else {
				char tmp[param->array_size];
				param_get_data(param, tmp, param->array_size);
				len = strnlen(tmp, param->array_size);

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

			mpack_start_bin(writer, param->array_size);

			unsigned int size = (param->array_size > 0) ? param->array_size : 1;
			if (writer->size - writer->used < size) {
				writer->error = mpack_error_too_big;
				break;
			}

			if (value) {
				memcpy(writer->buffer + writer->used, value, size);
			} else {
				param_get_data(param, writer->buffer + writer->used, size);
			}
			writer->used += param->array_size;
			mpack_finish_bin(writer);
			break;

		default:
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

void param_deserialize_from_mpack_to_param(void * context, void * queue, param_t * param, int offset, mpack_reader_t * reader) {

	if (offset < 0)
		offset = 0;

	int count = 1;

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
			if (len == 0) {
				param_set_string(param, "", 1);
			} else {
				param_set_string(param, &reader->buffer[reader->pos], len);
			}
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
			mpack_discard(reader);
			break;
		}

		if (mpack_reader_error(reader) != mpack_ok) {
			return;
		}

	}

}
