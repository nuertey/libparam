/*
 * param_queue.c
 *
 *  Created on: Nov 9, 2017
 *      Author: johan
 */

#include <stdio.h>
#include <csp/csp.h>
#include <mpack/mpack.h>

#include <param/param.h>
#include <param/param_server.h>
#include <param/param_queue.h>
#include <param/param_list.h>

#include "param_serializer.h"
#include "param_string.h"

void param_queue_init(param_queue_t * queue, void * buffer, int buffer_size, int used, param_queue_type_e type) {
    queue->buffer = buffer;
    queue->buffer_size = buffer_size;
    queue->type = type;
    queue->used = used;
}

int param_queue_add(param_queue_t *queue, param_t *param, int offset, void *value) {
    mpack_writer_t writer;
    mpack_writer_init(&writer, queue->buffer, queue->buffer_size);
    writer.used = queue->used;
    if (queue->type == PARAM_QUEUE_TYPE_SET) {
        param_serialize_to_mpack(param, offset, &writer, value);
    } else {
        param_serialize_id(&writer, param, offset);
    }
    if (mpack_writer_error(&writer) != mpack_ok)
        return -1;
    queue->used = writer.used;
    return 0;
}

int param_queue_foreach(param_queue_t *queue, param_queue_callback_f callback, void * context) {

    mpack_reader_t reader;
    mpack_reader_init_data(&reader, queue->buffer, queue->used);
    while(reader.left > 0) {
        int id, node, offset = -1;
        param_deserialize_id(&reader, &id, &node, &offset);
        param_t * param = param_list_find_id(node, id);
        //param_t * param = &tlm_int_temp;
        if (param) {
            callback(context, queue, param, offset, &reader);
        }
    }

    return mpack_ok;

}

int param_queue_foreach_bms(param_t *param, param_queue_t *queue, param_queue_callback_f callback, void * context) {

    mpack_reader_t reader;
    mpack_reader_init_data(&reader, queue->buffer, queue->used);
    while(reader.left > 0) {
        int id, node, offset = -1;
        param_deserialize_id(&reader, &id, &node, &offset);
        //param_t * param = param_list_find_id(node, id);
        //extern param_t tlm_int_temp;
        //param_t * param = &tlm_int_temp; 
        if (param) {
            callback(context, queue, param, offset, &reader);
        }
    }

    return mpack_ok;

}

int param_queue_apply(param_queue_t *queue) {
    return param_queue_foreach(queue, (param_queue_callback_f) param_deserialize_from_mpack_to_param, NULL);
}

int param_queue_apply_bms(param_t *param, param_queue_t *queue) {
    return param_queue_foreach_bms(param, queue, (param_queue_callback_f) param_deserialize_from_mpack_to_param, NULL);
}

static int param_queue_print_callback(void * ctx, param_queue_t *queue, param_t *param, int offset, void *reader) {

    return 0;
}

static int param_queue_print_local_callback(void * ctx, param_queue_t *queue, param_t *param, int offset, void *reader) {
    mpack_discard(reader);
    return 0;
}

void param_queue_print(param_queue_t *queue) {
    param_queue_foreach(queue, param_queue_print_callback, NULL);
}

void param_queue_print_local(param_queue_t *queue) {
    param_queue_foreach(queue, param_queue_print_local_callback, NULL);
}
