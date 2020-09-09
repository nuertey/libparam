/*
 * param_list.c
 *
 *  Created on: Oct 9, 2016
 *      Author: johan
 */

#include <csp/csp.h>
#include <csp/arch/csp_malloc.h>
#include <csp/csp_endian.h>
#include <param/param.h>
#include <param/param_list.h>
#include <param/param_server.h>

#include "../param_string.h"
#include "param_list.h"
#include "libparam.h"

#ifdef PARAM_HAVE_SYS_QUEUE
#include <sys/queue.h>
#endif

/**
 * The storage size (i.e. how closely two param_t structs are packed in memory)
 * varies from platform to platform (in example on x64 and arm32). This macro
 * defines two param_t structs and saves the storage size in a define.
 */
#ifndef PARAM_STORAGE_SIZE
static const param_t param_size_set[2] __attribute__((aligned(1)));
#define PARAM_STORAGE_SIZE ((intptr_t) &param_size_set[1] - (intptr_t) &param_size_set[0])
#endif

#ifdef PARAM_HAVE_SYS_QUEUE
static SLIST_HEAD(param_list_head_s, param_s) param_list_head = {};
#endif

param_t * param_list_iterate(param_list_iterator * iterator) {

	/**
	 * GNU Linker symbols. These will be autogenerate by GCC when using
	 * __attribute__((section("param"))
	 */
	__attribute__((weak)) extern param_t __start_param;
	__attribute__((weak)) extern param_t __stop_param;

	/* First element */
	if (iterator->element == NULL) {

		/* Static */
		if ((&__start_param != NULL) && (&__start_param != &__stop_param)) {
			iterator->phase = 0;
			iterator->element = &__start_param;
		} else {
			iterator->phase = 1;
#ifdef PARAM_HAVE_SYS_QUEUE
			iterator->element = SLIST_FIRST(&param_list_head);
#endif
		}

		return iterator->element;
	}

	/* Static phase */
	if (iterator->phase == 0) {

		/* Increment in static memory */
		iterator->element = (param_t *)(intptr_t)((char *)iterator->element + PARAM_STORAGE_SIZE);

		/* Check if we are still within the bounds of the static memory area */
		if (iterator->element < &__stop_param)
			return iterator->element;

		/* Otherwise, switch to dynamic phase */
		iterator->phase = 1;
#ifdef PARAM_HAVE_SYS_QUEUE
		iterator->element = SLIST_FIRST(&param_list_head);
		return iterator->element;
#else
		return NULL;
#endif
	}

#ifdef PARAM_HAVE_SYS_QUEUE
	/* Dynamic phase */
	if (iterator->phase == 1) {

		iterator->element = SLIST_NEXT(iterator->element, next);
		return iterator->element;
	}
#endif

	return NULL;

}


int param_list_add(param_t * item) {
	if (param_list_find_id(item->node, item->id) != NULL)
		return -1;
#ifdef PARAM_HAVE_SYS_QUEUE
	SLIST_INSERT_HEAD(&param_list_head, item, next);
#else
	return -1;
#endif
	return 0;
}

param_t * param_list_find_id(int node, int id)
{
	if (node == -1)
		node = PARAM_LIST_LOCAL;
	if (node == csp_get_address())
		node = PARAM_LIST_LOCAL;

	param_t * found = NULL;
	param_t * param;
	param_list_iterator i = {};
	while ((param = param_list_iterate(&i)) != NULL) {

		if (param->node != (uint8_t) node)
			continue;

		if (param->id == id) {
			found = param;
			break;
		}

		continue;
	}

	return found;
}

param_t * param_list_find_name(int node, char * name)
{
	if (node == -1)
		node = PARAM_LIST_LOCAL;

	param_t * found = NULL;
	param_t * param;
	param_list_iterator i = {};
	while ((param = param_list_iterate(&i)) != NULL) {

		if (param->node != (uint8_t) node)
			continue;

		if (strcmp(param->name, name) == 0) {
			found = param;
			break;
		}

		continue;
	}

	return found;
}


