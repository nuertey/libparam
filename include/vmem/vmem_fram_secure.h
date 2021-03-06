/*
 * vmem_fram_secure.h
 *
 *  Created on: Sep 28, 2016
 *      Author: johan
 */

#ifndef SRC_PARAM_VMEM_FRAM_SECURE_H_
#define SRC_PARAM_VMEM_FRAM_SECURE_H_

#include <vmem/vmem.h>

void vmem_fram_secure_init(const vmem_t * vmem);
void vmem_fram_secure_read(const vmem_t * vmem, uint32_t addr, void * dataout, int len);
void vmem_fram_secure_write(const vmem_t * vmem, uint32_t addr, void * datain, int len);
int vmem_fram_secure_backup(const vmem_t * vmem);
int vmem_fram_secure_restore(const vmem_t * vmem);

typedef const struct {
	uint8_t *data;
	int fram_primary_addr;
	int fram_backup_addr;
	void (*fallback_fct)(void);
} vmem_fram_secure_driver_t;

#define VMEM_DEFINE_FRAM_SECURE(name_in, strname, fram_primary_addr_in, fram_backup_addr_in, _fallback_fct, size_in, _vaddr) \
	uint8_t vmem_##name_in##_heap[size_in] = {}; \
	static const vmem_fram_secure_driver_t vmem_##name_in##_driver = { \
		.data = vmem_##name_in##_heap, \
		.fram_primary_addr = fram_primary_addr_in, \
		.fram_backup_addr = fram_backup_addr_in, \
		.fallback_fct = _fallback_fct, \
	}; \
	__attribute__((section("vmem"))) \
	__attribute__((aligned(1))) \
	__attribute__((used)) \
	const vmem_t vmem_##name_in= { \
		.type = VMEM_TYPE_FRAM_SECURE, \
		.name = strname, \
		.size = size_in, \
		.read = vmem_fram_secure_read, \
		.write = vmem_fram_secure_write, \
		.backup = vmem_fram_secure_backup, \
		.restore = vmem_fram_secure_restore, \
		.driver = &vmem_##name_in##_driver, \
		.vaddr = (void *) _vaddr, \
	};

#endif /* SRC_PARAM_VMEM_FRAM_SECURE_H_ */
