//
//  tfp0_Patch.c
//  UserKernelAccess
//
//
//  Copyright © 2020 Anonymouz4. All rights reserved.
//

#include "tfp0_Patch.h"
#include "KernelTools.h"
#include "RuntimeSymPatch.h"


kern_return_t remapKernTask(void);
kern_return_t restoreKernTask(void);

bool patch_zone_require(bool patch);


bool allowTFP0() {
	return (remapKernTask() == KERN_SUCCESS) & patch_zone_require(true);
}
bool denyTFP0() {
	return (restoreKernTask() == KERN_SUCCESS) & patch_zone_require(false);
}



#pragma mark - kernel_map Patches

#include <stdint.h>             // uintptr_t, uint32_t
#include <string.h>             // strcmp

#include <kern/host.h>          // host_priv_self
#include <kern/task.h>          // kernel_task
#include <mach/boolean.h>       // boolean_t, FALSE
#include <mach/kern_return.h>   // KERN_*, kern_return_t
#include <mach/kmod.h>          // kmod_*_t
#include <mach/mach_host.h>     // mach_zone_*
#include <mach/mach_types.h>    // host_priv_t, ipc_space_t, task_t
#include <mach/port.h>          // ipc_port_t
#include <mach/vm_types.h>      // mach_vm_*_t, natural_t, vm_*_t
#include <mach-o/loader.h>      // MH_MAGIC_64

struct host {
    char _[0x10];
    ipc_port_t special[8];
};
#define IKOT_NONE 0
#define IKOT_TASK 2

typedef vm_offset_t ipc_kobject_t;
typedef natural_t   ipc_kobject_type_t;
typedef void*		vm_map_copy_t;

static vm_size_t		sizeof_task = 0;
static kern_return_t	(*_mach_zone_info)(host_priv_t host, mach_zone_name_array_t *names, mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info, mach_msg_type_number_t *infoCnt) = 0;
static kern_return_t	(*_vm_map_copyout)(vm_map_t dst_map, vm_map_address_t *dst_addr, vm_map_copy_t copy) = 0;
static kern_return_t	(*_mach_vm_deallocate)(vm_map_t map, vm_offset_t start, vm_size_t size) = 0;
static kern_return_t	(*_mach_vm_remap)(vm_map_t target, mach_vm_address_t *dst, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t source, mach_vm_address_t src, boolean_t copy, vm_prot_t *cur, vm_prot_t *mac, vm_inherit_t inherit) = 0;
static kern_return_t	(*_mach_vm_wire)(host_priv_t host, vm_map_t map, mach_vm_address_t addr, mach_vm_size_t size, vm_prot_t prot) = 0;
static ipc_port_t		(*_ipc_port_alloc_special)(ipc_space_t space) = 0;
static void				(*_ipc_port_dealloc_special)(ipc_port_t port, ipc_space_t space) = 0;
static void				(*_ipc_kobject_set)(ipc_port_t port, ipc_kobject_t kobject, ipc_kobject_type_t type) = 0;
static ipc_port_t		(*_ipc_port_make_send)(ipc_port_t port) = 0;

static mach_vm_offset_t remap_addr = 0;

kern_return_t remapKernTask() {
	
	host_priv_t host = host_priv_self();
    LOG_PTR("realhost", host);
    if(!host) return KERN_RESOURCE_SHORTAGE;
    if(host->special[4]) {
        LOG("realhost.special[4] exists already!");
		return KERN_NO_SPACE;
    }
	
    SYM(mach_zone_info);
    SYM(vm_map_copyout);
    SYM(mach_vm_deallocate);
    SYM(mach_vm_remap);
    SYM(ipc_port_alloc_special);
    SYM(ipc_port_dealloc_special);
    SYM(ipc_kobject_set);
    SYM(ipc_port_make_send);
	
	if (!(_mach_vm_wire = getSymbolAddr("mach_vm_wire_external")) && !(_mach_vm_wire = getSymbolAddr("mach_vm_wire"))) return false;
	LOG_PTR("sym(mach_vm_wire)", _mach_vm_wire);

    vm_map_t zmap = *_zone_map;
    LOG_PTR("zone_map", zmap);
    if(!zmap) return KERN_RESOURCE_SHORTAGE;

    ipc_space_t space = *_ipc_space_kernel;
    LOG_PTR("ipc_space_kernel", space);
    if(!space) return KERN_RESOURCE_SHORTAGE;

    vm_map_copy_t namesCopy;
    mach_msg_type_number_t nameCnt;
    vm_map_copy_t infoCopy;
    mach_msg_type_number_t infoCnt;
	kern_return_t ret = KERN_SUCCESS;
    ret = _mach_zone_info(host, (mach_zone_name_array_t*)&namesCopy, &nameCnt, (mach_zone_info_array_t*)&infoCopy, &infoCnt);
    LOG("mach_zone_info(): %u", ret);
    if(ret) return ret;

    mach_zone_name_t *names;
	mach_zone_info_t *info = NULL;
    ret = _vm_map_copyout(kernel_map, (vm_map_address_t*)&names, namesCopy);
    if(!ret) ret = _vm_map_copyout(kernel_map, (vm_map_address_t*)&info, infoCopy);
    LOG("vm_map_copyout(): %u", ret);
    if(ret) return ret;

    if(nameCnt != infoCnt) {
        LOG("nameCnt (%u) != infoCnt (%u)", nameCnt, infoCnt);
        _mach_vm_deallocate(kernel_map, (vm_offset_t)names, nameCnt * sizeof(*names));
        _mach_vm_deallocate(kernel_map, (vm_offset_t)info, infoCnt * sizeof(*info));
        return KERN_INVALID_VALUE;
    }
    for(size_t i = 0; i < nameCnt; ++i)
        if(strcmp(names[i].mzn_name, "tasks") == 0) {
            sizeof_task = info[i].mzi_elem_size;
            break;
        }
	
    ret = _mach_vm_deallocate(kernel_map, (vm_offset_t)names, nameCnt * sizeof(*names));
    if(ret == KERN_SUCCESS)  _mach_vm_deallocate(kernel_map, (vm_offset_t)info, infoCnt * sizeof(*info));
    LOG("mach_vm_deallocate(): %u", ret);
    if(ret != KERN_SUCCESS) return ret;

    if(!sizeof_task) {
        LOG("Failed to find tasks zone");
        return KERN_RESOURCE_SHORTAGE;
    }
    LOG("sizeof(task_t): 0x%lx", sizeof_task);

    vm_prot_t cur, max;
    ret = _mach_vm_remap(kernel_map, &remap_addr, sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, zmap, (mach_vm_address_t)kernel_task, FALSE, &cur, &max, VM_INHERIT_NONE);
    LOG("mach_vm_remap(): %u", ret);
    if(ret) return ret;
    LOG_PTR("remap_addr", remap_addr);

    // mach_vm_wire is much easier to use, but increases user wires rather than kernel ones.
    // This is kinda bad for something as critical as tfp0, but for now it seems to work.
    // TODO: Would be nice to use vm_map_wire/vm_map_unwire one day.
    ret = _mach_vm_wire(host, kernel_map, remap_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    LOG("mach_vm_wire(): %u", ret);
    if(ret) return ret;

    ipc_port_t port = _ipc_port_alloc_special(space);
    LOG_PTR("port", port);
    if(!port) return KERN_RESOURCE_SHORTAGE;

    _ipc_kobject_set(port, remap_addr, IKOT_TASK);
    host->special[4] = _ipc_port_make_send(port);

	return KERN_SUCCESS;
}

kern_return_t restoreKernTask() {
	
	if (!remap_addr) return KERN_RESOURCE_SHORTAGE;
	
	host_priv_t host = host_priv_self();
	LOG_PTR("realhost", host);
	if(!host) return KERN_RESOURCE_SHORTAGE;

	ipc_port_t port = host->special[4];
	if(!port) {
		LOG("realhost.special[4] doesn't exist...");
		return KERN_SUCCESS;
	}

	host->special[4] = 0;
	_ipc_kobject_set(port, IKOT_NONE, 0);
	_ipc_port_dealloc_special(port, *_ipc_space_kernel);

	kern_return_t ret = _mach_vm_wire(host, kernel_map, remap_addr, sizeof_task, VM_PROT_NONE);
	LOG("mach_vm_unwire(): %u", ret);
	if(ret) return ret;

	// TODO: Find a way to remove the memory entry without freeing the backing memory.
#if 0
	ret = _mach_vm_deallocate(*_kernel_map, remap_addr, sizeof_task);
	LOG("mach_vm_deallocate(): %u", ret);
	if(ret) return ret;
#endif

	return KERN_SUCCESS;
}



#pragma mark - zone_require Patch

bool patch_zone_require(bool patch) {
	
	typedef struct zone *zone_t;
	static void (*_zone_require)(void *addr, zone_t expected_zone) = 0;

	static const uint8_t returnByte	= 0xC3;
	static uint8_t firstByte = 0;
	
	if (!_zone_require && !(_zone_require = (void*)getSymbolAddr("zone_require"))) return false;
	
	uint8_t byteToWrite = returnByte;
	if (!patch && !firstByte) return false;
	else if (!patch) byteToWrite = firstByte;
	else if (patch && !firstByte) firstByte = *(uint8_t*)_zone_require;
		
	paddr_t paddr = kernel_virtual_to_physical((kaddr_t)_zone_require);
	if (paddr == 0) return false;

	bool success = kWrite8PHY(paddr, byteToWrite);
	if (!success) return false;
	
	return true;
}


