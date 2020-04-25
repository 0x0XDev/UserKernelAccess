//
//  tfp0_Patch.c
//  SysPlus
//
//  Created by Leonardos Jr. on 18.04.20.
//  Copyright © 2020 Leonardos Jr. All rights reserved.
//

#include "tfp0_Patch.h"
#include "KernelTools.h"
#include "RuntimeSymPatch.h"

#include <mach/task.h>
static kern_return_t (*_task_conversion_eval)(task_t caller, task_t victim) = 0;

kern_return_t remapKernTask(void);
kern_return_t restoreKernTask(void);

bool patchNonInline(bool patch, bool firstMethod);
bool patchInline1(bool patch);
bool patchInline2(bool patch);


bool allowTFP0() {
	return (remapKernTask() == KERN_SUCCESS) & patchInline1(true) & patchInline2(true); //NonInline won't get called anyways
}
bool denyTFP0() {
	return (restoreKernTask() == KERN_SUCCESS) & patchInline1(false) & patchInline2(false); //NonInline won't get called anyways
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
typedef void        *vm_map_copy_t;

static vm_size_t		sizeof_task = 0;
static vm_map_t			*_zone_map = 0;
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
	
    SYM(zone_map);
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



#pragma mark - zone_require Patches

#include "RuntimeSymPatch.h"

bool patchNonInline(bool patch, bool firstMethod) {
	
	static const uint8_t code[] =
	//0000000000000000 <_task_conversion_eval>:
	/* 0:*/	"\x55"							//push   rbp
	/* 1:*/	"\x48\x89\xe5"					//mov    rbp,rsp
	/* 4:*/	"\x31\xc0"						//xor    eax,eax
	/* 6:*/	"\x48\x39\xf7"					//cmp    rdi,rsi							# caller == victim
	/* 9:*/	"\x74\x2f"						//je     0x3a								# -> return KERN_SUCCESS
	/* b:*/	"\x48\x8b\x0d\xce\x7b\xab\x00"	//mov    rcx,qword [_kernel_task]			# rcx,QWORD PTR [rip+0xab7bce]
	/*12:*/	"\x48\x39\xf9"					//cmp    rcx,rdi							# caller == kernel_task
	/*15:*/	"\x74\x23"						//je     0x3a								# -> return KERN_SUCCESS
	/*17:*/	"\xb8\x23\x00\x00\x00"			//mov    eax,0x23
	/*1c:*/	"\x48\x85\xf6"					//test   rsi,rsi							# victim == TASK_NULL
	/*1f:*/	"\x74\x19"						//je     0x3a								# -> return KERN_INVALID_SECURITY
	/*21:*/	"\x48\x39\xf1"					//cmp    rcx,rsi							# victim == kernel_task
	/*24:*/	"\x74\x14"						//je     0x3a								# -> return KERN_INVALID_SECURITY
	/*26:*/	"\x48\x8b\x05\x7b\x7b\xab\x00"	//mov    rax,qword [_task_zone]				# rax,QWORD PTR [rip+0xab7b7b]
	/*2d:*/	"\x48\x89\xf7"					//mov    rdi,rsi
	/*30:*/	"\x48\x89\xc6"					//mov    rsi,rax
	/*33:*/	"\xe8\x98\x8f\x05\x00"			//call   0x58fd0
	/*38:*/	"\x31\xc0"						//xor    eax,eax
	/*3a:*/	"\x5d"							//pop    rbp
	/*3b:*/	"\xc3"							//ret
	/*3c:*/	"\x0f\x1f\x40\x00"				//nop    DWORD PTR [rax+0x0]
	;
	
	//Method 1: Override Failure Return Value
	static const uint FAILURE_RETURN_CODE_OFFSET	= 0x18; //24
	static const uint8_t RETURN_CODE_REPLACEMENT	= 0x0;

	//Method 2: Override Failure JMP Addr
	static const uint JMP_RETURN_OFFSET				= 0x25; //37
	static const uint8_t JMP_RETURN_REPLACEMENT		= 0x12; //18
	

	//Integrity Check
	uint offset = firstMethod ? FAILURE_RETURN_CODE_OFFSET:JMP_RETURN_OFFSET;
	uint8_t replacement = firstMethod ? RETURN_CODE_REPLACEMENT:JMP_RETURN_REPLACEMENT;
	if (_task_conversion_eval == NULL && !(_task_conversion_eval = (void*)getSymbolAddr("task_conversion_eval"))) return false;
	
	uint8_t check = *(uint8_t*)(_task_conversion_eval + offset);
	bool isPatched;
	
	//Switch doesn't work here
	if (check == code[offset]) isPatched = false;		//not patched
	else if (check == replacement) isPatched = true;	//already patched
	else return false;									//codebase changed, err

	if (patch == isPatched) return true;
	

	//Patch
	kaddr_t patchAddr = (kaddr_t)_task_conversion_eval + offset;
	
	paddr_t paddr = kernel_virtual_to_physical(patchAddr);
	if (paddr == 0) return false;
	
	bool success = kWrite8PHY(paddr, replacement);
	if (!success) return false;

	return *(uint8_t*)patchAddr == replacement;
}

#pragma mark Patch inlined `task_conversion_eval`

#define MaxSearchBytes 0x10000

// convert_port_to_locked_task
bool patchInline1(bool patch) {
	
	static const uint8_t searchBytes[36] =
	//ffffff80004086a2 <_convert_port_to_locked_task+194>:
	/* ffffff80004086a2:*/	"\x48\x8B\x05\xD7\x7A\xAB\x00"		//mov    rax, qword [_kernel_task]		# rax = _kernel_task
	/* ffffff80004086a9:*/	"\x4C\x39\xF0"						//cmp    rax, r14						# r14 = callee
	/* ffffff80004086ac:*/	"\x74\x18"							//je     loc_ffffff80004086c6			# if (callee == kernel_task) -> SUCCESS
	/* ffffff80004086ae:*/	"\x48\x39\xD8"						//cmp    rax, rbx						# rbx = victim
	/* ffffff80004086b1:*/	"\x0F\x84\xC2\x00\x00\x00"			//je     loc_ffffff8000408779			# if (victim == kernel_task) -> ERR
	/* ffffff80004086b7:*/	"\x48\x8B\x35\x8A\x7A\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff80004086be:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff80004086c1:*/	"\xE8\xAA\x8E\x05\x00"				//call   _zone_require
	;
	static const uint8_t replaceBytes[36] =
	//ffffff80004086a2 <_convert_port_to_locked_task+194>:
	/* ffffff80004086a2:*/	"\x48\x8B\x05\xD7\x7A\xAB\x00"		//mov    rax, qword [_kernel_task]
	/* ffffff80004086a9:*/	"\x4C\x39\xF0"						//cmp    rax, r14
	/* ffffff80004086ac:*/	"\x74\x18"							//je     loc_ffffff80004086c6
	/* ffffff80004086ae:*/	"\x48\x39\xD8"						//cmp    rax, rbx
	/* ffffff80004086b1:*/	"\x0F\x84\xC2\x00\x00\x00"			//je     loc_ffffff8000408779
	/* ffffff80004086b7:*/	"\x48\x8B\x35\x8A\x7A\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff80004086be:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff80004086c1:*/	"\x0F\x1F\x44\x00\x00"				//nop    dword [rax+rax]				# remove zone_require call
	;
	
	static const uint8_t changeOffset = 31;	//1byte patch
	
	kaddr_t addr = (kaddr_t)getSymbolAddr("convert_port_to_locked_task");
	if (!addr) return false;
	
	for (int i=0;i < MaxSearchBytes;i++) {
		if (memcmp(patch?searchBytes:replaceBytes, (void*)(addr+i), sizeof(searchBytes)) == 0) {
			// Patch nop 4byte
			paddr_t paddr = kernel_virtual_to_physical(addr+i+changeOffset);
			if (paddr == 0) return false;
			bool success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset]);
			if (!success) return false;
			
			return memcmp(patch?replaceBytes:searchBytes, (void*)(addr+i), sizeof(searchBytes)) == 0;
		}
	}
	LOG("nothing found");
	return false;
}


// convert_port_to_task_locked
bool patchInline2(bool patch) {

	
	static const uint8_t searchBytes[32] =
	//ffffff8000408b23 <_convert_port_to_task_locked+131>:
	/* ffffff8000408b23:*/	"\x48\x8B\x05\x56\x76\xAB\x00"		//mov    rax, qword [_kernel_task]		# rax = _kernel_task
	/* ffffff8000408b2a:*/	"\x48\x39\xC8"						//cmp    rax, rcx						# rcx = callee
	/* ffffff8000408b2d:*/	"\x74\x14"							//je     loc_ffffff8000408b43			# if (callee == kernel_task) -> SUCCESS
	/* ffffff8000408b2f:*/	"\x48\x39\xD8"						//cmp    rax, rbx						# rbx = victim
	/* ffffff8000408b32:*/	"\x74\x2F"							//je     loc_ffffff8000408b63			# if (victim == kernel_task) -> ERR
	/* ffffff8000408b34:*/	"\x48\x8B\x35\x0D\x76\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff8000408b3b:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff8000408b3e:*/	"\xE8\x2D\x8A\x05\x00"				//call   _zone_require
	;
	static const uint8_t replaceBytes[32] =
	//ffffff8000408b23 <_convert_port_to_task_locked+131>:
	/* ffffff8000408b23:*/	"\x48\x8B\x05\x56\x76\xAB\x00"		//mov    rax, qword [_kernel_task]
	/* ffffff8000408b2a:*/	"\x48\x39\xC8"						//cmp    rax, rcx
	/* ffffff8000408b2d:*/	"\x74\x14"							//je     loc_ffffff8000408b43
	/* ffffff8000408b2f:*/	"\x48\x39\xD8"						//cmp    rax, rbx
	/* ffffff8000408b32:*/	"\x74\x2F"							//je     loc_ffffff8000408b63
	/* ffffff8000408b34:*/	"\x48\x8B\x35\x0D\x76\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff8000408b3b:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff8000408b3e:*/	"\x0F\x1F\x44\x00\x00"				//nop    dword [rax+rax]				# remove zone_require call
	;
	
	static const uint8_t changeOffset = 27;	//1byte patch
	
	kaddr_t addr = (kaddr_t)getSymbolAddr("convert_port_to_task_locked");
	if (!addr) return false;
	
	for (int i=0;i < MaxSearchBytes;i++) {
		if (memcmp(patch?searchBytes:replaceBytes, (void*)(addr+i), sizeof(searchBytes)) == 0) {
			
			// Patch nop 4byte
			paddr_t paddr = kernel_virtual_to_physical(addr+i+changeOffset);
			if (paddr == 0) return false;
			bool success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset]);
			if (!success) return false;
			
			return memcmp(patch?replaceBytes:searchBytes, (void*)(addr+i), sizeof(searchBytes)) == 0;
		}
	}
	LOG("nothing found");
	return false;
}



void setBreakpoint(kaddr_t addr) {
	static const uint8_t BREAKPOINT_BYTE		= 0xCC; //__asm__("int3")

	paddr_t paddr = kernel_virtual_to_physical(addr);
	if (paddr == 0) return;

	bool success = kWrite8PHY(paddr, BREAKPOINT_BYTE);
	if (!success) return;
}


//find 5D C3 (pop, ret)
#define MaxFuncLen 0x10000

uint32_t getFunctionLen(kaddr_t addr) {
	uint32_t len = 0;
	uint8_t oldbyte = 0;
	uint8_t cbyte = 0;
	for (;len < MaxFuncLen && !(oldbyte == 0x5D && cbyte == 0xC3);len++) {
		oldbyte = cbyte;
		cbyte = *(uint8_t*)(addr+len);
	}
	return len == MaxFuncLen ? 0 : len;
}



