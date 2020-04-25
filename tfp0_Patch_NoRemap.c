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
#include <mach/task.h>

bool setKernelMap(bool set);
bool patchNonInline(bool patch, bool firstMethod);
bool patchInline1(bool patch);
bool patchInline2(bool patch);
bool patchInline3(bool patch);
bool patch_zone_require(bool patch);

bool allowTFP0() {
	return setKernelMap(true) & patch_zone_require(true) & patchInline1(true) & patchInline2(true) & patchInline3(true) & patchNonInline(true,true); //NonInline won't get called anyways
}
bool denyTFP0() {
	return setKernelMap(true) & patch_zone_require(false) & patchInline1(false) & patchInline2(false) & patchInline3(false) & patchNonInline(false,true); //NonInline won't get called anyways
}


#pragma mark - Set kernel_map for host->special[4]

#include <kern/host.h>          // host_priv_self
struct host {
    char _[0x10];
    ipc_port_t special[8];
};
#define IKOT_NONE 0
#define IKOT_TASK 2

bool setKernelMap(bool set) {

	typedef vm_offset_t ipc_kobject_t;
	typedef natural_t   ipc_kobject_type_t;
	static void (*_ipc_kobject_set)(ipc_port_t port, ipc_kobject_t kobject, ipc_kobject_type_t type) = 0;
	static ipc_port_t (*_ipc_port_alloc_special)(ipc_space_t space) = 0;
	static ipc_port_t (*_ipc_port_make_send)(ipc_port_t port) = 0;
	vm_map_t *_zone_map = 0;
	
	host_priv_t host = host_priv_self();
    if(!host) return false;
	
    if(set && host->special[4]) LOG("realhost.special[4] exists already!");
	if(!set) {
		host->special[4] = 0;
		return true;
	}
	
	if (_ipc_port_alloc_special == NULL && !(_ipc_port_alloc_special = (void*)getSymbolAddr("ipc_port_alloc_special"))) return false;
	if (_ipc_kobject_set == NULL && !(_ipc_kobject_set = (void*)getSymbolAddr("ipc_kobject_set"))) return false;
	if (_ipc_port_make_send == NULL && !(_ipc_port_make_send = (void*)getSymbolAddr("ipc_port_make_send"))) return false;
	if (_zone_map == NULL && !(_zone_map = (void*)getSymbolAddr("zone_map"))) return false;
	
    // TODO: Set correct Port
	ipc_port_t port = _ipc_port_alloc_special(ipc_space_kernel);
    LOG_PTR("port", port);
    if(!port) return false;
    _ipc_kobject_set(port, (ipc_kobject_t)zone_map, IKOT_TASK);
    host->special[4] = _ipc_port_make_send(port);
	
	return true;
}



#pragma mark - task_conversion_eval Patches

#include "RuntimeSymPatch.h"

bool patchNonInline(bool patch, bool firstMethod) {
	
	static kern_return_t (*_task_conversion_eval)(task_t caller, task_t victim) = 0;
	
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
	/* ffffff80004086a9:*/	"\x48\x39\xc0"						//cmp    rax, rax
	/* ffffff80004086ac:*/	"\x74\x18"							//je     loc_ffffff80004086c6			# if (kernel_task == kernel_task) -> SUCCESS
	/* ffffff80004086ae:*/	"\x48\x39\xD8"						//cmp    rax, rbx
	/* ffffff80004086b1:*/	"\x0F\x84\xC2\x00\x00\x00"			//je     loc_ffffff8000408779
	/* ffffff80004086b7:*/	"\x48\x8B\x35\x8A\x7A\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff80004086be:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff80004086c1:*/	"\x0F\x1F\x44\x00\x00"				//nop    dword [rax+rax]				# remove zone_require call - won't reach anyways
	;
	
	static const uint changeOffset1 = 7;	//3byte cmp patch
	static const uint changeOffset2 = 31;	//4byte nop patch
	
	kaddr_t addr = (kaddr_t)getSymbolAddr("convert_port_to_locked_task");
	if (!addr) return false;
	
	for (int i=0;i < MaxSearchBytes;i++) {
		if (memcmp(patch?searchBytes:replaceBytes, (void*)(addr+i), sizeof(searchBytes)) == 0) {
			
			// Patch cmp 3byte
			paddr_t paddr = kernel_virtual_to_physical(addr+i+changeOffset1);
			if (paddr == 0) return false;
			bool success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset1]);
			if (!success) return false;
			
			// Patch nop 4byte
			paddr = kernel_virtual_to_physical(addr+i+changeOffset2);
			if (paddr == 0) return false;
			success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset2]);
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
	/* ffffff8000408b2a:*/	"\x48\x39\xC0"						//cmp    rax, rax
	/* ffffff8000408b2d:*/	"\x74\x14"							//je     loc_ffffff8000408b43			# if (kernel_task == kernel_task) -> SUCCESS
	/* ffffff8000408b2f:*/	"\x48\x39\xD8"						//cmp    rax, rbx
	/* ffffff8000408b32:*/	"\x74\x2F"							//je     loc_ffffff8000408b63
	/* ffffff8000408b34:*/	"\x48\x8B\x35\x0D\x76\xAB\x00"		//mov    rsi, qword [_task_zone]
	/* ffffff8000408b3b:*/	"\x48\x89\xDF"						//mov    rdi, rbx
	/* ffffff8000408b3e:*/	"\x0F\x1F\x44\x00\x00"				//nop    dword [rax+rax]				# remove zone_require call - won't reach anyways
	;
	
	static const uint changeOffset1 = 7;	//3byte cmp patch
	static const uint changeOffset2 = 27;	//4byte nop patch
	
	kaddr_t addr = (kaddr_t)getSymbolAddr("convert_port_to_task_locked");
	if (!addr) return false;
	
	for (int i=0;i < MaxSearchBytes;i++) {
		if (memcmp(patch?searchBytes:replaceBytes, (void*)(addr+i), sizeof(searchBytes)) == 0) {
			
			// Patch cmp 3byte
			paddr_t paddr = kernel_virtual_to_physical(addr+i+changeOffset1);
			if (paddr == 0) return false;
			bool success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset1]);
			if (!success) return false;
			
			// Patch nop 4byte
			paddr = kernel_virtual_to_physical(addr+i+changeOffset2);
			if (paddr == 0) return false;
			success = kWrite32PHY(paddr, *(uint32_t*)&(patch?replaceBytes:searchBytes)[changeOffset2]);
			if (!success) return false;
			
			return memcmp(patch?replaceBytes:searchBytes, (void*)(addr+i), sizeof(searchBytes)) == 0;
		}
	}
	LOG("nothing found");
	return false;
}


// convert_port_to_thread_locked
bool patchInline3(bool patch) {

	static const uint8_t searchBytes[12] =
	//ffffff8000409228 <_convert_port_to_thread_locked+168>:
	/* ffffff8000409228:*/	"\x48\x8B\x0D\x51\x6F\xAB\x00"		//mov    rcx, qword [_kernel_task]		# rcx = _kernel_task
	/* ffffff800040922f:*/	"\x48\x39\xC1"						//cmp    rcx, rax						# rax = callee
	/* ffffff8000409232:*/	"\x74\x37"							//je     loc_ffffff800040926b			# if (callee == kernel_task) -> SUCCESS
	;
	static const uint8_t replaceBytes[12] =
	//ffffff8000409228 <_convert_port_to_task_locked+131>:
	/* ffffff8000409228:*/	"\x48\x8B\x0D\x51\x6F\xAB\x00"		//mov    rcx, qword [_kernel_task]
	/* ffffff800040922f:*/	"\x48\x39\xC9"						//cmp    rcx, rcx
	/* ffffff8000409232:*/	"\x74\x37"							//je     loc_ffffff800040926b			# if (kernel_task == kernel_task) -> SUCCESS
	;
	static const uint changeOffset = 9;	//1byte cmp patch
	
	kaddr_t addr = (kaddr_t)getSymbolAddr("convert_port_to_thread_locked");
	if (!addr) return false;
	
	for (int i=0;i < MaxSearchBytes;i++) {
		if (memcmp(patch?searchBytes:replaceBytes, (void*)(addr+i), sizeof(searchBytes)) == 0) {
			
			// Patch cmp 1byte
			paddr_t paddr = kernel_virtual_to_physical(addr+i+changeOffset);
			if (paddr == 0) return false;
			bool success = kWrite8PHY(paddr, *(uint8_t*)&(patch?replaceBytes:searchBytes)[changeOffset]);
			if (!success) return false;
			
			return memcmp(patch?replaceBytes:searchBytes, (void*)(addr+i), sizeof(searchBytes)) == 0;
		}
	}
	LOG("nothing found");
	return false;
}









#pragma mark - zone_require Patch

//host_get_special_port will also call `zone_require`

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



