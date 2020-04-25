//
//  tfp0_Patch.h
//  UserKernelAccess
//
//
//  Copyright © 2020 Anonymouz4. All rights reserved.
//

#ifndef tfp0_Patch_h
#define tfp0_Patch_h

#include "Types.h"

#ifndef __x86_64__
#   error "Only x86_64 is supported"
#endif

bool allowTFP0(void);
bool denyTFP0(void);

void setBreakpoint(kaddr_t addr);
uint32_t getFunctionLen(kaddr_t addr);

#endif /* tfp0_Patch_h */
