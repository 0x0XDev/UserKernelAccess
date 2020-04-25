//
//  tfp0_Patch.h
//  SysPlus
//
//  Created by Leonardos Jr. on 18.04.20.
//  Copyright © 2020 Leonardos Jr. All rights reserved.
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
