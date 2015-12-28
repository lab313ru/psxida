#ifndef __GPU_H__
#define __GPU_H__

int gpuReadStatus();

void psxDma2(u32 madr, u32 bcr, u32 chcr);
void gpuInterrupt();

#endif
