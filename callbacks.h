#ifndef _CALLBACKS_
#define _CALLBACKS_
#include <Fltkernel.h>
/* process access rights. is there a more appropriate header for this? */
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_DUP_HANDLE 0x0040
#define PROCESS_TERMINATE 0x0001
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_WRITE 0x0020

NTSTATUS SetCallbacks(void);
void ClearCallbacks(void);
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID, POB_PRE_OPERATION_INFORMATION);
void PostCallback(PVOID, POB_POST_OPERATION_INFORMATION);
#endif
