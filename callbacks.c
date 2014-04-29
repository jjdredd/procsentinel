#include "callbacks.h"
#include "sentinel.h"
#include "util.h"

int CBCKRegistered = 0;		/* set if callbacks registered/hooked */
PVOID RegistrationHandle;
extern LIST_ENTRY ProcessListHead;
/* relax, these will be NOTted before ANDing with the ones passed in */
/* so set them naturally */
ACCESS_MASK PROCESS_DESIRED_ACCESS_MASK
= PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
  | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
  PROCESS_ORIGINAL_ACCESS_MASK
  = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE
  | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

/* set callbacks/hooks (hooking xp only) */
NTSTATUS SetCallbacks(void){
  NTSTATUS NtStatus;
  UNICODE_STRING Altitude;
  OB_CALLBACK_REGISTRATION CallbackRegistration;
  OB_OPERATION_REGISTRATION OperationRegistration;

  RtlZeroMemory(&CallbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
  RtlZeroMemory(&OperationRegistration, sizeof(OB_OPERATION_REGISTRATION));
  RtlInitUnicodeString(&Altitude, L"42000");  //adjust later

  /* ATTENTION!!! register PsThreadType too!! */
  OperationRegistration.ObjectType = PsProcessType;
  OperationRegistration.Operations 
    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
  OperationRegistration.PreOperation = &PreCallback;
  OperationRegistration.PostOperation = &PostCallback;
  CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
  CallbackRegistration.OperationRegistrationCount = 1; //set later
  CallbackRegistration.Altitude = Altitude;
  /* allocate a buffer, write a key and pass buffer address ?
  CallbackRegistration.RegistrationContext = &key;
  */
  CallbackRegistration.OperationRegistration = &OperationRegistration;
  //match unregister in the unload function
  NtStatus = ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
  if(NT_SUCCESS(NtStatus)) CBCKRegistered = 1;
  else DbgPrint("ObRegisterCallbacks() failed with 0X%X\n", NtStatus);
  return NtStatus;
}
/* remove callbacks/hooks (hooks winxp only) */
void ClearCallbacks(void){
  if(CBCKRegistered) ObUnRegisterCallbacks(RegistrationHandle);
  return;
}
/* callback routines. in case some1 wants to open/dup a handle */
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID Context, 
				     POB_PRE_OPERATION_INFORMATION OpInfo){
  HANDLE pid;
  /* do we really need the following check? rethink */ 
  /* if( (OpInfo->Object == PsGetCurrentProcess()) 
   *     || (OpInfo->KernelHandle == 1))
   *   return STATUS_SUCCESS; */
  if(OpInfo->ObjectType == *PsProcessType){
    pid = PsGetProcessId(OpInfo->Object);
    if ( !LocatePIDEntry(&ProcessListHead, pid)
	 || (pid == PsGetCurrentProcessId()) ) return STATUS_SUCCESS;
    /* DbgPrint("Trying to open process %li\n", pid); */
  }else if(OpInfo->ObjectType == *PsThreadType){ /* FIXME NEED to register this!!! */
    DbgPrint("opening pocess handle\n");
    /* pid = PsGetThreadId(OpInfo->Object); */
    /* !!! Use PsGetThreadProcessId !!!!!!! */
    pid = PsGetThreadProcessId(OpInfo->Object);
    if(!LocatePIDEntry(&ProcessListHead, pid)
       || (pid == PsGetCurrentProcessId())) return STATUS_SUCCESS;
    /* DbgPrint("Trying to open thread of process %li\n", pid); */
  }else 
    DbgPrint("unknown handle type %p %p %p\n", OpInfo->ObjectType,
	     PsProcessType, PsThreadType);
  /* pid = PsGetProcessId(OpInfo->Object); */
  /* if(LocatePIDEntry(&ProcessListHead, pid)) */
  /*   DbgPrint("Trying to open subject pid %li\n", pid); */

  switch(OpInfo->Operation){
    /* DO NOT forget NOTting before ANDing */
  case OB_OPERATION_HANDLE_CREATE:
    OpInfo->Parameters->CreateHandleInformation.DesiredAccess
      &= ~PROCESS_DESIRED_ACCESS_MASK;
    OpInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess
      &= ~PROCESS_ORIGINAL_ACCESS_MASK;
    break;
  case OB_OPERATION_HANDLE_DUPLICATE:
    OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess
      &= ~PROCESS_DESIRED_ACCESS_MASK;
    OpInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess
      &= ~PROCESS_ORIGINAL_ACCESS_MASK;
    break;
  default: 			/* lol */
    return STATUS_SUCCESS;
  }
    
  return STATUS_SUCCESS;
}
void PostCallback(PVOID Context, POB_POST_OPERATION_INFORMATION OpInfo){
  return;
}
