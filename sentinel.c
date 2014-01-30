#include "sentinel.h"
#include "sha1.h"
#include "util.h"

int RegistrationHandle;
//int CBCKRegistered;
UNICODE_STRING usDosDeviceName, MainModuleName;
LIST_ENTRY ProcessListHead;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath){
  NTSTATUS NtStatus = STATUS_SUCCESS;
  PDEVICE_OBJECT pDeviceObject = NULL;
  UNICODE_STRING usDriverName, Altitude;
  int i;
  OB_CALLBACK_REGISTRATION CallbackRegistration;
  OB_OPERATION_REGISTRATION OperationRegistration;

  RtlInitUnicodeString(&usDriverName, L"\\Device\\Sentinel");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Sentinel");
  RtlInitUnicodeString(&MainModuleName, L"hl.exe");
  DbgPrint("Driver Entry \n");
  NtStatus = IoCreateDevice(pDriverObject, 0,
			    &usDriverName,
			    FILE_DEVICE_UNKNOWN,
			    FILE_DEVICE_SECURE_OPEN,
			    FALSE, &pDeviceObject);
  IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
  for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    pDriverObject->MajorFunction[i] = &NotImplemented;
  pDriverObject->MajorFunction[IRP_MJ_CLOSE] = &Close;
  pDriverObject->MajorFunction[IRP_MJ_CREATE] = &Create;
  pDriverObject->MajorFunction[IRP_MJ_READ] = &Read;
  pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &HandleIOCTL;
  pDriverObject->DriverUnload = &Dtor;
  pDeviceObject->Flags |= DO_DIRECT_IO;
  pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

  NtStatus = PsSetLoadImageNotifyRoutine(&LoadImageNotify);
  if(!NT_SUCCESS(NtStatus)){
    DbgPrint("couldn't set imageload notify routine\n");
    return STATUS_UNSUCCESSFUL;
  }
  NtStatus = PsSetCreateProcessNotifyRoutine(&ProcessNotify, 0);
  if(!NT_SUCCESS(NtStatus)){
    DbgPrint("couldn't set create process notify routine\n");
   return STATUS_UNSUCCESSFUL;
  }
  InitializeListHead(&ProcessListHead);
    
  RtlZeroMemory(&CallbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
  RtlZeroMemory(&OperationRegistration, sizeof(OB_OPERATION_REGISTRATION));
  RtlInitUnicodeString(&Altitude, L"idkwat2puthere");  //adjust later
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
  //NtStatus = ObRegisterCallbacks(&CallbackRegistration, &RegistrationHandle);
  DbgPrint("0X%X\n", NtStatus);
  return NtStatus;
}

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID Context, 
				     POB_PRE_OPERATION_INFORMATION OpInfo){

  DbgPrint("Trying to open pid %li\n", PsGetProcessId(OpInfo->Object));
  return STATUS_SUCCESS;
}
void PostCallback(PVOID Context, POB_POST_OPERATION_INFORMATION OpInfo){
  return;
}
void LoadImageNotify(PUNICODE_STRING FullImgName,
					  HANDLE PID,
					  PIMAGE_INFO ImageInfo){
  PROC_ENTRY *ProcEntry;
  MODULE_ENTRY *ModuleEntry;
  if(DoesEndWith(FullImgName, &MainModuleName)){
    DbgPrint("%wZ loaded in %i\n @ 0x%X", FullImgName, PID,
	     ImageInfo->ImageBase);
    if((ProcEntry = ExAllocatePoolWithTag(PagedPool, sizeof(PROC_ENTRY), TAG)) == NULL){
      DbgPrint("Couldn't allocate\n");
      return;
    }
    InitializeListHead(&(ProcEntry->ModuleListHead));
    ProcEntry->pid = PID;
    InsertTailList(&ProcessListHead, &(ProcEntry->PList));
  }
  if(ProcEntry = LocatePIDEntry(&ProcessListHead, PID)){
    DbgPrint("%wZ loaded in %i\n @ 0x%X", FullImgName, PID,
	     ImageInfo->ImageBase);
    if((ModuleEntry = AllocModuleEntry()) == NULL){
       DbgPrint("Couldn't allocate\n");
      return;
    }
    RtlUnicodeStringCopy(&(ModuleEntry->FullImgName), FullImgName);
    ModuleEntry->ImgBase = ImageInfo->ImageBase;
    InsertTailList(&(ProcEntry->ModuleListHead), &(ModuleEntry->MList));
  }
  return;
}
void ProcessNotify(HANDLE PPID, HANDLE PID, BOOLEAN Create){
  PROC_ENTRY *ProcEntry;
  if(!Create && (ProcEntry = LocatePIDEntry(&ProcessListHead, PID))){
    DbgPrint("died subj %i", PID);
    RemoveProcessEntry(ProcEntry);
  }
  return;
}
NTSTATUS Read(PDEVICE_OBJECT  DriverObject, PIRP Irp){
  int  size;
  PIO_STACK_LOCATION pIoStackIrp = NULL;
  PCHAR pBuffer;
  NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

  /*
  DbgPrint("Read Called \r\n");
  Irp->IoStatus.Information = Irp->IoStatus.Information = 0;
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  if(pIoStackIrp){
    size = pIoStackIrp->Parameters.Read.Length;
    pBuffer =
      MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    DbgPrint("User buffer @ virt addr %p\n", pBuffer);
    if( pBuffer && vaddr && SCVAddr){
      DbgPrint("Moving %i bytes from %p to %p\n", size, SCVAddr, pBuffer);
      READ_REGISTER_BUFFER_UCHAR(SCVAddr, pBuffer, size);
      DbgPrint("Moving finished\n");
      Irp->IoStatus.Information = size;
    }
    else DbgPrint("vaddr or PBuffer = NULL\r\n");
  }
  else DbgPrint("can't get stack location\r\n");
  Irp->IoStatus.Status = NtStatus;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  */
  return NtStatus;
}

NTSTATUS HandleIOCTL(PDEVICE_OBJECT  DriverObject, PIRP Irp){
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  int nsec, i, PESIGN = 0x00004550;
  union {
    DWORD highlow;
    struct {
      WORD low;
      WORD high;
    } split;  
  } delta;
  struct {
    DWORD PageRVA;
    DWORD  BlockSize;
  } *RelocBlockHead;
  WORD *RelocBlock, offset, DOSMAGIC = 0x5A4D;
  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  PCHAR OutBuffer = NULL, FixedSection;
  HashReqData *hri;
  PEPROCESS proc;
  KAPC_STATE apc_state;
  PLIST_ENTRY ModuleLE, ProcessLE;
  DWORD RelocSectionRVA, RelocSectionSize, VarSectionSize;
  char Type;
  PIMAGE_DOS_HEADER dosh;
  PIMAGE_NT_HEADERS32 nth32;
  PIMAGE_NT_HEADERS64 nth64;

  PIMAGE_SECTION_HEADER ish;
  SHA1Context sha;
  
  PROC_ENTRY *ProcEntry;
  MODULE_ENTRY *ModuleEntry;

  DbgPrint("IOCTL handler called\r\n");
  switch (pIoStackIrp->
	  Parameters.DeviceIoControl.IoControlCode){
  case IOCTL_SENTINEL_PPID:
    if( pIoStackIrp->
	Parameters.DeviceIoControl.InputBufferLength
	&& Irp->AssociatedIrp.SystemBuffer){
      
    }
    break;
  case IOCTL_SENTINEL_HASH:
    DbgPrint("IOCTL_SENTINEL_HASH received\n");
    if(Irp->MdlAddress)
      OutBuffer =
	MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if( /*(pIoStackIrp->
	 Parameters.DeviceIoControl.InputBufferLength == sizeof(HashReqData))
	//supplied big enough
	&&*/ Irp->AssociatedIrp.SystemBuffer //input buffer
	&& (pIoStackIrp->
	    Parameters.DeviceIoControl.OutputBufferLength >= 4*sizeof(int))
	// supplied big enough
	&& OutBuffer){ //outbuffer
      //attach, read, hash
      hri = Irp->AssociatedIrp.SystemBuffer;

      if(IsListEmpty(&ProcessListHead)){
	DbgPrint("Empty Proc List\n");
	break;
      }
      for(ProcessLE = ProcessListHead.Flink; 
	  ProcessLE != &(ProcessListHead); ProcessLE = ProcessLE->Flink){
	ProcEntry = CONTAINING_RECORD(ProcessLE, PROC_ENTRY, PList);
	DbgPrint("In Process List: %i", ProcEntry->pid);
	if(IsListEmpty(&ProcEntry->ModuleListHead)){
	  DbgPrint("Empty mod List\n");
	  break;
	}
	DbgPrint("attaching to pid %i\n", ProcEntry->pid);
	if(NT_SUCCESS(PsLookupProcessByProcessId(ProcEntry->pid, &proc))){
	  KeStackAttachProcess(proc, &apc_state);
	  for(ModuleLE = ProcEntry->ModuleListHead.Flink; 
	      ModuleLE != &(ProcEntry->ModuleListHead); ModuleLE = ModuleLE->Flink){
	    ModuleEntry = CONTAINING_RECORD(ModuleLE, MODULE_ENTRY, MList);
	    DbgPrint("%wZ @ %p\n", &(ModuleEntry->FullImgName), ModuleEntry->ImgBase);
	    dosh = ModuleEntry->ImgBase;
   	    __try{
	      if(!dosh && (dosh->e_magic != DOSMAGIC)){
		DbgPrint("DOS magic not valid\n");
		continue;
	      }
	      nth32 = nth64 = (char *)dosh + dosh->e_lfanew;
	      if(nth32->Signature != PESIGN){
		DbgPrint("PE signature not valid\n");
		continue;
	      }
	    }__except(EXCEPTION_EXECUTE_HANDLER){
	      DbgPrint("!EXCEPTION! Module probably unloaded\n");
	      continue;
	    }
	    if(nth32->FileHeader.Machine == 0x8664){
	      nsec = nth64->FileHeader.NumberOfSections;
	      ish = (char *) &(nth64->OptionalHeader) 
		+ nth64->FileHeader.SizeOfOptionalHeader;
	      delta.highlow = (char *) nth64->OptionalHeader.ImageBase - ModuleEntry->ImgBase;
	      RelocSectionRVA = nth64->OptionalHeader.DataDirectory[5].VirtualAddress;
	      RelocSectionSize = nth64->OptionalHeader.DataDirectory[5].Size;
	    }else if(nth32->FileHeader.Machine == 0x014c){
	      nsec = nth32->FileHeader.NumberOfSections;
	      ish = (char *) &(nth32->OptionalHeader) 
		+ nth32->FileHeader.SizeOfOptionalHeader;
	      delta.highlow = (char *) nth32->OptionalHeader.ImageBase - ModuleEntry->ImgBase;
	      RelocSectionRVA = nth32->OptionalHeader.DataDirectory[5].VirtualAddress;
	      RelocSectionSize = nth32->OptionalHeader.DataDirectory[5].Size;
	    }else DbgPrint("Probably itanium :-)\n");
	    for( i = 0; i < nsec; i++){
	      if(ish[i].Characteristics & IMAGE_SCN_CNT_CODE){
		FixedSection = ExAllocatePoolWithTag(PagedPool, ish[i].Misc.VirtualSize, TAG);
		RtlCopyMemory(FixedSection, 
			      ish[i].VirtualAddress + (char *)dosh, ish[i].Misc.VirtualSize);
		VarSectionSize = 0;
		while(VarSectionSize < RelocSectionSize){
		  VarBlockSize = 0;
		  RelocBlockHead = RelocSectionRVA + (char *)VarSectionSize + (char *)dosh;
		  RelocBlock = (char *)RelocBlockHead + sizeof(RelocBlockHead);
		  for(NBlock = 0; NBlock*sizeof(WORD) < RelocBlockHead->BlockSize;){
		    Type = offset = 0;
		    Type = (RelocBlock[NBlock] & 0xF000) >> 12;
		    offset = RelocBlock[NBlock] & 0xFFF;
		    
		  }
		  VarSectionSize += RelocBlockHead->BlockSize;
		}  
		DbgPrint("%p w/ sha1: ", ish[i].VirtualAddress + (char *)dosh);
		SHA1Reset(&sha);
		SHA1Input(&sha, 
			  (PUCHAR *) (ish[i].VirtualAddress + (char *)dosh), 
			  ish[i].Misc.VirtualSize);
		if(SHA1Result(&sha))
		  DbgPrint("%X%X%X%X%X", sha.Message_Digest[0],
			   sha.Message_Digest[1],
			   sha.Message_Digest[2],
			   sha.Message_Digest[3],
			   sha.Message_Digest[4]);
		      
		
	      }
	    }	   
	  }
	  KeUnstackDetachProcess(&apc_state);
	  ObDereferenceObject(proc);
	  status = STATUS_SUCCESS;
	}
      }
    }else DbgPrint("Argument mismatch");
    break;
  default:
    status = STATUS_INVALID_DEVICE_REQUEST;
    break;
  }
  /*
  && (pIoStackIrp->
      Parameters.DeviceIoControl.InputBufferLength == sizeof(PAYLOAD))
    && (Irp->AssociatedIrp.SystemBuffer) ){
       
    else status = STATUS_UNSUCCESSFUL;
}
  */  
  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return status;
}

NTSTATUS Create(PDEVICE_OBJECT  DriverObject, PIRP Irp){
  DbgPrint("Create called\r\n");
  return STATUS_SUCCESS; 
}

NTSTATUS Close(PDEVICE_OBJECT  DriverObject, PIRP Irp){
  DbgPrint("Close Called\r\n");
  return STATUS_SUCCESS;
}

NTSTATUS NotImplemented(PDEVICE_OBJECT  DriverObject, PIRP Irp){
  DbgPrint("NotImplemented called\r\n");
  return STATUS_SUCCESS; //STATUS_NOT_IMPLEMENTED?
}

void Dtor(PDRIVER_OBJECT  DriverObject){
  DbgPrint("Dtor Called \n");
  //ObUnRegisterCallbacks(&RegistrationHandle);
  //free process list stuff here?
  PsRemoveLoadImageNotifyRoutine(&LoadImageNotify);
  PsSetCreateProcessNotifyRoutine(&ProcessNotify, 1);
  IoDeleteSymbolicLink(&usDosDeviceName);
  IoDeleteDevice(DriverObject->DeviceObject);
  return STATUS_SUCCESS;
}
