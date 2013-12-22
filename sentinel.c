#include <Fltkernel.h>
#include <Bcrypt.h>
#include <windef.h>

/* workaround for an undefined type of an unsupported variable */
typedef PVOID* PPS_POST_PROCESS_INIT_ROUTINE; 

// the following structures are from msdn
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
/*
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
*/
typedef struct _LDR_DATA_TABLE_ENTRY {
  PVOID Reserved1[2];
  LIST_ENTRY InMemoryOrderLinks;
  PVOID Reserved2[2];
  PVOID DllBase;
  PVOID EntryPoint;
  PVOID Reserved3;
  UNICODE_STRING FullDllName;
  BYTE Reserved4[8];
  PVOID Reserved5[3];
  union {
    ULONG CheckSum;
    PVOID Reserved6;
  };
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
/*
typedef struct _LSA_UNICODE_STRING32 {
  USHORT Length;
  USHORT MaximumLength;
  DWORD  Buffer;
} LSA_UNICODE_STRING32, *PLSA_UNICODE_STRING32, UNICODE_STRING32, *PUNICODE_STRING32;
typedef struct _LIST_ENTRY32 {
  DWORD Flink;
  DWORD Blink;
} LIST_ENTRY32, *PLIST_ENTRY32;
*/
typedef struct _LDR_DATA_TABLE_ENTRY32 {
  DWORD Reserved1[2];
  LIST_ENTRY32 InMemoryOrderLinks;
  DWORD Reserved2[2];
  DWORD DllBase;
  DWORD EntryPoint;
  DWORD Reserved3;
  UNICODE_STRING32 FullDllName;
  BYTE Reserved4[8];
  DWORD Reserved5[3];
  union {
    DWORD CheckSum;
    DWORD Reserved6;
  };
  DWORD TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
typedef struct _PEB_LDR_DATA32 {
  BYTE       Reserved1[8];
  DWORD      Reserved2[3];
  LIST_ENTRY32 InMemoryOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
/* for 32 bit windows */
typedef struct _PEB32 {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  DWORD                         Reserved3[2];
  DWORD                 Ldr;
  DWORD  ProcessParameters;
  BYTE                          Reserved4[104];
  DWORD                         Reserved5[52];
  DWORD PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  DWORD                         Reserved7[1];
  DWORD                         SessionId;
} PEB32, *PPEB32;
/* for 64 bit windows */
typedef struct _PEB64 {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[21];
  PPEB_LDR_DATA LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  BYTE Reserved3[520];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE Reserved4[136];
  ULONG SessionId;
} PEB64, *PPEB64;
// this is from some forum 
PPEB PsGetProcessPeb(PEPROCESS Process);
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
#define IMAGE_SIZEOF_SHORT_NAME              8
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.


#define IOCTL_SENTINEL_PPID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SENTINEL_HASH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

int RegistrationHandle;
//int CBCKRegistered;
int *pidlist = NULL;

typedef struct{
  int pid; // long???
  PVOID start;
  int size;
}  HashReqData;

NTSTATUS Read(PDEVICE_OBJECT, PIRP);
NTSTATUS Create(PDEVICE_OBJECT, PIRP);
NTSTATUS Close(PDEVICE_OBJECT, PIRP);
NTSTATUS HandleIOCTL(PDEVICE_OBJECT, PIRP);
NTSTATUS NotImplemented(PDEVICE_OBJECT, PIRP);
void Dtor(PDRIVER_OBJECT );
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID, POB_PRE_OPERATION_INFORMATION);
void PostCallback(PVOID, POB_POST_OPERATION_INFORMATION);
NTSTATUS SHA1(PVOID data, int size, int *hash){
  BCRYPT_ALG_HANDLE halg;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath){
  NTSTATUS NtStatus = STATUS_SUCCESS;
  PDEVICE_OBJECT pDeviceObject = NULL;
  UNICODE_STRING usDriverName, usDosDeviceName, Altitude;
  int i;
  OB_CALLBACK_REGISTRATION CallbackRegistration;
  OB_OPERATION_REGISTRATION OperationRegistration;
  

  RtlInitUnicodeString(&usDriverName, L"\\Device\\Sentinel");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Sentinel");
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
  
  RtlZeroMemory(&CallbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
  RtlZeroMemory(&OperationRegistration, sizeof(OB_OPERATION_REGISTRATION));
  RtlInitUnicodeString(&Altitude, L"idkwat2puthere");  //adjust later
  OperationRegistration.ObjectType = PsProcessType;
  OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE; 
  // | _DUPLICATE ?
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
  int nsec, i;
  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  PCHAR OutBuffer = NULL;
  HashReqData *hri;
  PEPROCESS proc;
  KAPC_STATE apc_state;
  BCRYPT_HASH_HANDLE hHash;
  PLIST_ENTRY Module, HeadModule;
  PLDR_DATA_TABLE_ENTRY dte;
  PEB64 *peb64;
  PEB32 *peb32;
  DWORD PTR32;
  UNICODE_STRING DllName;
  PIMAGE_DOS_HEADER dosh;
  PIMAGE_NT_HEADERS32 nth32;
  PIMAGE_NT_HEADERS64 nth64;
  PIMAGE_SECTION_HEADER ish;

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
      DbgPrint("attaching to pid %i\n", hri->pid);
      if(NT_SUCCESS(PsLookupProcessByProcessId(hri->pid, &proc))){
	KeStackAttachProcess(proc, &apc_state);
	peb64 = PsGetProcessPeb(proc);
	peb32 = (char *)peb64 - 0x1000;
	HeadModule = &(peb64->LoaderData->InMemoryOrderModuleList);
	for( Module = HeadModule->Flink;
	     Module != HeadModule; Module = Module->Flink){
	  dte = (PVOID *)Module - 2;
	  DbgPrint("%wZ @ %p\n", &(dte->FullDllName), dte->DllBase);
	  dosh = dte->DllBase;
	  nth64 = (char *)dosh + dosh->e_lfanew;
	  nsec = nth64->FileHeader.NumberOfSections;
	  ish = (char *) &(nth64->OptionalHeader) 
	    + nth64->FileHeader.SizeOfOptionalHeader;
	  for( i = 0; i < nsec; i++){
	    DbgPrint("%p\n", ish[i].VirtualAddress + (char *)dosh);
	    //ish[i].Misc.VirtualSize
	  }
	}
	PTR32 = peb32->Ldr;
	HeadModule = &(((PPEB_LDR_DATA32)PTR32)->InMemoryOrderModuleList);
	for( PTR32 = HeadModule->Flink;
	     PTR32 != HeadModule; PTR32 = ((PLIST_ENTRY32)PTR32)->Flink){
	  dte = (DWORD *)PTR32 - 2;
	  DllName.Length = ((PLDR_DATA_TABLE_ENTRY32)dte)->FullDllName.Length;
	  DllName.MaximumLength = ((PLDR_DATA_TABLE_ENTRY32)dte)->
	    FullDllName.MaximumLength;
	  DllName.Buffer = (PWSTR)((PLDR_DATA_TABLE_ENTRY32)dte)->
	    FullDllName.Buffer;
	  DbgPrint("%wZ @ 0x%X\n", &DllName, 
		   ((PLDR_DATA_TABLE_ENTRY32)dte)->DllBase);
	  dosh = (DWORD)(((PLDR_DATA_TABLE_ENTRY32)dte)->DllBase);
	  nth32 = (char *)dosh + dosh->e_lfanew;
	  nsec = nth32->FileHeader.NumberOfSections;
	  ish = (char *) &(nth32->OptionalHeader) 
	    + nth32->FileHeader.SizeOfOptionalHeader;
	  for( i = 0; i < nsec; i++){
	    DbgPrint("%p\n", ish[i].VirtualAddress + (char *)dosh);
	  }
	}
      
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(proc);
	status = STATUS_SUCCESS;
      }
    }
    else DbgPrint("Argument mismatch");
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
  UNICODE_STRING usDosDeviceName;
  DbgPrint("Dtor Called \n");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Sentinel");
  //ObUnRegisterCallbacks(&RegistrationHandle);
  IoDeleteSymbolicLink(&usDosDeviceName);
  IoDeleteDevice(DriverObject->DeviceObject);
  return STATUS_SUCCESS;
}
