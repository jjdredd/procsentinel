//#include <ntddk.h>
//#include <Wdm.h>
#include <Fltkernel.h>
#include <Bcrypt.h>

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
  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  PCHAR OutBuffer = NULL;
  HashReqData *hri;
  PEPROCESS proc;
  KAPC_STATE apc_state;
  BCRYPT_HASH_HANDLE hHash;

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
	    Parameters.DeviceIoControl.OutputBufferLength >= 5*sizeof(int))
	// supplied big enough
	&& OutBuffer){ //outbuffer
      //attach, read, hash
      hri = Irp->AssociatedIrp.SystemBuffer;
      DbgPrint("attaching to pid %i\n", hri->pid);
      if(NT_SUCCESS(PsLookupProcessByProcessId(hri->pid, &proc))){
	KeStackAttachProcess(proc, &apc_state);
	BCryptCreateHash(hAlgo, &hHandle, );
	BCryptHashData(hHandle, hri->start, hri->size, 0);
	
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(proc);
	status = STATUS_SUCCESS;
      }
    }
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
