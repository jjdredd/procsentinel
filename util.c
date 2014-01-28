#include "util.h"

int DoesEndWith(PUNICODE_STRING hay, PUNICODE_STRING needle){
  int i, ldif;
  PWSTR haySTR = hay->Buffer, needleSTR = needle->Buffer;
  if( (ldif = hay->Length - needle->Length) < 0)
    return 0;
  if(RtlCompareMemory((char *)haySTR + ldif, needleSTR, needle->Length)
     == needle->Length)
    return 1;
  return 0;    
}
PROC_ENTRY *LocatePIDEntry(PLIST_ENTRY lst, HANDLE pid){
  PLIST_ENTRY li;
  PROC_ENTRY *Pentry;
  for(li = lst->Flink; li != lst; li = li->Flink){
    Pentry = CONTAINING_RECORD(li, PROC_ENTRY, PList);
    if(Pentry->pid == pid)
      return Pentry;
  }
  return NULL;
}
void RemoveModuleEntry(MODULE_ENTRY *Mentry){
  RemoveEntryList(&(Mentry->MList));
  ExFreePoolWithTag(Mentry->FullImgName.Buffer, TAG);
  ExFreePoolWithTag(Mentry, TAG);
  return;
}
void RemoveProcessEntry(PROC_ENTRY *Pentry){
  PLIST_ENTRY li, nli;
  for( li = Pentry->ModuleListHead.Flink; 
       li != &(Pentry->ModuleListHead); li = nli){
    nli = li->Flink;
    RemoveModuleEntry(CONTAINING_RECORD(li, MODULE_ENTRY, MList));
  }
  RemoveEntryList(&(Pentry->PList));
  ExFreePoolWithTag(Pentry, TAG);
  return;
}
MODULE_ENTRY *AllocModuleEntry(void){
  MODULE_ENTRY *ret;
  if(!(ret = ExAllocatePoolWithTag(PagedPool, sizeof(MODULE_ENTRY), TAG)))
    return ret;
  ret->FullImgName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH*sizeof(WCHAR);
  ret->FullImgName.Buffer 
    = ExAllocatePoolWithTag(PagedPool, NTSTRSAFE_UNICODE_STRING_MAX_CCH*sizeof(WCHAR), TAG);
  return ret;
}

