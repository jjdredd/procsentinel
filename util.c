#include "util.h"

DoesEndWith(PUNICODE_STRING hay, PUNICODE_STRING needle){
  int i, ldif;
  PWSTR haySTR = hay->Buffer, needleSTR = needle->Buffer;
  if( (ldif = hay->Length - needle->Length) < 0)
    return 0;
  if(RtlCompareMemory((char *)haySTR + ldif, needleSTR, needle->Length)
     == needle->Length)
    return 1;
  return 0;    
}
LocatePIDEntry(PLIST_ENTRY lst, HANDLE pid){
  PLIST_ENTRY li;
  PROC_ENTRY *Pentry;
  for(li = lst->Flink; li != lst; li = li -> Flink){
    Pentry = CONTAINING_RECORD(li, PROC_ENTRY, PList);
    if(Pentry->pid == pid)
      return Pentry;
  }
  return NULL;
}
RemoveProcessEntry(PLIST_ENTRY lst){
  PROC_ENTRY *Pentry;
  PLIST_ENTRY li;
  MODULE_ENTRY *Mentry;
  Pentry = CONTAINING_RECORD(lst, PROC_ENTRY, PList);
  for( li = Pentry->ModuleListHead->Flink; 
       li != Pentry->ModuleListHead; li = li->Flink){
    Mentry = CONTAINING_RECORD(li, MODULE_ENTRY, MList);
    RemoveHeadList();
  }
}
