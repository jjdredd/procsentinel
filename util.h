#ifndef UTIL_H
#define UTIL_H
#include "sentinel.h"
#include <Ntstrsafe.h>
int DoesEndWith(PUNICODE_STRING, PUNICODE_STRING);
PROC_ENTRY *LocatePIDEntry(PLIST_ENTRY, HANDLE);
void RemoveProcessEntry(PROC_ENTRY*);
void RemoveModuleEntry(MODULE_ENTRY*);
MODULE_ENTRY *AllocModuleEntry(void);
#endif
