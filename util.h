#ifndef UTIL_H
#define UTIL_H
#include "sentinel.h"
int DoesEndWith(PUNICODE_STRING, PUNICODE_STRING);
PROC_ENTRY *LocatePIDEntry(PLIST_ENTRY, HANDLE);
void RemoveProcessEntry(PLIST_ENTRY);
#endif
