#ifndef DOSBOX_MEMDUMP_H
#define DOSBOX_MEMDUMP_H

#include <string>
#include "dosbox.h"
#include "setup.h"

enum class MemDumpTrigger {
	MEMDUMP_TRIGGER_NONE = 0,
	MEMDUMP_TRIGGER_ON_PM_ENTRY
};

void MEMDUMP_Init(Section *sec);
void MEMDUMP_OnProtectedModeEntry(void);
bool MEMDUMP_IsEnabled(void);
std::string MEMDUMP_CurrentTriggerName(void);

#endif
