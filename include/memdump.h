/*
 *  Configurable memory dump helpers.
 */

#ifndef DOSBOX_MEMDUMP_H
#define DOSBOX_MEMDUMP_H

class Section;

void MEMDUMP_Init(Section* sec);
void MEMDUMP_OnProtectedModeEntry(void);

#endif /* DOSBOX_MEMDUMP_H */
