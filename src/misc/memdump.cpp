/*
 *  Configurable memory dumps that can run even with the debugger disabled.
 */

#include "dosbox.h"
#include "memdump.h"

#include <fstream>
#include <iomanip>
#include <string>

#include "control.h"
#include "cpu.h"
#include "logging.h"
#include "mem.h"

enum MemdumpTrigger {
	MEMDUMP_TRIGGER_OFF,
	MEMDUMP_TRIGGER_ON_PM_ENTRY
};

struct MemdumpConfig {
	bool enabled;
	MemdumpTrigger trigger;
	std::string output_path;
	std::string descriptor_log_path;
	bool fired;
};

static MemdumpConfig g_memdump = { false, MEMDUMP_TRIGGER_OFF, "memdump.bin", "", false };

static void LogDescriptorTable(std::ofstream &stream, const char *name, DescriptorTable &table) {
	const Bit32u limit = table.GetLimit();
	const Bit32u entries = (limit + 1u) / 8u;

	stream << name << " base=0x" << std::setw(8) << table.GetBase() << " limit=0x" << std::setw(4)
	       << limit << " entries=" << entries << "\n";

	for (Bit32u idx = 0; idx < entries; ++idx) {
		const Bit32u selector = idx * 8u;
		Descriptor desc;
		if (!table.GetDescriptor(selector, desc)) continue;

		stream << "  [" << std::setw(4) << selector << "] base=0x" << std::setw(8) << desc.GetBase()
		       << " limit=0x" << std::setw(8) << desc.GetLimit() << " type=0x" << std::setw(2)
		       << desc.Type() << " dpl=" << desc.DPL() << " big=" << desc.Big() << "\n";
	}
}

static void WriteDescriptorLog(void) {
	if (g_memdump.descriptor_log_path.empty()) return;

	std::ofstream log(g_memdump.descriptor_log_path.c_str());
	if (!log.is_open()) {
		LOG_MSG("MEMDUMP: Failed to open descriptor log '%s'.", g_memdump.descriptor_log_path.c_str());
		return;
	}

	log << std::hex << std::uppercase << std::setfill('0');
	LogDescriptorTable(log, "GDT", cpu.gdt);
	LogDescriptorTable(log, "IDT", cpu.idt);
	LOG_MSG("MEMDUMP: Descriptor log written to '%s'.", g_memdump.descriptor_log_path.c_str());
}

static void WriteMemoryDump(void) {
	if (g_memdump.output_path.empty()) return;

	std::ofstream dump(g_memdump.output_path.c_str(), std::ios::binary);
	if (!dump.is_open()) {
		LOG_MSG("MEMDUMP: Failed to open output '%s'.", g_memdump.output_path.c_str());
		return;
	}

	const Bit32u total_pages = MEM_TotalPages();
	const size_t total_bytes = static_cast<size_t>(total_pages) * MEM_PAGESIZE;
	dump.write(reinterpret_cast<const char *>(MemBase), static_cast<std::streamsize>(total_bytes));

	if (!dump.good()) {
		LOG_MSG("MEMDUMP: Short write when dumping memory to '%s'.", g_memdump.output_path.c_str());
		return;
	}

	LOG_MSG("MEMDUMP: Wrote %lu bytes to '%s'.", static_cast<unsigned long>(total_bytes),
	        g_memdump.output_path.c_str());
}

static void TriggerMemdump(void) {
	if (!g_memdump.enabled || g_memdump.fired) return;

	g_memdump.fired = true;
	WriteMemoryDump();
	WriteDescriptorLog();
}

void MEMDUMP_Init(Section *sec) {
	Section_prop *section = static_cast<Section_prop *>(sec);

	g_memdump.enabled = section->Get_bool("enabled");

	const std::string trigger = section->Get_string("trigger");
	if (trigger == "on_pm_entry") g_memdump.trigger = MEMDUMP_TRIGGER_ON_PM_ENTRY;
	else g_memdump.trigger = MEMDUMP_TRIGGER_OFF;

	g_memdump.output_path = section->Get_path("output");
	g_memdump.descriptor_log_path = section->Get_path("descriptor_log");
	g_memdump.fired = false;
}

void MEMDUMP_OnProtectedModeEntry(void) {
	if (g_memdump.trigger != MEMDUMP_TRIGGER_ON_PM_ENTRY) return;
	TriggerMemdump();
}
