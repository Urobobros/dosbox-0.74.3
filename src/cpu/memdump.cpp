#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <string>

#include "cpu.h"
#include "logging.h"
#include "mem.h"
#include "memdump.h"
#include "paging.h"
#include "regs.h"
#include "support.h"

namespace {

bool g_enabled = false;
MemDumpTrigger g_trigger = MemDumpTrigger::MEMDUMP_TRIGGER_ON_PM_ENTRY;
std::string g_trigger_name = "on_pm_entry";
std::string g_output_path = "spellcross_memdump.bin";
std::string g_descriptor_path = "spellcross_descriptors.txt";
bool g_dumped = false;

constexpr size_t kChunkSize = 1 << 20; // 1 MiB chunks to avoid long blocking writes

void WriteGdtEntry(std::ofstream &out, const char *label, Bitu selector,
                   Descriptor &desc) {
	out << std::hex << std::setw(4) << std::setfill('0') << selector << "  "
	    << "base=0x" << std::setw(8) << desc.GetBase() << "  "
	    << "limit=0x" << std::setw(8) << desc.GetLimit() << "  "
	    << "type=0x" << std::setw(2) << desc.Type() << "  "
	    << "dpl=" << std::dec << desc.DPL() << "  "
	    << "big=" << desc.Big() << "  "
	    << "g=" << desc.saved.seg.g << "  "
	    << label << "\n";
}

void WriteIdtEntry(std::ofstream &out, Bitu selector, Descriptor &desc) {
	out << std::hex << std::setw(4) << std::setfill('0') << selector << "  "
	    << "offset=0x" << std::setw(8) << desc.GetOffset() << "  "
	    << "selector=0x" << std::setw(4) << desc.GetSelector() << "  "
	    << "type=0x" << std::setw(2) << desc.Type() << "  "
	    << "dpl=" << std::dec << desc.DPL() << "\n";
}

void DumpDescriptorTable(std::ofstream &out, const char *name, Bitu base,
                         Bitu limit, bool is_gdt) {
	out << name << ": base=0x" << std::hex << base << " limit=0x" << limit
	    << std::dec << "\n";
	if (!limit)
		return;

	const Bitu entry_bytes = sizeof(G_Descriptor);
	const Bitu entry_count = (limit + 1) / entry_bytes;
	for (Bitu i = 0; i < entry_count; ++i) {
		const Bitu selector = i * entry_bytes;
		Descriptor desc;
		const bool ok =
		        is_gdt ? cpu.gdt.GetDescriptor(selector, desc)
		               : cpu.idt.GetDescriptor(selector, desc);
		if (!ok)
			continue;
		if (is_gdt) {
			WriteGdtEntry(out, "gdt", selector, desc);
		} else {
			WriteIdtEntry(out, selector, desc);
		}
	}
}

void DumpCurrentSegments(std::ofstream &out) {
	const struct {
		const char *name;
		Bitu selector;
	} segments[] = {{"CS", SegValue(cs)}, {"DS", SegValue(ds)},
	                {"ES", SegValue(es)}, {"FS", SegValue(fs)},
	                {"GS", SegValue(gs)}, {"SS", SegValue(ss)}};

	for (const auto &seg : segments) {
		Descriptor desc;
		if (!cpu.gdt.GetDescriptor(seg.selector, desc))
			continue;
		WriteGdtEntry(out, seg.name, seg.selector, desc);
	}
}

void WriteDescriptorSnapshot(const std::string &trigger_name) {
	std::ofstream out(g_descriptor_path.c_str());
	if (!out) {
		LOG_MSG("MEMDUMP: unable to open descriptor log %s",
		        g_descriptor_path.c_str());
		return;
	}

	const size_t total_bytes =
	        static_cast<size_t>(MEM_TotalPages()) * MEM_PAGESIZE;
	out << "Memdump trigger: " << trigger_name << "\n";
	out << "Dump size (bytes): " << std::dec << total_bytes << "\n";
	out << "Paging enabled: " << (PAGING_Enabled() ? "yes" : "no") << "\n";
	if (PAGING_Enabled())
		out << "CR3: 0x" << std::hex << PAGING_GetDirBase() << std::dec << "\n";

	const Bitu ldt_selector = cpu.gdt.SLDT();
	out << "LDT selector: 0x" << std::hex << ldt_selector << std::dec << "\n";
	if (ldt_selector) {
		Descriptor ldt_desc;
		if (cpu.gdt.GetDescriptor(ldt_selector, ldt_desc))
			WriteGdtEntry(out, "ldt", ldt_selector, ldt_desc);
	}

	DumpCurrentSegments(out);
	DumpDescriptorTable(out, "GDT", CPU_SGDT_base(), CPU_SGDT_limit(), true);
	DumpDescriptorTable(out, "IDT", CPU_SIDT_base(), CPU_SIDT_limit(), false);
	out.flush();
}

bool DumpLinearMemory(const std::string &trigger_name) {
	const size_t total_bytes =
	        static_cast<size_t>(MEM_TotalPages()) * MEM_PAGESIZE;
	const Bit8u *base = GetMemBase();
	const unsigned long total_bytes_log =
	        static_cast<unsigned long>(total_bytes);

	FILE *fp = fopen(g_output_path.c_str(), "wb");
	if (!fp) {
		LOG_MSG("MEMDUMP: failed to open %s for writing", g_output_path.c_str());
		return false;
	}

	size_t written = 0;
	while (written < total_bytes) {
		const size_t to_write =
		        std::min(kChunkSize, static_cast<size_t>(total_bytes - written));
		const size_t count =
		        fwrite(base + written, sizeof(Bit8u), to_write, fp);
		if (count != to_write) {
			LOG_MSG("MEMDUMP: short write after %lu bytes",
			        static_cast<unsigned long>(written));
			fclose(fp);
			return false;
		}
		written += count;
	}
	fclose(fp);
	LOG_MSG("MEMDUMP: wrote %lu bytes to %s (trigger=%s)", total_bytes_log,
	        g_output_path.c_str(), trigger_name.c_str());
	return true;
}

void PerformMemDump(const std::string &trigger_name) {
	if (g_dumped) {
		LOG_MSG("MEMDUMP: skipping dump for trigger=%s (already dumped)",
		        trigger_name.c_str());
		return;
	}
	if (!g_enabled) {
		LOG_MSG("MEMDUMP: skipping dump for trigger=%s (memdump disabled)",
		        trigger_name.c_str());
		return;
	}

	if (!DumpLinearMemory(trigger_name))
		return;

	WriteDescriptorSnapshot(trigger_name);
	g_dumped = true;
}

MemDumpTrigger ParseTrigger(const char *value) {
	if (value == nullptr)
		return MemDumpTrigger::MEMDUMP_TRIGGER_NONE;
	if (!strcasecmp(value, "on_pm_entry"))
		return MemDumpTrigger::MEMDUMP_TRIGGER_ON_PM_ENTRY;
	return MemDumpTrigger::MEMDUMP_TRIGGER_NONE;
}

} // namespace

void MEMDUMP_Init(Section *sec) {
	auto *section = static_cast<Section_prop *>(sec);
	g_enabled = section->Get_bool("enabled");
	g_trigger_name = section->Get_string("trigger");
	g_trigger = ParseTrigger(g_trigger_name.c_str());
	g_output_path = section->Get_string("output");
	g_descriptor_path = section->Get_string("descriptor_log");

	if (g_enabled && g_trigger == MemDumpTrigger::MEMDUMP_TRIGGER_NONE) {
		LOG_MSG("MEMDUMP: unknown trigger \"%s\"; disabling memdump.",
		        g_trigger_name.c_str());
		g_enabled = false;
	} else if (g_enabled) {
		LOG_MSG("MEMDUMP: enabled with trigger=%s, output=%s, descriptor_log=%s",
		        g_trigger_name.c_str(), g_output_path.c_str(),
		        g_descriptor_path.c_str());
	}
}

void MEMDUMP_OnProtectedModeEntry(void) {
	if (g_trigger != MemDumpTrigger::MEMDUMP_TRIGGER_ON_PM_ENTRY)
		return;
	LOG_MSG("MEMDUMP: protected mode entry detected (trigger=%s, enabled=%s)",
	        g_trigger_name.c_str(), g_enabled ? "yes" : "no");
	PerformMemDump(g_trigger_name);
}

bool MEMDUMP_IsEnabled(void) {
	return g_enabled;
}

std::string MEMDUMP_CurrentTriggerName(void) {
	return g_trigger_name;
}
