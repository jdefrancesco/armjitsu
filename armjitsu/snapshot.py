from construct import *
import os

# snapshot version 1 == ARMulator 1.0.7d


class Snapshot(object):
    def __init__(self, filename, ini_file=False):
        self.filename = filename
        self.is_ini = ini_file
        self.filedata = None
        self.snapshot_container = None
        self.timestamp = None

        # ini file vars
        self.ini_cpu_settings = {}
        self.ini_cpu_features = []
        self.ini_cpu_registers = {}
        self.ini_cpu_coprocessors = {}
        self.ini_mmu_settings = {}
        self.ini_memory_pages = []

        self._load()

    def _load(self):
        with open(self.filename, "rb") as f:
            self.filedata = f.read()

        if self.is_ini:
            self._load_ini_file()
        else:
            self._load_snapshot_file()

    def _load_ini_file(self):
        ini_data = self.filedata.splitlines()
        sections = {}
        current_section = ""

        for line in ini_data:
            if line.startswith("#") or line == "":
                # this is a comment line or an empty line, skip
                continue
            elif line.startswith("[") and line.endswith("]"):
                # line is a section
                current_section = line
                sections[current_section] = []
            else:
                # line is part of the section, add it
                sections[current_section].append(line)

        cpu_section_name = ""
        mmu_section_name = ""

        if "[VM]" not in sections:
            print "Error parsing ini file, no VM section defined"
            raise ValueError

        # get the CPU and MMU values
        for line in sections["[VM]"]:
            if line.lower().startswith("cpu="):
                cpu_section_name = "[{}]".format(line[4:])
            elif line.lower().startswith("mmu="):
                mmu_section_name = "[{}]".format(line[4:])

        # parse cpu section data
        if cpu_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(cpu_section_name)
            raise ValueError

        cpu_features_section_name = ""
        cpu_registers_section_name = ""
        cpu_coprocessors_section_name = ""

        for line in sections[cpu_section_name]:
            if line.lower().startswith("features="):
                cpu_features_section_name = "[{}]".format(line[9:])
            elif line.lower().startswith("registers="):
                cpu_registers_section_name = "[{}]".format(line[10:])
            elif line.lower().startswith("coprocessors="):
                cpu_coprocessors_section_name = "[{}]".format(line[13:])
            else:
                # store everything else
                name = line[:line.index("=")]
                value = line[line.index("=") + 1:]
                self.ini_cpu_settings[name] = value

        # parse cpu feature section
        if cpu_features_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(cpu_features_section_name)
            raise ValueError

        for line in sections[cpu_features_section_name]:
            self.ini_cpu_features.append(line)

        # parse cpu registers section
        if cpu_registers_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(cpu_registers_section_name)
            raise ValueError

        for line in sections[cpu_registers_section_name]:
            name = line[:line.index("=")].upper()
            value = line[line.index("=") + 1:]

            try:
                converted_value = int(value, 16)
            except ValueError as e:
                print "Error parsing ini file, invalid value for {} for section {}".format(name, cpu_registers_section_name)
                raise ValueError

            if name == "SP":
                self.ini_cpu_registers["R13"] = converted_value
            elif name == "LR":
                self.ini_cpu_registers["R14"] = converted_value
            elif name == "PC":
                self.ini_cpu_registers["R15"] = converted_value
            else:
                self.ini_cpu_registers[name] = converted_value

        # parse cpu coprocessors section
        if cpu_coprocessors_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(cpu_coprocessors_section_name)
            raise ValueError

        cpu_coprocessors_sections = []

        for line in sections[cpu_coprocessors_section_name]:
            cpu_coprocessors_sections.append("[{}]".format(line))

        # parse cpu coprocessor section sections
        coprocessor_count = 0
        for coprocessor_section in cpu_coprocessors_sections:
            if coprocessor_section not in sections:
                print "Error parsing ini file, no {} section defined".format(coprocessor_section)
                raise ValueError

            self.ini_cpu_coprocessors[coprocessor_count] = {}

            for line in sections[coprocessor_section]:
                name = line[:line.index("=")]
                value = line[line.index("=") + 1:]
                self.ini_cpu_coprocessors[coprocessor_count][name] = value

        # parse mmu section data
        if mmu_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(mmu_section_name)
            raise ValueError

        mmu_memory_sections_section_name = ""

        for line in sections[mmu_section_name]:
            if line.lower().startswith("memorysections="):
                mmu_memory_sections_section_name = "[{}]".format(line[15:])
            else:
                # store everything else
                name = line[:line.index("=")]
                value = line[line.index("=") + 1:]
                self.ini_mmu_settings[name] = value

        # parse memory sections list
        if mmu_memory_sections_section_name not in sections:
            print "Error parsing ini file, no {} section defined".format(mmu_memory_sections_section_name)
            raise ValueError

        page_list_section_names = []
        for line in sections[mmu_memory_sections_section_name]:
            page_list_section_names.append("[{}]".format(line))

        # parse memory sections and read in memory files
        for mem_page_section in page_list_section_names:
            if mem_page_section not in sections:
                print "Error parsing ini file, no {} section defined".format(mem_page_section)
                raise ValueError

            mem_file = None
            file_type = None
            protection = None
            base_address = None

            for line in sections[mem_page_section]:
                if line.lower().startswith("file="):
                    mem_file = line[line.index("=") + 1:]
                elif line.lower().startswith("type="):
                    file_type = line[line.index("=") + 1:]
                elif line.lower().startswith("protection="):
                    protection = line[line.index("=") + 1:]
                elif line.lower().startswith("baseaddress="):
                    base_address = line[line.index("=") + 1:]

            if file_type.lower() != "binary":
                print "Error parsing ini file, unsupported type '{}' for section '{}'".format(file_type, mem_page_section)
                raise ValueError

            try:
                converted_base_addr = int(base_address, 16)
            except ValueError as e:
                print "Error parsing ini file, invalid value for BASEADDRESS for section {}".format(mem_page_section)
                raise ValueError

            # read in data
            if not os.path.isabs(mem_file):
                ini_file_dir = os.path.dirname(self.filename)
                memory_file = os.path.join(ini_file_dir, mem_file)
            else:
                memory_file = mem_file

            try:
                with open(memory_file, "rb") as f:
                    file_data = f.read()
            except IOError as e:
                print "Error parsing ini file, unable to open '{}' for section {}".format(memory_file, mem_page_section)
                raise ValueError

            #ARMBASICMMU_READ_FLAG	( 1 <<0)
            # define ARMBASICMMU_WRITE_FLAG		(1<<1)
            # define ARMBASICMMU_EXEC_FLAG		(1<<2)

            # get page protection
            if len(protection) < 3 or (protection[0].lower() != "r" and protection[0].lower() != "-") \
                    or (protection[1].lower() != "w" and protection[1].lower() != "-") \
                    or (protection[2].lower() != "x" and protection[2].lower() != "-"):
                print "Error parsing ini file, invalid value for PROTECTION for section {}".format(mem_page_section)
                raise ValueError

            prot = 0
            if protection[0].lower() == "r":
                prot |= (1 << 0)

            if protection[1].lower() == "w":
                prot |= (1 << 1)

            if protection[2].lower() == "x":
                prot |= (1 << 2)

            # dict keys: "loadPageIdx", "loadProtectionFlags", "memoryPage"
            self.ini_memory_pages.append({"baseAddress": converted_base_addr, "loadProtectionFlags": prot,
                                          "memoryPage": file_data})

    def _load_snapshot_file(self):
        # Timestamp.cpp TimestampPacked_t
        timestamp = Struct(
            "year" / Int16ul,
            "month" / Int8ul,
            "day" / Int8ul,
            "hours" / Int8ul,
            "minutes" / Int8ul,
            "seconds" / Int8ul,
            Padding(1),
        )

        # VMSnapshot.cpp LoadBase()
        base = Struct(
            "curTime" / timestamp,
            "versionCheck" / Int32ul,
        )

        # ARMBasicMMU.cpp LoadState()
        # ARMBASICMMU_PAGESIZE (1<<12)
        pages = Struct(
            "loadPageIdx" / Int32ul,
            "loadProtectionFlags" / Int8ul,
            "memoryPage" / Bytes(1 << 12),
        )

        # ARMBasicMMU.cpp LoadState()
        arm_basic_mmu_state = Struct(
            "mmuTypeStringLen" / Int32ul,
            "mmuTypeString" / String(this.mmuTypeStringLen),
            "storedPageCnt" / Int32ul,
            "pages" / Array(this.storedPageCnt, pages),
        )

        # VM.cpp LoadState()
        mmu = Struct(
            "mmuTypeNameSize" / Int32ul,
            "mmuName" / String(this.mmuTypeNameSize),
            "ARMBasicMMU" / arm_basic_mmu_state,
        )

        # ARMCPU.h eARMREGINDEX
        arm_gp_registers = Struct(
            "R0" / Int32ul,
            "R1" / Int32ul,
            "R2" / Int32ul,
            "R3" / Int32ul,
            "R4" / Int32ul,
            "R5" / Int32ul,
            "R6" / Int32ul,
            "R7" / Int32ul,
            "R8" / Int32ul,
            "R9" / Int32ul,
            "R10" / Int32ul,
            "R11" / Int32ul,
            "R12" / Int32ul,
            "R13" / Int32ul,
            "R14" / Int32ul,
            "R15" / Int32ul,
            "R13_SVC" / Int32ul,
            "R14_SVC" / Int32ul,
            "R13_ABT" / Int32ul,
            "R14_ABT" / Int32ul,
            "R13_UND" / Int32ul,
            "R14_UND" / Int32ul,
            "R13_IRQ" / Int32ul,
            "R14_IRQ" / Int32ul,
            "R8_FIQ" / Int32ul,
            "R9_FIQ" / Int32ul,
            "R10_FIQ" / Int32ul,
            "R11_FIQ" / Int32ul,
            "R12_FIQ" / Int32ul,
            "R13_FIQ" / Int32ul,
            "R14_FIQ" / Int32ul,
            "CPSR" / Int32ul,
            "SPSR_SVC" / Int32ul,
            "SPSR_ABT" / Int32ul,
            "SPSR_UND" / Int32ul,
            "SPSR_IRQ" / Int32ul,
            "SPSR_FIQ" / Int32ul,
        )

        # ARMCPUSettings.h
        arm_cpu_settings = Struct(
            Enum("cpuArchitecture" / Int32ul,
                 ARCHV4=0,
                 ARCHV5=1,
                 ARCHV6=2,
                 ARCHV7=3,
            ),
            Enum("cpuEndianness" / Int32ul,
                 ENDIAN_BIG=0,
                 ENDIAN_LITTLE=1
            ),
            Enum("cpuPrefetchSettings" / Int32ul,
                 PREFETCH_OFF=0,
                 PREFETCH_ON=1
            ),
            Enum("cpuExceptionVectorSettings" / Int32ul,
                 EXCEPTIONVECTORS_LOW=0,
                 EXCEPTIONVECTORS_HIGH=1
            ),
            "cpuFeatures" / Int32ul,
            "cpuSpeedHz" / Int64ul,
        )

        # ARMSystemControlProcessor.cpp LoadState()
        arm_system_control_coprocessor = Struct(
            "versionCheck" / Int32ul,
            "c0_cpuid" / Int32ul,
            "c0_cachetype" / Int32ul,
            "c0_ccsid" / Array(16, Int32ul),
            "c0_clid" / Int32ul,
            "c0_cssel" / Int32ul,
            "c0_c1" / Array(8, Int32ul),
            "c0_c2" / Array(8, Int32ul),
            "c1_sys" / Int32ul,
            "c1_coproc" / Int32ul,
            "c1_xscaleauxcr" / Int32ul,
            "c2_base0" / Int32ul,
            "c2_base1" / Int32ul,
            "c2_control" / Int32ul,
            "c2_mask" / Int32ul,
            "c2_base_mask" / Int32ul,
            "c2_data" / Int32ul,
            "c2_insn" / Int32ul,
            "c3" / Int32ul,
            "c5_insn" / Int32ul,
            "c5_data" / Int32ul,
            "c6_region" / Array(8, Int32ul),
            "c6_insn" / Int32ul,
            "c6_data" / Int32ul,
            "c9_insn" / Int32ul,
            "c9_data" / Int32ul,
            "c13_fcse" / Int32ul,
            "c13_context" / Int32ul,
            "c13_tls1" / Int32ul,
            "c13_tls2" / Int32ul,
            "c13_tls3" / Int32ul,
            "c15_par" / Int32ul,
            "c15_ticonfig" / Int32ul,
            "c15_i_max" / Int32ul,
            "c15_i_min" / Int32ul,
            "c15_threadid" / Int32ul,
        )

        # ARMCPU.cpp LoadState()
        arm_coprocessor_id = Struct(
            Enum("coprocessorID" / Int32ul,
                 ID_SPVFP=10,
                 ID_DPVFP=11,
                 ID_SYSCP=15,
                 BAD_CP=100
            ),
            "coprocessor" / If(this.coprocessorID == "ID_SYSCP", arm_system_control_coprocessor),
        )

        # ARMCoprocessor.h
        arm_coprocessor = Struct(
            "coprocessorCount" / Int32ul,
            "coprocessors" / Array(this.coprocessorCount, arm_coprocessor_id),
        )

        arm_linux_syscall_handler = Struct(
            "currentThreadID" / Int32ul,
            "programBreak" / Int32ul,
        )

        # ARMCPUSettings.cpp LoadState()
        # ARMCPU.cpp
        arm_cpu = Struct(
            "registers" / arm_gp_registers,
            "thumbITState" / Int8ul,
            "prefetchFlush" / Int8ul,
            "prefetchInstr" / Int32ul,
            "cpuSettings" / arm_cpu_settings,
            "coprocessors" / arm_coprocessor,
            "instrCount" / Int64ul,
            "syscallHandler" / arm_linux_syscall_handler,
        )

        # VM.cpp LoadState()
        cpu = Struct(
            "cpuTypeNameSize" / Int32ul,
            "cpuName" / String(this.cpuTypeNameSize),
            "arm" / If(this.cpuName == "arm", arm_cpu),
        )

        # DebugCLI.cpp DBCLoad()
        # VM.cpp LoadState()
        # main.cpp
        snapshot = Struct(
            "base" / base,
            "mmuBool" / Int8ul,
            "mmu" / If(this.mmuBool, mmu),
            "cpuBool" / Int8ul,
            "cpu" / If(this.cpuBool, cpu),
        )

        self.snapshot_container = snapshot.parse(self.filedata)

    def snapshot_cpu_registers(self):
        """
        register keys:
        R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
        R13_SVC, R14_SVC, R13_ABT, R14_ABT, R13_UND, R14_UND, R13_IRQ, R14_IRQ,
        R8_FIQ, R9_FIQ, R10_FIQ, R11_FIQ, R12_FIQ, R13_FIQ, R14_FIQ, CPSR,
        SPSR_SVC, SPSR_ABT, SPSR_UND, SPSR_IRQ, SPSR_FIQ 
        """

        if self.is_ini:
            return self.ini_cpu_registers
        else:
            return self.snapshot_container.cpu.arm.registers

    """
    def snapshot_coprocessor_count(self):
        return self.snapshot_container.cpu.coprocessors.coprocessorCount

    def snapshot_get_coprocessors(self):
        for coprocessor in self.snapshot_container.cpu.coprocessors.coprocessors:
            yield coprocessor
    """

    def snapshot_page_count(self):
        if self.is_ini:
            return len(self.ini_memory_pages)
        else:
            return len(self.snapshot_container.mmu.ARMBasicMMU.pages)

    def snapshot_get_pages(self):
        """ dict keys: "baseAddress", "loadPageIdx", "loadProtectionFlags", "memoryPage" 
            ini dict uses the "baseAddress" key instead of "loadPageIdx"
        """
        if self.is_ini:
            for page in self.ini_memory_pages:
                yield page
        else:
            for page in self.snapshot_container.mmu.ARMBasicMMU.pages:
                yield page


if __name__ == "__main__":
    #fs = Snapshot("C:\\Users\\kfujim01\\Desktop\\test\\test.ini", True)
    fs = Snapshot("C:\\Users\\kfujim01\\Desktop\\test\\snapshot")

    print fs.snapshot_cpu_registers()
    print type(fs.snapshot_cpu_registers())

    """
    c = fs.snapshot_page_count()
    pages = fs.snapshot_get_pages()
    for x in xrange(c):
        page = pages.next()
        # ini
        print "baseAddress: 0x{:X}".format(page["baseAddress"])
        #print "loadPageIdx: 0x{:X}".format(page["loadPageIdx"])
        print "memoryPage length: 0x{:X}".format(len(page["memoryPage"]))
        print "loadProtectionFlags: 0x{:X}".format(page["loadProtectionFlags"])
        print type(page)
    """

    #print fs.snapshot_container
    #with open("parsed.txt", "w") as f:
    #    f.write(str(fs.snapshot_container))
