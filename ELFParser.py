__author__ = "makethyme@sina.com.cn"
__version__ = "$Revision: 0.1 $"
__date__ = "$Date : 2006/08/05 $"
__copyright__ = "Copyrigth (c) 2006"
__license__ = "Python"

import os, sys
from struct import *

global OpenFile, Endian
from optparse import OptionParser

Endian = None

# the struct Elf32_Ehdr defined in Elf.h
# ELF Header
# typedef struct {
# unsigned char e_ident[EI_NIDENT]; //16
# Elf32_Half    e_type;      //2
# Elf32_Half    e_machine;   //2
# Elf32_Word    e_version;   //4
# Elf32_Addr    e_entry;     //4
# Elf32_Off     e_phoff;     //4
# Elf32_Off     e_shoff;     //4
# Elf32_Word    e_flags;     //4
# Elf32_Half    e_ehsize;    //2
# Elf32_Half    e_phentsize; //2
# ELf3_Half     e_phnum;     //2
# Elf32_Half    e_shentsize; //2
# Elf32_Half    e_shnum;     //2
# Elf32_Half    e_shstrndx;  //2
# } Elf32_Ehdr;

EI_NIDENT = 16
SIZEOFSECTIONHEADER = 50
ELFHEADERSIZESUBIDENT = 36
ELFCLASS = {
    0: "Invalid Class",
    1: "ELF32",
    2: "ELF64"
}
ENCODING = {
    0: "Invalid data encoding",
    1: "2's complement, little endian",
    2: "2's complement, big endian"
}
VERSION = {
    0: "Invalid Version",
    1: "Current Version"
}
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

ELFHEADERFILETYPE = {
    ET_NONE: "No file type",
    ET_REL: "Relocatable file",
    ET_EXEC: "Executable file",
    ET_DYN: "Shared Object file",
    ET_CORE: "Core file",
    ET_LOPROC: "Processor-specific",
    ET_HIPROC: "Processor-specific"
}

EM_NONE = 0
EM_M32 = 1
EM_SPACE = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_860 = 7
EM_MIPS = 8
EM_S370 = 9
EM_MIPS_RS4_BE = 10
EM_PARISC = 15
EM_VPP550 = 17
EM_SPARC32PLUS = 18
EM_960 = 19
EM_FR20 = 37
EM_RH32 = 38
EM_MCORE = 39
EM_ARM = 40
EM_OLD_ALPHA = 41
EM_SH = 42
EM_MIPS_X = 51
EM_COLDFIRE = 52
EM_68HC12 = 53
EM_MMA = 54
EM_PCP = 55
EM_NCPU = 56
EM_NDR1 = 57
EM_STARCORE = 58
EM_ME16 = 59
EM_ST100 = 60
EM_TINYJ = 61
EM_FX66 = 66
EM_ST9PLUS = 67
EM_ST7 = 68
EM_68HC16 = 69
EM_68HC11 = 70
EM_68HC08 = 71
EM_68HC05 = 72
EM_SVX = 73
EM_ST19 = 74
EM_VAX = 75
EM_PJ = 99

ELFHEADERMACHINE = {
    EM_NONE: "No Machine",
    EM_M32: "AT&T WE 32100",
    EM_SPACE: "SPARC",
    EM_386: "Intel 80386",
    EM_68K: "Motorola 68000",
    EM_860: "Intel 80860",
    EM_MIPS: "MIPS R3000",
    EM_S370: "Amdahl",
    EM_MIPS_RS4_BE: "MIPS R4000 big-endian",
    EM_PARISC: "HPPA",
    EM_VPP550: "Fujitsu VPP500",
    EM_SPARC32PLUS: "Sun v8plus",
    EM_960: "Intel 80960",
    EM_FR20: "Fujitsu FR20",
    EM_RH32: "TRW RH32",
    EM_MCORE: "Motorolla MCore",
    EM_ARM: "ARM",
    EM_OLD_ALPHA: "Digital Alpha",
    EM_SH: "Hitachi SH",
    EM_MIPS_X: "Stanford MIPS-X",
    EM_COLDFIRE: "Motorola Coldfire",
    EM_68HC12: "Motorola M68HC12",
    EM_MMA: "Fujitsu Multimedia Accelerator",
    EM_PCP: "Siemens PCP",
    EM_NCPU: "Sony nCPU embedded RISC processor",
    EM_NDR1: "Denso NDR1 microprocesspr",
    EM_STARCORE: "Motorola Star*Core processor",
    EM_ME16: "Toyota ME16 processor",
    EM_ST100: "STMicroelectronics ST100 processor",
    EM_TINYJ: "Advanced Logic Corp. TinyJ embedded processor",
    EM_FX66: "Siemens FX66 microcontroller",
    EM_ST9PLUS: "STMicroelectronics ST9+ 8/16 bit microcontroller",
    EM_ST7: "STMicroelectronics ST7 8-bit microcontroller",
    EM_68HC16: "Motorola MC68HC16 Microcontroller",
    EM_68HC11: "Motorola MC68HC11 Microcontroller",
    EM_68HC08: "Motorola MC68HC08 Microcontroller",
    EM_68HC05: "Motorola MC68HC05 Microcontroller",
    EM_SVX: "Silicon Graphics SVx",
    EM_ST19: "STMicroelectronics ST19 8-bit microcontroller",
    EM_VAX: "Digital VAX",
    EM_PJ: "picoJava"
}

SIZEOFSECTIONENTRY = 40
# Section Header
# typedef struct {
# Elf32_Word    sh_name;
# Elf32_Word    sh_type;
# Elf32_Word    sh_flags;
# Elf32_Addr    sh_addr;
# Elf32_Off     sh_offset;
# Elf32_Word    sh_size;
# Elf32_Word    sh_link;
# Elf32_Word    sh_info;
# Elf32_Word    sh_addralign;
# Elf32_Word    sh_entsize;
# }Elf32_Shdr;


SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff
SHT_VERSYM = 0x6fffffff
SHT_VERNEED = 0x6ffffffe

SECTIONTYPE = {
    SHT_NULL:   "NULL",
    SHT_PROGBITS:   "PROGBITS",
    SHT_SYMTAB:   "SYMTAB",
    SHT_STRTAB:   "STRTAB",
    SHT_RELA:   "RELA",
    SHT_HASH:   "HASH",
    SHT_DYNAMIC:   "DYNAMIC",
    SHT_NOTE:   "NOTE",
    SHT_NOBITS:   "NOBITS",
    SHT_REL:   "REL",
    SHT_SHLIB:   "SHLIB",
    SHT_DYNSYM:   "DYNSYM",
    SHT_LOPROC:   "LOPROC",
    SHT_HIPROC:   "HIPROC",
    SHT_LOUSER:   "LOUSER",
    SHT_HIUSER:   "HIUSER",
    SHT_VERSYM:   "VERSYM",
    SHT_VERNEED:   "VERNEED"
}
SECTIONFLAG = {
    0:   "",
    1:   "W ",
    2:   " A",
    3:   "WA",
    4:   " X",
    5:   "WX",
    6:   "AX"
}
SYMBOLHEADERENTRY = 16
# typedef struct {
# Elf32_Word    st_name;
# Elf32_Addr    st_value;
# Elf32_Word    st_size;
# unsigned char st_info;
# unsigned char st_other;
# Elf32_Half    st_shndx;
# } Elf32_Sym;


STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_LOPROC = 13
STT_HIPROC = 15
SYMBOLTYPE = {
    STT_NOTYPE:   "NOTYPE",
    STT_OBJECT:   "OBJECT",
    STT_FUNC:   "FUNC",
    STT_SECTION:   "SECTION",
    STT_FILE:   "FILE",
    STT_LOPROC:   "LOPROC",
    STT_HIPROC:   "HIPROC"
}
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_LOPROC = 3
STB_HIPROC = 4
SYMBOLBIND = {
    STB_LOCAL:   "LOCAL",
    STB_GLOBAL:   "GLOBAL",
    STB_WEAK:   "WEAK",
    STB_LOPROC:   "LOPROC",
    STB_HIPROC:   "HIPROC"
}

# typedef struct {
# Elf32_Word    p_type;
# Elf32_Off     p_offset;
# Elf32_Word    p_vaddr;
# Elf32_Word    p_paddr;
# Elf32_Word    p_filesz;
# Elf32_Word    p_memsz;
# Elf32_Word    p_flags;
# Elf32_Word    p_align;
# } Elf32_Phdr;

PROGRAMHEADERENTRYSIZE = 32

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PROGRAMHEADERTYPE = {
    PT_NULL: "NULL",
    PT_LOAD:   "LOAD",
    PT_DYNAMIC:   "DYNAMIC",
    PT_INTERP:   "INTERP",
    PT_NOTE:   "NOTE",
    PT_SHLIB:   "SHLIB",
    PT_PHDR:   "PHDR",
    PT_LOPROC:   "LOPROC",
    PT_HIPROC:   "HIPROC"
}

PROGRAMHEADERFLAG = {
    0:   "",
    1:   "  E",
    2:   " W ",
    3:   " WE",
    4:   "R  ",
    5:   "R E",
    6:   "RW ",
    7:   "RWE"
}
# typedef struct {
# Elf32_SWord d_tag;
# union {
#   Elf32_Sword d_val;
#   Elf32_Addr  d_ptr;
#  }d_un;
# }Elf32_Dyn;
DYNAMICENTRYSIZE = 8

DynamicTagDict = {
    0:    "NULL",
    1:    "NEEDED",
    2:    "PLTRELSZ",
    3:    "PLTGOT",
    4:    "HASH",
    5:    "STRTAB",
    6:    "SYMTAB",
    7:    "RELA",
    8:    "RELASZ",
    9:    "RELAENT",
    10:    "STRSZ",
    11:    "SYMENT",
    12:    "INIT",
    13:    "FINI",
    14:    "SONAME",
    15:    "RPATH",
    16:    "SYMBOLIC",
    17:    "REL",
    18:    "RELSZ",
    19:    "RELENT",
    20:    "PLTREL",
    21:    "DEBUG",
    22:    "TEXTREL",
    23:    "JMPREL",
    0x70000000:    "LOPROC",
    0x7fffffff:    "HIPROC",
    0x6ffffffe:    "VERNEED",
    0x6fffffff:    "VERNEEDNUM",
    0x6ffffff0:    "VERSYM",
}

# typedef struct {
# Elf32_Addr  r_offset;
# Elf32_Word  r_info;
# } Elf32_Rel;

RelocateTypeDict = {
    0:    "R_386_NONE",
    1:    "R_386_32",
    2:    "R_386_PC32",
    3:    "R_386_GOT32",
    4:    "R_386_PLT32",
    5:    "R_386_COPY",
    6:    "R_386_GLOB_DAT",
    7:    "R_386_JMP_SLOT",
    8:    "R_386_RELATIVE",
    9:    "R_386_GOTOFF",
    10:    "R_386_GOTPC",
}


RELOCATIONENTRYSIZE = 8


class ElfStruct:
    def __init__(self, PathFile):
        self.openfile = open(PathFile, "rb")
        self.ElfHeader = ElfHeader(self.openfile)
        self.Endian = ord(self.ElfHeader.e_ident[5])
        self.strTable = ReadStrTable(self.ElfHeader, self.openfile)
        self.SectionTable = SectionHeader(self.openfile, self.ElfHeader)
        self.strtabIndex = FindSectionTable(self.strTable, self.SectionTable.SectionHeaderTable, '.strtab',
                                            self.ElfHeader.e_shnum)
        self.symtabIndex = FindSectionTable(self.strTable, self.SectionTable.SectionHeaderTable, '.symtab',
                                            self.ElfHeader.e_shnum)
        self.dynsymIndex = FindSectionTable(self.strTable, self.SectionTable.SectionHeaderTable, '.dynsym',
                                            self.ElfHeader.e_shnum)
        self.dynstrIndex = FindSectionTable(self.strTable, self.SectionTable.SectionHeaderTable, '.dynstr',
                                            self.ElfHeader.e_shnum)
        strtabPosition = self.SectionTable.SectionHeaderTable[self.strtabIndex][4]
        strtabLength = self.SectionTable.SectionHeaderTable[self.strtabIndex][5]
        self.openfile.seek(strtabPosition, 0)
        self.strtabTable = self.openfile.read(strtabLength)
        dynstrPosition = self.SectionTable.SectionHeaderTable[self.dynstrIndex][4]
        dynstrLength = self.SectionTable.SectionHeaderTable[self.dynstrIndex][5]
        self.openfile.seek(dynstrPosition, 0)
        self.dynstrTable = self.openfile.read(dynstrLength)
        self.DynSymbolTable = SymbolHeader(self.openfile, self.SectionTable.SectionHeaderTable, self.strtabTable,
                                           self.dynsymIndex, self.Endian)
        self.SymbolTable = SymbolHeader(self.openfile, self.SectionTable.SectionHeaderTable, self.strtabTable,
                                        self.symtabIndex, self.Endian)
        self.ProgramHeader = ProgramHeader(self.openfile, self.ElfHeader)
        self.DynamicStruct = DynamicStruct(self.openfile, self.SectionTable, self.Endian)
        self.RelocateSection = RelocateStruct(self.openfile, self.SectionTable, self.Endian)

    def ParseHeader(self):
        print "/n"
        print "ELF Header"
        Magic = self.ElfHeader.e_ident[0:4]
        print "Magic:".ljust(40) + "%02x %02x %02x %02x" % (ord(Magic[0]), ord(Magic[1]), ord(Magic[2]), ord(Magic[3]))
        ElfClass = self.ElfHeader.e_ident[4]
        print "Class:".ljust(40) + "%s" % ELFCLASS[ord(ElfClass)]
        Encoding = self.ElfHeader.e_ident[5]
        print "Data:".ljust(40) + "%s" % ENCODING[ord(Encoding)]
        Version = self.ElfHeader.e_ident[6]
        print "Version:".ljust(40) + "%s" % VERSION[ord(Version)]
        Padding = self.ElfHeader.e_ident[7:16]
        print "Padding:".ljust(40) + "%02x %02x %02x %02x %02x %02x %02x %02x %02x" % \
        (ord(Padding[0]), ord(Padding[1]), ord(Padding[2]), ord(Padding[3]),
        ord(Padding[4]), ord(Padding[5]), ord(Padding[6]), ord(Padding[7]), ord(Padding[8]) )
        e_type = self.ElfHeader.e_type
        print "Type:".ljust(40) + ELFHEADERFILETYPE[e_type]
        e_machine = self.ElfHeader.e_machine
        print "Machine:".ljust(40) + ELFHEADERMACHINE[e_machine]
        e_version = self.ElfHeader.e_version
        print "Version:".ljust(40) + VERSION[e_version]
        print "Entry Point Address:".ljust(40) + "%04X" % self.ElfHeader.e_entry
        print "Start of program header:".ljust(40) + "%d" % (self.ElfHeader.e_phoff) + " <byte into file>"
        print "Start of section header".ljust(40) + "%d" % (self.ElfHeader.e_shoff) + " <byte into file>"
        print "Flags:".ljust(40) + "%d" % self.ElfHeader.e_flag
        print "size of this header:".ljust(40) + "%d" % self.ElfHeader.e_ehsize + " <byte into file>"
        print "Size of program headers:".ljust(40) + "%d" % self.ElfHeader.e_phentsize + " <byte into file>"
        print "Number of program headers:".ljust(40) + "%d" % self.ElfHeader.e_phnum
        print "size of section headers:".ljust(40) + "%d" % self.ElfHeader.e_shentsize + " <byte into file>"
        print "Number of section header numbers:".ljust(40) + "%d" % self.ElfHeader.e_shnum
        print "Section header string table index:".ljust(40) + "%d" % self.ElfHeader.e_shstrndex

    def ParseSectionHeader(self):
        print "/n"
        print "There are %d section header, starting at offset %0X" % (self.ElfHeader.e_shnum, self.ElfHeader.e_shoff)
        print "%s".ljust(4) % "[Nr]" + " " + "%s".ljust(15) % "Name" + " " + "%-10s" % "Type" + \
        " " + "%-8s" % "Addr" + " " + "%-6s" % "Off" + " " + "%-6s" % "SIZE" + \
        " " + "%-2s" % "ES" + " " + "%-3s" % "Flg" + " " + "%-2s" % "Lk" + " " + "%-3s" % "Inf" + " " + "%-4s" % "Alig"

        for index in range(self.ElfHeader.e_shnum):
            SectionName = self.strTable[self.SectionTable.SectionHeaderTable[index][0]:].split('/0')[0]
            SectionType = SECTIONTYPE[self.SectionTable.SectionHeaderTable[index][1]]
            SectionAddr = self.SectionTable.SectionHeaderTable[index][3]
            SectionOffset = self.SectionTable.SectionHeaderTable[index][4]
            SectionSize = self.SectionTable.SectionHeaderTable[index][5]
            SectionES = self.SectionTable.SectionHeaderTable[index][9]
            SectionFlag = SECTIONFLAG[self.SectionTable.SectionHeaderTable[index][2]]
            SectionLink = self.SectionTable.SectionHeaderTable[index][6]
            SectionInfo = self.SectionTable.SectionHeaderTable[index][7]
            SectionAlign = self.SectionTable.SectionHeaderTable[index][8]
            print "[%02d]" % index + " " + "%-18s" % SectionName + " " \
            + "%-10s" % SectionType \
            + " " + "%08x" % SectionAddr + " " + "%06x" % SectionOffset + " " + "%06x" % SectionSize \
            + " " + "%02x" % SectionES + " " + "%03s" % SectionFlag + "  " + "%02x" % SectionLink \
            + "  " + "%03x" % SectionInfo + "   " + "%02x" % SectionAlign


        print "Key to Flags:"
        print "W (write), A (alloc), X (execute), M (merge), S (strings)"
        print "I (info), L (link order), G (group), x (unknown)"
        print "O (extra OS processing required) o (OS specific), p (processor specific)"


def ParseSymbolHeader(self):
    print
    print "Symbol table /'.symtab/' contains %d entries:" % self.SymbolTable.entryNumber
    print "%-4s" % "Num" + " " + "%-8s" + "Value" + " " + "%-4s" % "Size" + "%-8s" % "Type" + \
    " " + "%-8s" % "Bind" + " " + "%-8s" % "Vis" + " " + "%-5s" % "Ndx" + " " + "%s" % "Name"


    for index in range(self.SymbolTable.entryNumber):
        SymbolInformation = self.SymbolTable.SymbolHeaderTable[index][3]
        SymbolName = self.strtabTable[self.SymbolTable.SymbolHeaderTable[index][0]:].split('/0')[0]
        SymbolValue = self.SymbolTable.SymbolHeaderTable[index][1]
        SymbolSize = self.SymbolTable.SymbolHeaderTable[index][2]
        SymbolOther = self.SymbolTable.SymbolHeaderTable[index][4]
        SymbolNdx = self.SymbolTable.SymbolHeaderTable[index][5]
        SymbolTypeTemp = SymbolInformation & 0x0f
        SymbolBindTemp = SymbolInformation >> 4
        SymbolType = SYMBOLTYPE[SymbolTypeTemp]
        SymbolBind = SYMBOLBIND[SymbolBindTemp]
        print "%4d" % index + " " + "%08x" % SymbolValue + " " + "%04x" % SymbolSize + " " + "%-8s" % SymbolType \
        + " " + "%-8s" % SymbolBind + " " + "%-8s" % "DEFAULT" + " " + "%05d" % SymbolNdx + " " + "%s" % SymbolName


def ParseDynSymbolHeader(self):
    print
    print "Symbol table /'.symtab/' contains %d entries:" % self.DynSymbolTable.entryNumber
    print "%-4s" % "Num" + " " + "%-8s" % "Value" + " " + "%-4s" % "Size" + "%-8s" % "Type" + \
    " " + "%-8s" % "Bind" + " " + "%-8s" % "Vis" + " " + "%-5s" % "Ndx" + " " + "%s" % "Name"


    for index in range(self.DynSymbolTable.entryNumber):
        SymbolInformation = self.DynSymbolTable.SymbolHeaderTable[index][3]
        SymbolName = self.dynstrTable[self.DynSymbolTable.SymbolHeaderTable[index][0]:].split('/0')[0]
        SymbolValue = self.DynSymbolTable.SymbolHeaderTable[index][1]
        SymbolSize = self.DynSymbolTable.SymbolHeaderTable[index][2]
        SymbolOther = self.DynSymbolTable.SymbolHeaderTable[index][4]
        SymbolNdx = self.DynSymbolTable.SymbolHeaderTable[index][5]
        SymbolTypeTemp = SymbolInformation & 0x0f
        SymbolBindTemp = SymbolInformation >> 4
        SymbolType = SYMBOLTYPE[SymbolTypeTemp]
        SymbolBind = SYMBOLBIND[SymbolBindTemp]
        # something wrong with visible, now just set it to Default
        print "%4d" % index + " " + "%08x" % SymbolValue + " " + "%04x" % SymbolSize + " " + "%-8s" % SymbolType \
        + " " + "%-8s" % SymbolBind + " " + "%-8s" % "DEFAULT" + " " + "%05d" % SymbolNdx + " " + "%s" % SymbolName


def ParseProgramHeader(self):
    filetypeString = "self.ElfHeader.e_type"
    filetypeString = ELFHEADERFILETYPE[self.ElfHeader.e_type]
    print 'Elf file type is ' + filetypeString

    print "    " + "%8s" % "Type" + " " + "%08s" % "Offset" + "  " + "%08s" % "VirtAddr" + \
    "  " + "%08s" % "PhysAddr" + " " + "%08s" % "FileSize" + " " + "%08s" % "MemSize" + \
    "  " + "%3s" % "Flag" + "%08s" % "Align"


    number = self.ProgramHeader.number
    for index in range(number):
        ProgramHeaderTypeTemp, ProgramHeaderOff, ProgramHeaderVadd, ProgramHeaderPaddr, \
        ProgramHeaderFileSz, ProgramHeaderMemSz, ProgramHeaderFlagTemp, \
        ProgramHeaderAlign = self.ProgramHeader.ProgramHeaderTable[index]

        if ProgramHeaderTypeTemp == 1685382481:
            ProgramHeaderType = ""
        else:
            ProgramHeaderType = PROGRAMHEADERTYPE[ProgramHeaderTypeTemp]

        ProgramHeaderFlag = PROGRAMHEADERFLAG[ProgramHeaderFlagTemp]
        print "%02d" % index + "  " + "%8s" % ProgramHeaderType + " " + "%08x" % ProgramHeaderOff + "  " + "%08x" % ProgramHeaderVadd + \
        "  " + "%08x" % ProgramHeaderPaddr + " " + "%08x" % ProgramHeaderFileSz + " " + "%08x" % ProgramHeaderMemSz + \
        "  " + "%3s" % ProgramHeaderFlag + "     " + "%02x" % ProgramHeaderAlign


def ParseDynamicStruct(self):
    print "Dynamic segment at offset %08X contains %d entries" % (
    self.DynamicStruct.position, self.DynamicStruct.number)
    print "%-8s" % "Tag" + "    " + "%12s" % "Type" + "           " + "Name/Value"
    for index in range(self.DynamicStruct.number):
        tag, valorptr = self.DynamicStruct.DynamicStructTable[index]
        tagString = DynamicTagDict[tag]
        if tag == 1:
            tagName = self.dynstrTable[valorptr:].split('/0')[0]
            print "%08X" % tag + "    " + "%12s" % tagString + "           " + "Shared Library : " + "%s" % tagName
        else:
            print "%08X" % tag + "    " + "%12s" % tagString + "            " + "%08x" % valorptr


def ParseRelocateStruct(self):
    relsectionnum = len(self.RelocateSection.index)
    indexTable = self.RelocateSection.index
    for outerIndex in range(relsectionnum):
        SectionName = self.strTable[self.SectionTable.SectionHeaderTable[indexTable[outerIndex]][0]:].split('/0')[0]
        Offset = self.RelocateSection.position[outerIndex]
        Number = self.RelocateSection.number[outerIndex]
        print
        print "Relocation section /'%s/'" % SectionName + "at offset " + "%08x" % Offset + " contains " + "%d" % Number + " entries:"
        print "Offset" + "      " + "Info" + "        " + "Type" + "        " + "Sym.Value" + "   " + "Sym.Name"
        for index in range(Number):
            OffsetField, InfoField = self.RelocateSection.RelocateStructTable[outerIndex][index]
            TypeField = InfoField & 0xF
            NameField = InfoField >> 8
            NameString = self.dynstrTable[self.DynSymbolTable.SymbolHeaderTable[NameField][0]:].split('/0')[0]
            TypeString = RelocateTypeDict[TypeField]
            ValueField = 0x0
            print "%08X" % OffsetField + "   " + "%08X" % InfoField + "   " + "%s" % TypeString + " " + "%08X" % ValueField + "  " + "%s" % NameString


class ElfHeader:
    def __init__(self, openfile):
        self.openfile = openfile
        position = 0x0L
        self.openfile.seek(position, 0)
        self.e_ident = self.openfile.read(16)
        if self.e_ident[0:4] != "/x7FELF":
            print "/nError: Not an ELF file - it has the wrong magic bytes at the start"
            sys.exit(0)
        self.Endian = ord(self.e_ident[5])
        BigOrLittleEndian = self.Endian
        RawString = self.openfile.read(ELFHEADERSIZESUBIDENT)
        if BigOrLittleEndian == 2:
            value = unpack(">HHiiiiiHHHHHH", RawString)
        elif BigOrLittleEndian == 1:
            value = unpack("<HHiiiiiHHHHHH", RawString)
        self.e_type, self.e_machine, self.e_version, self.e_entry, \
        self.e_phoff, self.e_shoff, self.e_flag, self.e_ehsize, \
        self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, \
        self.e_shstrndex = value


class SectionHeader:
    def __init__(self, openfile, ElfHeader):
        self.openfile = openfile
        self.e_shnum = ElfHeader.e_shnum
        self.e_shoff = ElfHeader.e_shoff
        BigOrLittleEndian = ElfHeader.Endian
        self.openfile.seek(self.e_shoff, 0)
        self.SectionHeaderTable = [[]]
        for index in range(self.e_shnum):
            RawString = self.openfile.read(SIZEOFSECTIONENTRY)
            if BigOrLittleEndian == 2:
                value = unpack(">iiiiiiiiii", RawString)
            elif BigOrLittleEndian == 1:
                value = unpack("<iiiiiiiiii", RawString)
            if index != 0:
                self.SectionHeaderTable.append([])
            self.SectionHeaderTable[index] = value


class SymbolHeader:
    def __init__(self, openfile, SectionTable, strtabTable, symtabIndex, BigOrLittleEndian):
        symtablePosition = SectionTable[symtabIndex][4]
        symtableLength = SectionTable[symtabIndex][5]
        entrySize = SectionTable[symtabIndex][9]
        if symtableLength == 0 or entrySize == 0:
            entryNumber = 0
        else:
            entryNumber = symtableLength / entrySize
        self.openfile = openfile
        self.openfile.seek(symtablePosition, 0)
        self.entryNumber = entryNumber
        self.SymbolHeaderTable = [[]]
        for index in range(entryNumber):
            if index != 0:
                self.SymbolHeaderTable.append([])
            RawString = self.openfile.read(SYMBOLHEADERENTRY)
            if BigOrLittleEndian == 2:
                value = unpack(">iiiBBH", RawString)
            elif BigOrLittleEndian == 1:
                value = unpack("<iiiBBH", RawString)
            for index_1 in range(6):
                self.SymbolHeaderTable[index].append(value[index_1])


class ProgramHeader:
    def __init__(self, openfile, ElfHeader):
        self.openfile = openfile
        self.number = ElfHeader.e_phnum
        self.position = ElfHeader.e_phoff
        BigOrLittleEndian = ElfHeader.Endian
        self.openfile.seek(self.position, 0)
        self.ProgramHeaderTable = [[]]
        for index in range(self.number):
            if index != 0:
                self.ProgramHeaderTable.append([])
            RawString = self.openfile.read(PROGRAMHEADERENTRYSIZE)
            if BigOrLittleEndian == 2:
                value = unpack(">iiiiiiii", RawString)
            elif BigOrLittleEndian == 1:
                value = unpack("<iiiiiiii", RawString)

            self.ProgramHeaderTable[index] = value


class DynamicStruct:
    def __init__(self, openfile, SectionTable, Endian):
        BigOrLittleEndian = Endian
        self.openfile = openfile
        SectionHeaderTable = SectionTable.SectionHeaderTable
        shnum = SectionTable.e_shnum
        sectionIndex = FindSectionIndexByType(SectionHeaderTable, SHT_DYNAMIC, shnum)
        Position = SectionTable.SectionHeaderTable[sectionIndex][4]
        self.position = Position
        Size = SectionTable.SectionHeaderTable[sectionIndex][5]
        entrySize = SectionTable.SectionHeaderTable[sectionIndex][9]
        if Size == 0 or entrySize == 0:
            number = 0
        else:
            number = Size / entrySize
        self.number = number
        self.openfile.seek(Position, 0)
        self.DynamicStructTable = [[]]
        for index in range(self.number):
            if index != 0:
                self.DynamicStructTable.append([])
            RawString = self.openfile.read(DYNAMICENTRYSIZE)
            if BigOrLittleEndian == 2:
                value = unpack(">ii", RawString)
            elif BigOrLittleEndian == 1:
                value = unpack("<ii", RawString)
            for index_1 in range(2):
                self.DynamicStructTable[index].append(value[index_1])


class RelocateStruct:
    def __init__(self, openfile, SectionTable, Endian):
        BigOrLittleEndian = Endian
        self.openfile = openfile
        SectionHeaderTable = SectionTable.SectionHeaderTable
        shnum = SectionTable.e_shnum
        sectionIndex = FindRelocationSectionIndexByType(SectionHeaderTable, SHT_REL, shnum)
        self.RelocateStructTable = [[[]]]
        self.number = []
        self.position = []
        self.index = []
        for outerIndex in range(len(sectionIndex)):
            realIndex = sectionIndex[outerIndex]
            if outerIndex != 0:
                self.RelocateStructTable.append([[]])
            position = SectionTable.SectionHeaderTable[realIndex][4]
            self.position.append(position)
            self.index.append(realIndex)
            Size = SectionTable.SectionHeaderTable[realIndex][5]
            entrySize = SectionTable.SectionHeaderTable[realIndex][9]
            number = Size / entrySize
            self.number.append(number)
            self.openfile.seek(position, 0)
            for index in range(number):
                if index != 0:
                    self.RelocateStructTable[outerIndex].append([])
                RawString = self.openfile.read(RELOCATIONENTRYSIZE)
                if BigOrLittleEndian == 2:
                    value = unpack(">ii", RawString)
                elif BigOrLittleEndian == 1:
                    value = unpack("<ii", RawString)
                for index_1 in range(2):
                    self.RelocateStructTable[outerIndex][index].append(value[index_1])


def ReadHalfWord(SourceFile, BigOrLittleEndian):
    RawString = SourceFile.read(2)
    if BigOrLittleEndian == 2:
        value = unpack(">h", RawString)
    elif BigOrLittleEndian == 1:
        value = unpack("<h", RawString)
    return value[0]


def ReadOneWord(SourceFile, BigOrLittleEndian):
    RawString = SourceFile.read(4)
    if BigOrLittleEndian == 2:
        value = unpack(">i", RawString)
    elif BigOrLittleEndian == 1:
        value = unpack("<i", RawString)
    return value[0]


def FindSectionTable(strTable, SectionHeaderTable, findstring, e_shnum):
    value = -1
    for index in range(e_shnum):
        SectionName = strTable[SectionHeaderTable[index][0]:].split('/0')[0]
        if SectionName == findstring:
            value = index;
    return value


def FindSectionIndexByType(SectionHeaderTable, Type, e_shnum):
    value = -1
    for index in range(e_shnum):
        if SectionHeaderTable[index][1] == Type:
            value = index
    return value


def FindRelocationSectionIndexByType(SectionHeaderTable, Type, e_shnmu):
    returnIndex = []
    for index in range(e_shnmu):
        if SectionHeaderTable[index][1] == Type:
            returnIndex.append(index)
    return returnIndex


def ReadStrTable(ElfHeader, openfile):
    Endian = ord(ElfHeader.e_ident[5])
    strPositionTemp = ElfHeader.e_shoff + ElfHeader.e_shstrndex * SIZEOFSECTIONENTRY + 4 * 4
    openfile.seek(strPositionTemp, 0)
    strPosition = ReadOneWord(openfile, Endian)
    strLength = ReadOneWord(openfile, Endian)
    openfile.seek(strPosition, 0)
    RawString = openfile.read(strLength)
    return RawString


if __name__ == '__main__':
    parser = OptionParser()
    MSG_USAGE = """
      Usage: readelf <option(s)> elf-file
      Display information about the contents of ELF format files
      Options are:
    """
    parser.add_option("-a", "--all", dest="bAll", default=False, action="store_true",
                      help="Equivalent to: -h -l -S -s -r -d -V -A -I")
    parser.add_option("-H", "--file-header", dest="bFileHeader", default=False, action="store_true",
                      help="Display the ELF file header")
    parser.add_option("-l", "--program-headers", dest="bProgramHeader", default=False, action="store_true",
                      help="Display the program headers")
    parser.add_option("-S", "--section-headers", dest="bsection_headers", default=False, action="store_true",
                      help="Display the sections' header")
    parser.add_option("-e", "--headers", dest="bheader", default=False, action="store_true",
                      help="Equivalent to: -h -l -S")
    parser.add_option("-s", "--symbols", dest="bSymbols", default=False, action="store_true",
                      help="Display the symbol table")
    parser.add_option("-n", "--notes", dest="bNotes", default=False, action="store_true",
                      help="Display the core notes (if present)")
    parser.add_option("-r", "--relocs", dest="bRelocs", default=False, action="store_true",
                      help="Display the relocations (if present)")
    parser.add_option("-u", "--unwind", dest="bUnwind", default=False, action="store_true",
                      help="Display the unwind info (if present)")
    parser.add_option("-d", "--dynamic", dest="bDynamic", default=False, action="store_true",
                      help="Display the dynamic segment (if present)")
    parser.add_option("-V", "--version-info", dest="bVersionInfo", default=False, action="store_true",
                      help="Display the version sections (if present)")
    parser.add_option("-A", "--arch-specific", dest="bArch", default=False, action="store_true",
                      help="Display architecture specific information (if any)")
    parser.add_option("-D", "--use-dynamic", dest="bUseDynamic", default=False, action="store_true",
                      help="Use the dynamic section info when displaying symbols")
    parser.add_option("-x", "--hex-dump", dest="hex_dump_number", default=0,
                      help="Dump the contents of section <number>")
    parser.add_option("-I", "--histogram", dest="bHistogram", default=False, action="store_true",
                      help="Display histogram of bucket list lengths")
    parser.add_option("-W", "--debug-dump", dest="wide", default=False, action="store_true",
                      help="Allow output width to exceed 80 characters")
    # -h is used for
    # parser.add_option("-H", "--help", dest = "bHelp", default = False, action = "store_true", help = "Display this information")
    parser.add_option("-v", "--version", dest="bVersion", default=False, action="store_true",
                      help="Display the version number of readelf")

    print  "11111"
    opts, args = parser.parse_args()
    inputFile = sys.argv[-1]
    if inputFile[0] == '-':
        inputFile = ""
    if opts.bVersion:
        print __version__
    # if not inputFile:
    #      return
    if not inputFile:
        sys.exit(0)
    AbsPath = os.path.abspath(os.path.curdir)
    print AbsPath
    elfStruct = ElfStruct(inputFile)
    if opts.bFileHeader:
        elfStruct.ParseHeader()
    if opts.bProgramHeader:
        elfStruct.ParseProgramHeader()
    if opts.bsection_headers:
        elfStruct.ParseSectionHeader()
    if opts.bSymbols:
        elfStruct.ParseDynSymbolHeader()
        elfStruct.ParseSymbolHeader()
    if opts.bheader:
        elfStruct.ParseHeader()
        elfStruct.ParseProgramHeader()
        elfStruct.ParseSectionHeader()
    if opts.bAll:
        elfStruct.ParseHeader()
        elfStruct.ParseProgramHeader()
        elfStruct.ParseSectionHeader()
        elfStruct.ParseDynSymbolHeader()
        elfStruct.ParseSymbolHeader()
    if opts.bNotes:
        print
    if opts.bRelocs:
        elfStruct.ParseRelocateStruct()
    if opts.bUnwind:
        print
    if opts.bDynamic:
        elfStruct.ParseDynamicStruct()
    if opts.bVersionInfo:
        print
    if opts.bArch:
        print
    if opts.hex_dump_number:
        print
    if opts.bHistogram:
        print

    elfStruct.openfile.close()