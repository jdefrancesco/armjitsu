PAGE_SIZE = 4096

RAW_BIN = 1
ELF_BIN  = 2


ACCESS_NONE = 0
ACCESS_READ = 1
ACCESS_WRITE = 2
ACCESS_EXEC = 4

# NAME, BASE_ADDRESS, SIZE
RAW_BIN_MEMORY_MAP = [[".text", 0x40000, 0x1000],
                      [".data", 0x60000, 0x1000],
                      [".stack", 0x800000, 0x4000],
                      [".misc", 0x900000, 0x1000]
                     ]
