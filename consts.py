
# HEAP_BASE = 0x005589d61bd000
# CODE_BASE = 0x005589d614c000

HEAP_BASE = 0x5000000
CODE_BASE = 0x4000000

VM_CODE_START = HEAP_BASE + 0x1490
VM_CODE_SIZE = 0x3000

VM_DATA_SEGMENT_START = 0x4060 - 0x60
VM_DATA_START = CODE_BASE + 0x4060
VM_DATA_SIZE = 0x10000

START_STACK = VM_DATA_SEGMENT_START + 0x3000

