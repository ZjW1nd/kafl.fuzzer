import struct

from .prpc_call import *

################################################################################

INT32LEN=4
UINT8LEN=1

def payloaddataparam(param):
    memsize = struct.pack("<I", param.size)
    isnullptr = struct.pack("<?", param.isnullptr)
    mem = param.value
    payload = memsize+isnullptr
    if type(mem) == bytes:
        payload += mem
    else:
        if param.size == 4:
            payload += struct.pack("<I", mem)
        if param.size == 8:
            payload += struct.pack("<Q", mem)
        if param.size == 1:
            payload += struct.pack("<B", mem)
    return payload

def payloaddatacall(call):
    cidbytes = struct.pack("<I", call.cid)
    if len(call.params) == 0:
        return cidbytes

    parambytes = bytes()
    for param in call.params:
        parambytes += payloaddataparam(param)
    parambytes += payloaddataparam(PRPC_Param(0,True,bytes()))
    paramssize = struct.pack("<I", len(parambytes))
    return cidbytes+paramssize+parambytes

def serialize(calls):
    payload = bytes()
    for call in calls:
        payload += payloaddatacall(call)
    return payload

def writefile(calls, filename):
    payload = serialize(calls)
    with open(filename, 'wb') as f:
        f.write(payload)
