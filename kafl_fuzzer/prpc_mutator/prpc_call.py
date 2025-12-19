from enum import Enum

# PRPC parameter
class PRPC_Param:
    def __init__(self, size, isnullptr, value):
        self.size = size
        self.isnullptr = isnullptr
        self.value = value
    def __str__(self):
        return "PRPC_Param(size="+str(self.size)+",isnullptr="+str(self.isnullptr)+",value="+repr(self.value)+")"
# C-String
class PRPC_CStrParam(PRPC_Param):
    pass
# Path
class PRPC_PathParam(PRPC_CStrParam):
    def __str__(self):
        return "PRPC_PathParam(size="+str(self.size)+",isnullptr="+str(self.isnullptr)+",value="+repr(self.value)+")"
# Void Pointer
class PRPC_LPParam(PRPC_Param):
    def __str__(self):
        return "PRPC_LPParam(size="+str(self.size)+",isnullptr="+str(self.isnullptr)+",value="+repr(self.value)+")"
# uint32_t
class PRPC_uintParam(PRPC_Param):
    def __str__(self):
        return "PRPC_uintParam(size="+str(self.size)+",isnullptr="+str(self.isnullptr)+",value="+repr(self.value)+")"
# int64_t
class PRPC_llParam(PRPC_Param):
    def __str__(self):
        return "PRPC_llParam(size="+str(self.size)+",isnullptr="+str(self.isnullptr)+",value="+repr(self.value)+")"

################################################################################

class PRPC_ID(Enum):
    LISTENDCALL=0
    CREATEDIRECTORY=1
    CREATEFILE=2
    CREATENAMEDPIPE=3 # not used
    CREATESYMBOLICLINK=4
    COPYFILE=5
    DELETEFILE=6
    GETCOMPRESSEDFILESIZE=7
    GETFILEATTRIBUTES=8
    GETFILESIZE=9
    GETFILETIME=10
    GETFILETYPE=11
    MOVEFILE=12
    LOCKFILE=13
    REMOVEDIRECTORY=14
    SETENDOFFILE=15
    SETFILEATTRIBUTES=16
    SETFILEINFORMATIONBYHANDLE=17 # not impl.
    SETFILETIME=18
    SETFILEVALIDDATA=19
    SETNAMEDSECURITYINFO=20 # not used
    UNLOCKFILE=21
    READFILE=22
    LISTDIRECTORY=23
    COPYDIRECTORY=24
    CREATEJUNCTION=25
    COPYJUNCTION=26

################################################################################

class PRPC_Call:
    Default_Params = {
        PRPC_ID.CREATEDIRECTORY.value : [PRPC_PathParam, PRPC_LPParam],
        PRPC_ID.CREATEFILE.value : [PRPC_PathParam, PRPC_uintParam, PRPC_LPParam],
        PRPC_ID.CREATESYMBOLICLINK.value : [PRPC_PathParam, PRPC_PathParam, PRPC_uintParam],
        PRPC_ID.COPYFILE.value : [PRPC_PathParam, PRPC_PathParam],
        PRPC_ID.DELETEFILE.value : [PRPC_PathParam],
        PRPC_ID.GETCOMPRESSEDFILESIZE.value : [PRPC_PathParam],
        PRPC_ID.GETFILEATTRIBUTES.value : [PRPC_PathParam],
        PRPC_ID.GETFILESIZE.value : [PRPC_PathParam],
        PRPC_ID.GETFILETIME.value : [PRPC_PathParam],
        PRPC_ID.GETFILETYPE.value : [PRPC_PathParam],
        PRPC_ID.MOVEFILE.value : [PRPC_PathParam, PRPC_PathParam],
        PRPC_ID.LOCKFILE.value : [PRPC_PathParam, PRPC_uintParam, PRPC_uintParam],
        PRPC_ID.REMOVEDIRECTORY.value : [PRPC_PathParam],
        PRPC_ID.SETENDOFFILE.value : [PRPC_PathParam, PRPC_uintParam],
        PRPC_ID.SETFILEATTRIBUTES.value : [PRPC_PathParam, PRPC_uintParam],
        PRPC_ID.SETFILETIME.value : [PRPC_PathParam, PRPC_LPParam, PRPC_LPParam, PRPC_LPParam],
        PRPC_ID.SETFILEVALIDDATA.value : [PRPC_PathParam, PRPC_llParam],
        PRPC_ID.UNLOCKFILE.value : [PRPC_PathParam, PRPC_uintParam, PRPC_uintParam],
        PRPC_ID.READFILE.value : [PRPC_PathParam],
        PRPC_ID.LISTDIRECTORY.value : [PRPC_PathParam],
        PRPC_ID.COPYDIRECTORY.value : [PRPC_PathParam, PRPC_PathParam],
        PRPC_ID.CREATEJUNCTION.value : [PRPC_PathParam, PRPC_PathParam],
        PRPC_ID.COPYJUNCTION.value : [PRPC_PathParam, PRPC_PathParam],
    }
    def __init__(self, cid):
        self.cid = cid
        self.params = list()

    def appendParam(self, param):
        self.params.append(param)

    def __str__(self):
        s="PRPC_Call(cid="+str(self.cid)+",params=["
        for param in self.params:
            s += str(param)+","
        s = s[:-1] + "])"
        return s

    def add_dummy_params(self):
        for param_class in PRPC_Call.Default_Params[self.cid]:
            length = 0
            if param_class == PRPC_llParam:
                length = 8
            if param_class == PRPC_uintParam:
                length = 4
            self.params.append(param_class(length, False, b''))
