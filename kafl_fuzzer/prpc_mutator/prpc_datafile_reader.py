import struct

from prpc_call import *

from common.debug import log_prpc

################################################################################

# read data bytes from file
def readfile(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return data

def getbytes(count, data):
    if len(data) < count:
        raise Exception('invalid file structure')
    return data[:count], data[count:]

def getcid(data):
    CIDMEMSIZE=4
    ciddata, data, = getbytes(CIDMEMSIZE, data)
    cid = struct.unpack('i', ciddata)[0]
    return cid, data


################################################################################

def getparammem(data):
    # get memory size of parameter
    PARAMMEMSIZELEN=4
    nbytesbytes, data = getbytes(PARAMMEMSIZELEN, data)
    nbytes = struct.unpack("<I", nbytesbytes)[0]
    # get isnullptr
    PARAMISNULLPTRLEN=1
    isnullptrbytes, data = getbytes(PARAMISNULLPTRLEN, data)
    isnullptr = struct.unpack("<?", isnullptrbytes)[0]

    # get parameter
    mem, data = getbytes(nbytes, data)
    return nbytes, isnullptr, mem, data


# NOTE: type-lists may be a cleaner solution, if applicable

def getpathparam(data):
    pathsize, isnullptr, pathmem, data = getparammem(data)
    path = PRPC_PathParam(pathsize, isnullptr, pathmem)
    return path, data

def getuintparam(data):
    intsize, isnullptr, intmem, data = getparammem(data)
    intparam = PRPC_uintParam(intsize, isnullptr, struct.unpack("<I", intmem)[0])
    return intparam, data

def getllparam(data):
    llsize, isnullptr, llmem, data = getparammem(data)
    llparam = PRPC_llParam(llsize, isnullptr, struct.unpack("<Q", llmem)[0])
    return llparam, data

def getlpparam(data):
    lptypesize, isnullptr, lpmem, data = getparammem(data)
    lp = PRPC_LPParam(lptypesize, isnullptr, lpmem)
    return lp, data

def processlistendparam(data):
    pathsize, isnullptr, pathmem, data = getparammem(data)
    # NOTE: consistency check may be reasonable here
    return data


################################################################################

# NOTE: type-lists may be a cleaner solution, if applicable

def getparams_path(data):
    p, data = getpathparam(data)
    data = processlistendparam(data)
    return [p], data

def getparams_path_ll(data):
    p1, data = getpathparam(data)
    p2, data = getllparam(data)
    data = processlistendparam(data)
    return [p1, p2], data

def getparams_path_lp(data):
    p1, data = getpathparam(data)
    p2, data = getlpparam(data)
    data = processlistendparam(data)
    return [p1, p2], data

def getparams_path_lp_lp_lp(data):
    p1, data = getpathparam(data)
    p2, data = getlpparam(data)
    p3, data = getlpparam(data)
    p4, data = getlpparam(data)
    data = processlistendparam(data)
    return [p1, p2, p3, p4], data

def getparams_path_path(data):
    p1, data = getpathparam(data)
    p2, data = getpathparam(data)
    data = processlistendparam(data)
    return [p1,p2], data

def getparams_path_path_uint(data):
    p1, data = getpathparam(data)
    p2, data = getpathparam(data)
    p3, data = getuintparam(data)
    data = processlistendparam(data)
    return [p1,p2,p3], data

def getparams_path_uint(data):
    p1, data = getpathparam(data)
    p2, data = getuintparam(data)
    data = processlistendparam(data)
    return [p1,p2], data

def getparams_path_uint_lp(data):
    p1, data = getpathparam(data)
    p2, data = getuintparam(data)
    p3, data = getlpparam(data)
    data = processlistendparam(data)
    return [p1, p2, p3], data

def getparams_path_uint_uint(data):
    p1, data = getpathparam(data)
    p2, data = getuintparam(data)
    p3, data = getuintparam(data)
    data = processlistendparam(data)
    return [p1, p2, p3], data

################################################################################
def getparams_listendcall(data):
    params = list()
    return params, data

def getparams_createdirectory(data):
    return getparams_path_lp(data)

def getparams_createfile(data):
    return getparams_path_uint_lp(data)

def getparams_createnamedpipe(data):
    raise Exception("TODO: implement")

def getparams_createsymboliclink(data):
    return getparams_path_path_uint(data)

def getparams_copyfile(data):
    return getparams_path_path(data)

def getparams_deletefile(data):
    return getparams_path(data)

def getparams_getcompressedfilesize(data):
    return getparams_path(data)

def getparams_getfileattributes(data):
    return getparams_path(data)

def getparams_getfilesize(data):
    return getparams_path(data)

def getparams_getfiletime(data):
    return getparams_path(data)

def getparams_getfiletype(data):
    return getparams_path(data)

def getparams_movefile(data):
    return getparams_path_path(data)

def getparams_lockfile(data):
    return getparams_path_uint_uint(data)

def getparams_removedirectory(data):
    return getparams_path(data)

def getparams_setendoffile(data):
    return getparams_path_uint(data)

def getparams_setfileattributes(data):
    return getparams_path_uint(data)

def getparams_setfileinformationbyhandle(data):
    raise Exception("TODO: implement")

def getparams_setfiletime(data):
    return getparams_path_lp_lp_lp(data)

def getparams_setfilevaliddata(data):
    return getparams_path_ll(data)

def getparams_setnamedsecurityinfo(data):
    raise Exception("TODO: implement")

def getparams_unlockfile(data):
    return getparams_path_uint_uint(data)

def getparams_readfile(data):
    return getparams_path(data)

def getparams_listdirectory(data):
    return getparams_path(data)

def getparams_copydirectory(data):
    return getparams_path_path(data)

def getparams_createjunction(data):
    return getparams_path_path(data)

def getparams_copyjunction(data):
    return getparams_path_path(data)

def getparams_invalidcid(data):
    log_prpc("Invalid cid.  Abort.")
    exit(1)
################################################################################

def getparams(cid, data):
    paramfuncs = {
         0 : getparams_listendcall,
         1 : getparams_createdirectory,
         2 : getparams_createfile,
         3 : getparams_createnamedpipe,
         4 : getparams_createsymboliclink,
         5 : getparams_copyfile,
         6 : getparams_deletefile,
         7 : getparams_getcompressedfilesize,
         8 : getparams_getfileattributes,
         9 : getparams_getfilesize,
        10 : getparams_getfiletime,
        11 : getparams_getfiletype,
        12 : getparams_movefile,
        13 : getparams_lockfile,
        14 : getparams_removedirectory,
        15 : getparams_setendoffile,
        16 : getparams_setfileattributes,
        17 : getparams_setfileinformationbyhandle,
        18 : getparams_setfiletime,
        19 : getparams_setfilevaliddata,
        20 : getparams_setnamedsecurityinfo,
        21 : getparams_unlockfile,
        22 : getparams_readfile,
        23 : getparams_listdirectory,
        24 : getparams_copydirectory,
        25 : getparams_createjunction,
        26 : getparams_copyjunction,
    }
    paramfunc = paramfuncs.get(cid, getparams_invalidcid)
    params, data = paramfunc(data)
    return params, data

def parse(data):
    # parse calls
    call_list = list()
    while True:
        # process next call
        cid, data = getcid(data)
        call = PRPC_Call(cid)
        if cid == PRPC_ID.LISTENDCALL.value:
            call_list.append(call)
            return call_list
        # extract total length of parameters
        PARAMSSIZELEN = 4
        paramssize, data = getbytes(PARAMSSIZELEN, data)
        # process parameters of call
        params, data = getparams(cid, data)
        if params is not None:
            for param in params:
                call.appendParam(param)
        # enlist call
        call_list.append(call)


