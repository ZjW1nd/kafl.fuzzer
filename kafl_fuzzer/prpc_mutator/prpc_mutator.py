#!/usr/bin/env python3

import random
import sys
# import logging
import types
import string

from prpc_call import *
from prpc_datafile_reader import *
from prpc_datafile_writer import *

from common.debug import log_prpc

# logging.basicConfig(filename='prpc.log', level=logging.INFO)
# logger = logging.getLogger("prpc_mutator")

################################################################################

MODCHANCE=.1
CSTRMAXLEN=32
PATHMAXLEN=32
RANDOMNULLPOINTERS=True
RANDOMNULLPOINTERCHANCE=0.5
CSTRCHANGELENTHCHANCE=1
LPCHANGELENGTHCHANCE=1

DELETECALLCHANCE = .1
ADDCALLCHANCE = .4

################################################################################

ORIGPATHPOOL = [
    b'Z:\\',
    b'Z:\\folder1\\',
    b'Z:\\folder1\\testfile123.txt',
    b'Z:\\folder1\\testfile567.txt',
    b'Z:\\folder1\\testfile568.txt',
    b'Z:\\folder1\\testfile5600.txt',
    b'Z:\\folder1\\testfile5612.txt',
    b'Z:\\folder1\\testfile5699.txt',
    b'Z:\\folder1\\testfile56607.txt',
    b'Z:\\folder1\\testfile5670000.txt',
    b'Z:\\folder1\\testfile56799999.txt',
    b'Z:\\folder2\\',
    b'Z:\\folder2\\88888888888.txt',
    b'Z:\\folder2\\444444444444.txt',
    b'Z:\\folder2\\7777777777777.txt',
    b'Z:\\folder2\\3333333333333333.txt',
    b'Z:\\folder2\\5555555555555555.txt',
    b'Z:\\folder2\\9999999999999999.txt',
    b'Z:\\folder2\\1010101010101010101010.txt',
    b'Z:\\folder2\\1111111111111111111.txt',
    b'Z:\\folder2\\2222222222222222222.txt',
    b'Z:\\folder2\\666666666666666666666.txt',
    b'Z:\\folder2\\asdfasdf.txt',
    b'Z:\\folder2\\cccccccc.txt',
    b'Z:\\folder2\\ddddddddddd.txt',
    b'Z:\\folder2\\eeeeeeeeeeeeeee.txt',
    b'Z:\\folder2\\ffffffffffffffffff.txt',
    b'Z:\\folder2\\testfile567aaaaaaaaa.txt',
    b'Z:\\folder2\\testfile567bbbbbbbbb.txt',
    b'Z:\\folder2\\testfile887.txt',
    b'Z:\\folder2\\testfile6677.txt',
    b'Z:\\asdfdf.txt',
    b'Z:\\ddfffffffffffffff.txt',
    b'Z:\\eeeeeeeeeee.txt',
    b'Z:\\fffffffffffffff.txt',
    b'Z:\\ggggggggggggg.txt',
    b'Z:\\hhhhhhhhhhhhhh.txt',
    b'Z:\\iiiiiiiiiiiiiiiiiiiiii.txt',
    b'Z:\\jjjjjjjjjjjjjjjjjj.txt',
    b'Z:\\kkkkkkkkkkkkk.txt',
    b'Z:\\lllllllllllllllll.txt',
    b'Z:\\mmmmmmmmmm.txt',
    b'Z:\\nnnnnnnnnnnnnn.txt',
    b'Z:\\oooooooooooooo.txt',
    b'Z:\\ppppppppppppp.txt',
    b'Z:\\testfil5.txt', # sic!
    b'Z:\\testfil6.txt', # sic!
    b'Z:\\testfile1.txt',
    b'Z:\\testfile2.txt',
    b'Z:\\testfile3.txt',
    b'Z:\\testfile4.txt',
    b'Z:\\testfile7.txt',
    b'Z:\\testfile8.txt',
    b'Z:\\testfile12.txt',
    b'Z:\\testfile19.txt',
]

pathpool = ORIGPATHPOOL

def set_pathpool(pathp):
    global pathpool
    pathpool = pathp

# NOTE: gen and kill lists are quite generic
#       No case adds/removes more than one path
def updatepathpool(call):
    params = call.params
    # indices for gen path params (left) and kill path params (right)
    genkillswitch = {
         1 : [[0],[ ]], # createdirectory
         2 : [[0],[ ]], # createfile
         4 : [[1],[ ]], # createsymboliclink
         5 : [[1],[ ]], # copyfile
         6 : [[ ],[0]], # deletefile
        12 : [[1],[0]], # movefile
        14 : [[ ],[0]], # removedirectory
        24 : [[0],[ ]], # copydirectory
        25 : [[1],[ ]], # createjunction
        26 : [[1],[ ]], # copyjunction
    }
    genkillindices = genkillswitch.get(call.cid, [[],[]])
    genlist  = [params[x].value[:-1] for x in genkillindices[0]]
    killlist = [params[x].value[:-1] for x in genkillindices[1]]
    # logger.debug(str(call)+"\nGEN: "+str(genlist)+",\nKILL: "+str(killlist))

    killlist = list(filter(lambda x: x != b'', killlist ))
    genlist = list(filter(lambda x: x != b'', genlist ))

    for kill in killlist:
        if kill not in pathpool:
            # can happen if a delete call changes the path param
            # maybe implement path check of every param in the future
            log_prpc("Attempt to remove non-existant "+str(kill)+" from pathpool")
        else:
            pathpool.remove(kill)
    pathpool.extend(genlist)


################################################################################

def modisnullptr(orig):
    if RANDOMNULLPOINTERS and random.uniform(0,1) < RANDOMNULLPOINTERCHANCE:
        # NOTE: Un-nullifying a real NULL-Pointer is a bad idea
        # return not orig
        return True
    return orig

# create random bytearray
def createrandombytes(length):
    rand = ''
    for _ in range(length):
        rand += chr(random.getrandbits(8))
    return rand

# create C string of specified length (including NULL-byte)
def createrandcstr(length):
    randstr = bytearray(createrandombytes(length-1))
    # avoid premature NULL bytes
    for i in range(len(randstr)):
        while randstr[i] == 0:
            randstr[i] = random.getrandbits(8)
    # terminate C string
    randstr = str(randstr) + b'\x00'
    return randstr

def modifyCStrParam(param, new, *others):
    length = param.size
    if random.uniform(0,1) < CSTRCHANGELENTHCHANCE or new:
        length = random.randint(1,CSTRMAXLEN-1)
    randstr = createrandcstr(length)
    if modisnullptr(False):
        modparam = PRPC_CStrParam(0, True, b'')
    else:
        modparam = PRPC_CStrParam(len(randstr), False, randstr)
    return modparam

def random_file_or_folder():
    if len(pathpool):
        return random.choice(pathpool)
    return ""

def random_file():
    files = list(filter(lambda path: not path.endswith(b'\\'), pathpool))
    if len(files):
        return random.choice(files)
    return ""

def random_folder():
    folders = list(filter(lambda path: path.endswith(b'\\'), pathpool))
    if len(folders):
        return random.choice(folders)
    return ""

def new_file():
    parent_folder = random_folder()
    filename = ''.join([random.choice(string.ascii_uppercase + string.digits) for _ in range(6)])
    return parent_folder + filename

def new_folder():
    return new_file() + b'\\'

def modifyPathParam(param, new, cid, pindex):
    gen_func = {
         1 : [new_folder,], # createdirectory
         2 : [new_file,], # createfile
         4 : [new_file, random_file_or_folder], # createsymboliclink
         5 : [random_file, new_file], # copyfile
         6 : [random_file], # deletefile
        12 : [random_file, new_file], # movefile
        14 : [random_folder], # removedirectory
        22 : [random_file],
        23 : [random_folder],
        24 : [random_folder, new_folder], # copydirectory
        25 : [new_folder, random_folder], # createjunction
    }
    path_func = gen_func.get(cid, random_file_or_folder)

    if isinstance(path_func, types.FunctionType):
        path = path_func()
    else:
        path = path_func[pindex]()

    if modisnullptr(param.isnullptr):
        modparam = PRPC_PathParam(0, True, b'')
    else:
        modparam = PRPC_PathParam(len(path)+1, False, path + b'\x00')
    return modparam

def modifyLPParam(param, new, *others):
    length = param.size
    if random.uniform(0,1) < LPCHANGELENGTHCHANCE or new:
        length = random.randint(1,CSTRMAXLEN-1)
    randcstr = createrandcstr(length)
    if modisnullptr(False):
        modparam = PRPC_LPParam(0, True, b'')
    else:
        modparam = PRPC_LPParam(len(randcstr), False, randcstr)
    return modparam

def modifyuintParam(param, *others):
    # NOTE: param.size should always match
    modvalue = createrandombytes(param.size)
    modparam = PRPC_uintParam(param.size, False, modvalue)
    return modparam

def modifyllParam(param, *others):
    # NOTE: param.size should always match
    modvalue = createrandombytes(param.size)
    modparam = PRPC_llParam(param.size, False, modvalue)
    return modparam

def invalidparammodifier(param, *others):
    raise Exception("Invaild PRPC_Param subclass not implemented yet: "+str(param.__class__))


def modifyparam(param, init, cid, pindex):
    modifiers = {
        PRPC_CStrParam : modifyCStrParam,
        PRPC_PathParam : modifyPathParam,
        PRPC_LPParam   : modifyLPParam,
        PRPC_uintParam : modifyuintParam,
        PRPC_llParam   : modifyllParam,
    }
    modifier = modifiers.get(param.__class__, invalidparammodifier)
    param = modifier(param, init, cid, pindex)
    return param

################################################################################


def modifycall(call):
   paramsbak = call.params[:]
   # modifiy parameters
   params = call.params
   for pi in range(len(params)):
       param = params[pi]
       if random.uniform(0,1) < MODCHANCE:
           parambak = param
           params[pi] = modifyparam(param, False, call.cid, pi)
           log_prpc("modified\n\t"+str(parambak)+"\n\tto\n\t"+str(params[pi])+'\n\tin\n\t'+str(call))

def create_random_call():
    call = None
    cid = PRPC_ID.LISTENDCALL.value
    while cid == PRPC_ID.LISTENDCALL.value or \
          cid == PRPC_ID.CREATENAMEDPIPE.value or \
          cid == PRPC_ID.SETNAMEDSECURITYINFO.value or \
          cid == PRPC_ID.SETFILEINFORMATIONBYHANDLE.value or\
          cid == PRPC_ID.COPYJUNCTION.value:
        cid = random.choice(list(PRPC_ID)).value

    call = PRPC_Call(cid)
    call.add_dummy_params()
    for pi in range(len(call.params)):
        param = call.params[pi]
        call.params[pi] = modifyparam(param, True, call.cid, pi)

    return call

################################################################################

def usage(scriptname):
    print("usage: "+scriptname+" <infile> <outfile>")
    print("Read in payload file, modify calls, and write to outfile")
    sys.exit(1)

def get_mutated_calls(del_chance, calls):
    log_prpc("mutate calls")
    new_calls = list()
    for call in calls:
        if call.cid == PRPC_ID.LISTENDCALL.value:
            new_calls.append(call)
            break

        if random.uniform(0,1) < del_chance:
            log_prpc("deleted\n\t"+str(call))
        else:
            modifycall(call)
            new_calls.append(call)
            updatepathpool(call)

        if random.uniform(0,1) < ADDCALLCHANCE:
            new_call = create_random_call()
            log_prpc("added\n\t"+str(new_call))
            new_calls.append(new_call)
            updatepathpool(new_call)

    return new_calls

def main():
    global DELETECALLCHANCE
    if len(sys.argv) != 3:
        usage(sys.argv[0])
    data = readfile(sys.argv[1])
    calls = parse(data)
    new_calls = list()

    default_del_chance = DELETECALLCHANCE
    if len(calls) > 30:
        DELETECALLCHANCE = .5

    for call in calls:
        if call.cid == PRPC_ID.LISTENDCALL.value:
            new_calls.append(call)
            break


        if random.uniform(0,1) < DELETECALLCHANCE:
            log_prpc("deleted\n\t"+str(call))
        else:
            modifycall(call)
            new_calls.append(call)
            updatepathpool(call)

        if random.uniform(0,1) < ADDCALLCHANCE:
            new_call = create_random_call()
            log_prpc("added\n\t"+str(new_call))
            new_calls.append(new_call)
            updatepathpool(new_call)


    DELETECALLCHANCE = default_del_chance
    writefile(new_calls, sys.argv[2])

if __name__ == '__main__':
    main()

