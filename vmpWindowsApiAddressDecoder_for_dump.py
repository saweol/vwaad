import idautils
import idc
import idaapi

vmp_list = []
fail_list = []
call_list = []
gadget_list = []
dummy_gadget_list = []
dummy_fail_list = []
dummy_patch_list = []
decoded_api = []

depth = 300

_t = ".text"
_s = ".vmp0"


def getVmpCallList(targetSeg, vmpSeg):
    idx = 0
    addr = 0
    dis_ea, dis_end, dis_size = getSegName(targetSeg)
    vmp_ea, vmp_end, vmp_size = getSegName(vmpSeg)
    while dis_ea < dis_end:
        if idc.GetDisasm(dis_ea)[:4] == "call":
            addr = get_operand_value(dis_ea, 0)
            if checkAddrInSegment(addr, vmp_ea, vmp_end) is True:
                idx = idx + 1
                vmp_list.append(addr)
                call_list.append(dis_ea)
        dis_ea = idc.next_head(dis_ea)
    return True


def getSegName(segName):
    print(segName)
    for seg in idautils.Segments():
        print(idc.get_segm_name(seg))
        if idc.get_segm_name(seg) == segName:
            return idc.get_segm_start(seg), idc.get_segm_end(seg), idc.get_segm_end(seg) - idc.get_segm_start(seg)


def getGadget(eip, ep, flow):
    return dict({'flow': flow, 'entrypoint': ep, 'addr': eip, 'gadget': idc.GetDisasm(eip), 'reg': idc.print_operand(eip, 0), 'const': get_operand_value(eip, 1)})


def checkAddrInSegment(eip, vmp_ea, vmp_end):
    if eip > vmp_ea and eip < vmp_end:
        return True
    else:
        return False


def findFirstDummyGadget(eip):
    if idc.GetDisasm(eip)[:4] == "mov ":
        if idc.print_operand(eip, 0)[0] == "e" and idc.print_operand(eip, 1)[:5] == "[esp+":
            print("FIRST MATCH TRUE", idc.GetDisasm(eip))
            return True
        else:
            return False
    else:
        return False


def findSecondDummyGadget(eip, reg):
    if idc.GetDisasm(eip)[:4] == "lea ":
        if idc.print_operand(eip, 0) == reg and idc.print_operand(eip, 1)[1:4] == reg and idc.print_operand(eip, 1)[-3:] == "+1]":
            return True
        else:
            return False
    else:
        return False


def findThirdDummyGadget(eip, reg):
    if idc.GetDisasm(eip)[:4] == "mov ":
        if idc.print_operand(eip, 0)[:5] == "[esp+" and idc.print_operand(eip, 1) == reg:
            return True
        else:
            return False
    else:
        return False


def functionDummyTracer(addr, debug=False):
    idx = 0
    result = []
    ep = addr

    dummy = False

    while idx < depth:
        idx = idx + 1
        # print( 'DUMMY : {0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'), idc.GetDisasm(addr), hex(get_operand_value(addr,0)) ))
        if debug is True:
            print(('{0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'),
                  idc.GetDisasm(addr), hex(get_operand_value(addr, 0)))))

        # dummy = findDummyGadget(addr)

        if idc.GetDisasm(addr)[:4] == "retn":
            break

        elif idc.GetDisasm(addr)[:3] == "jmp" or idc.GetDisasm(addr)[:4] == "call":
            # print get_operand_value(addr,0)
            addr = get_operand_value(addr, 0)

        elif findFirstDummyGadget(addr) == True:
            # print "MATCH FIRST"
            if len(result) > 0:
                result = []
            result.append(getGadget(addr, ep, 1))
            addr = idc.next_head(addr)

        elif len(result) == 1 and findSecondDummyGadget(addr, result[0]['reg']) == True:
            # input gadget
            result.append(getGadget(addr, ep, 2))
            addr = idc.next_head(addr)

        elif len(result) == 2 and findThirdDummyGadget(addr, result[0]['reg']) == True:
            result.append(getGadget(addr, ep, 3))
            addr = idc.next_head(addr)

        else:
            addr = idc.next_head(addr)

    if debug is True and len(result) > 0:
        for x in result:
            print(("{0} : {1} {2} ".format(
                hex(x['addr']).rstrip('L'), hex(x['const']), x['gadget'])))

    print("")
    if len(result) == 3:
        return result
    else:
        return False


def findFirstGadget(eip):
    if idc.GetDisasm(eip)[:4] == "mov ":
        if idc.print_operand(eip, 0)[0] == "e" and (idc.print_operand(eip, 1)[:7] == "(offset" or idc.print_operand(eip, 1)[:6] == "offset" or idc.print_operand(eip, 1)[-1] == "h"):
            return True
        else:
            return False
    else:
        return False


def findSecondGadget(eip, reg):
    if idc.GetDisasm(eip)[:4] == "mov ":
        if idc.print_operand(eip, 0) == reg and (idc.print_operand(eip, 1)[:2] == "[e" or idc.print_operand(eip, 1)[:-2] == "h]"):
            return True
        else:
            return False
    else:
        return False


def findThirdGadget(eip, reg):
    if idc.GetDisasm(eip)[:4] == "lea ":
        if idc.print_operand(eip, 0) == reg and (idc.print_operand(eip, 1)[:2] == "[e" or idc.print_operand(eip, 1)[:-2] == "h]"):
            return True
        else:
            return False
    else:
        return False


def functionTracer(addr, debug=False):
    idx = 0
    result = []
    ep = addr

    dummy = False

    while idx < depth:
        idx = idx + 1
        if debug is True:
            print(('{0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'),
                  idc.GetDisasm(addr), hex(get_operand_value(addr, 0)))))

        #dummy = findDummyGadget(addr)

        if idc.GetDisasm(addr)[:4] == "retn":
            break

        elif idc.GetDisasm(addr)[:3] == "jmp" or idc.GetDisasm(addr)[:4] == "call":
            # print get_operand_value(addr,0)
            addr = get_operand_value(addr, 0)

        elif findFirstGadget(addr) == True:
            if len(result) > 0:
                result = []
            result.append(getGadget(addr, ep, 1))
            addr = idc.next_head(addr)

        elif len(result) == 1 and findSecondGadget(addr, result[0]['reg']) == True:
            # input gadget
            result.append(getGadget(addr, ep, 2))
            addr = idc.next_head(addr)

        elif len(result) == 2 and findThirdGadget(addr, result[0]['reg']) == True:
            result.append(getGadget(addr, ep, 3))
            addr = idc.next_head(addr)

        else:
            addr = idc.next_head(addr)

    if debug is True and len(result) > 0:
        for x in result:
            print(("{0} : {1} {2} ".format(
                hex(x['addr']).rstrip('L'), hex(x['const']), x['gadget'])))

    if len(result) == 3:
        return result
    else:
        return False


def idaBytePatch(addr, opcode):
    idc.patch_byte(addr, opcode)


def patchDummyCode():
    for x in dummy_patch_list:
        idaBytePatch(x, 0x90)


def printDecodedApi():
    for gadget in decoded_api:
        print(('{0} : {1} -> call {2}'.format(hex(gadget['original_addr']).rstrip(
            'L'), gadget['original_assembly'], hex(gadget['decoded_address']).rstrip("L"))))
    print("")


def printGadget():
    idx = 0
    print("gadget_list")
    for gadget in gadget_list:
        print(('gadget address : {0}'.format(
            hex(gadget[0]['entrypoint']).rstrip('L'))))
        for y in gadget:
            print(('{0} {1} : {2} '.format(y['flow'], hex(
                y['addr']).rstrip('L'), y['gadget'])))
        print("")
        data = 0
    print("")


def printCallList():
    print("call_list")
    for x in call_list:
        print(hex(x).rstrip("L"), end=' ')
    print("")


def printFailList():
    print("fail_list")
    for x in fail_list:
        print(hex(x).rstrip("L"), end=' ')
    print("")


def printDebugFailList():
    print("Debug Fail List")

    for x in fail_list:
        functionTracer(x, debug=True)
        print("")


def printDebugDummyFailList():
    print("Debug Fail List")

    for x in dummy_fail_list:
        functionDummyTracer(x, debug=True)
        print("")


def printDummyGadget():
    idx = 0
    print("gadget_list")
    for gadget in dummy_gadget_list:
        print(('DUMMY gadget address : {0}'.format(
            hex(gadget[0]['entrypoint']).rstrip('L'))))
        # dummy_patch_list.append(hex(gadget[0]['entrypoint']).rstrip('L')+5)
        for y in gadget:
            print(('{0} {1} : {2} '.format(y['flow'], hex(
                y['addr']).rstrip('L'), y['gadget'])))
        print("")
        data = 0
    print("")


def printDebugFailList():
    print("Debug Fail List")

    for x in fail_list:
        functionTracer(x, debug=True)
        print("")


def decodeAddress():
    idx = 0
    data = 0

    for gadget in gadget_list:
        for y in gadget:
            if y['flow'] == 2:
                data = next(GetDataList(data + y['const'], 1, itemsize=4))
            else:
                data = data + y['const']

        data = data & 0xFFFFFFFF
        decoded_api.append(dict(
            {'original_addr': gadget[0]['entrypoint'],
             'original_assembly': idc.GetDisasm(gadget[0]['entrypoint']),
             'decoded_address': data}))
        data = 0


if getVmpCallList(_t, _s) is not True:
    print("Get Call list Fail 1")
else:
    for x in call_list:
        print("")
        result = functionDummyTracer(x)
        if result is False:
            dummy_fail_list.append(x)
        else:
            if idaapi.get_bytes(x + 5, 1) != '\x90':
                dummy_patch_list.append(x + 5)
                dummy_gadget_list.append(result)
            else:
                dummy_patch_list.append(x + 5)
                dummy_gadget_list.append(result)


patchDummyCode()
call_list = []

if getVmpCallList(_t, _s) is not True:
    print("Get Call list Fail 2")
else:
    for x in call_list:
        print("")
        result = functionDummyTracer(x)
        if result is False:
            dummy_fail_list.append(x)
        else:
            if idaapi.get_bytes(x + 5, 1) != '\x90':
                dummy_patch_list.append(x + 5)
                dummy_gadget_list.append(result)

patchDummyCode()
call_list = []

if getVmpCallList(_t, _s) is not True:
    print("Get Call list Fail 3")
else:
    for x in call_list:
        result = functionTracer(x)
        if result is False:
            fail_list.append(x)
        else:
            gadget_list.append(result)
    decodeAddress()

    print("################### vmp0 Call List ###################")
    printCallList()

    print("################### Trace Fail List ###################")
    printFailList()

    print("################### Gadget List ###################")
    printGadget()

    print("################### Decoded Api List ###################")
    printDecodedApi()

    print("################### Decoded Dummy Api List ###################")
    printDummyGadget()

    for x in dummy_patch_list:
        print(hex(x).rstrip('L'))

print("ok :)")
