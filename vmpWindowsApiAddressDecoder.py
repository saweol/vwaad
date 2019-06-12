#-*- encoding:utf-8 -*-
'''
Autor : JHJ
Project : VMProtect Windows Api Address Decoder
TEST Ver : IDA 7.0
'''
import idc
import idaapi
import idautils


#Set Your name
AUTOR = "JHJ"

#VMProtect Windows Api Address Decoder
class vwaad:

    vmp_list = []   #virtualization code Entrypoint
    fail_list = []
    call_list = []

    gadget_list = []

    decoded_api = []

    depth = 100



    def __init__(self, targetSeg = ".text", vmpSeg = ".vmp0"):      
        #Get Segment Info (start, end, size)
        
        if self.getVmpCallList(targetSeg, vmpSeg) is not True:
            print ("Get Call list Fail")
            return
        
        for x in self.call_list:
            result = self.functionTracer(x)
            if result is False:
                self.fail_list.append(x)
            else:
                self.gadget_list.append(result)
        self.decodeAddress()

        print("################### vmp0 Call List ###################")
        self.printCallList()

        print("################### Trace Fail List ###################")
        self.printFailList()

        print("################### Gadget List ###################")
        self.printGadget()

        print("################### Decoded Api List ###################")
        self.printDecodedApi()
    

    ############################## PRINT FUNCTION ##############################
    def printDecodedApi(self):
        for gadget in self.decoded_api:
            print ('{0} : {1} -> call {2}'.format(hex(gadget['original_addr']).rstrip('L'), gadget['original_assembly'], hex(gadget['decoded_address']).rstrip("L")))
        
        print ("")

    def printGadget(self):
        idx = 0
        print ("gadget_list")
        for gadget in self.gadget_list:
            print ('gadget address : {0}'.format(hex(gadget[0]['entrypoint']).rstrip('L')))
            for y in gadget:
                print( '{0} {1} : {2} '.format(y['flow'],hex(y['addr']).rstrip('L'), y['gadget']))
            print ("")
            data = 0
        print ("")
    
    def printCallList(self):
        print ("call_list")
        for x in self.call_list:
            print hex(x).rstrip("L"), 
        print ("")
    
    def printFailList(self):
        print ("fail_list")
        for x in self.fail_list:
            print hex(x).rstrip("L"),
        print ("")
    
    ############################## UTILITY FUNCTION ##############################

    '''
    patch script for ollydbg
    arg : None
    return : None
    '''
    def patchOllyScript(self):
        for gadget in self.decoded_api:
            print ('asm {0}, \"call {1}\"'.format(hex(gadget['original_addr']).rstrip("L").lstrip("0x"), 
                hex(gadget['decoded_address']).rstrip("L")))
    

    '''
    Verify that eip is in the vmp segment.
    arg : eip, vmp segment address, vmp segment end address
    return : Ture/False
    '''
    def checkAddrInSegment(self, eip, vmp_ea, vmp_end):
        if eip > vmp_ea and eip < vmp_end:
            return True
        else:
            return False

    ############################## GET DATA FUNCTION ##############################
    '''
    Collect All calls thet .vmp0 from .text
    arg : targetSeg Address, vmpSeg Address
    return : True

    '''
    def getVmpCallList(self, targetSeg, vmpSeg):
        idx = 0
        addr = 0
        dis_ea, dis_end, dis_size = self.getSegName(targetSeg)   
        vmp_ea, vmp_end, vmp_size = self.getSegName(vmpSeg)

        
        while dis_ea < dis_end:
            if idc.GetDisasm(dis_ea)[:4] == "call":
                addr = get_operand_value(dis_ea,0)
                if self.checkAddrInSegment(addr, vmp_ea, vmp_end) is True:
                    idx = idx + 1
                    self.vmp_list.append(addr)
                    self.call_list.append(dis_ea)

            dis_ea = idc.NextHead(dis_ea)
        
        return True

    
    
    '''
    Function Tracing without conditional branching
    arg : function address, debug falg
    return : gadget list / False
    '''
    def functionTracer(self, addr, debug = False):
        idx = 0
        depth = self.depth
        result = []
        ep = addr
        
        while idx < depth:
            idx = idx + 1
            if debug is True:
                print( '{0} {1} {2} {3}'.format(idx, hex(addr), idc.GetDisasm(addr), hex(get_operand_value(addr,0)) ))
            
            if idc.GetDisasm(addr)[:4] == "retn":
                break
            
            elif idc.GetDisasm(addr)[:3] == "jmp" or idc.GetDisasm(addr)[:4] == "call":
                #print get_operand_value(addr,0)
                addr = get_operand_value(addr,0)
            
            elif self.findFirstGadget(addr) == True:
                if len(result) > 0:
                    result = []
                result.append(self.getGadget(addr, ep, 1))
                addr = idc.NextHead(addr)
            
            elif len(result) == 1 and self.findSecondGadget(addr, result[0]['reg']) == True:
                #input gadget
                result.append(self.getGadget(addr,ep, 2))
                addr = idc.NextHead(addr)

            elif len(result) == 2 and self.findThirdGadget(addr, result[0]['reg']) == True:
                result.append(self.getGadget(addr,ep, 3))
                addr = idc.NextHead(addr)
            
            else:
                addr = idc.NextHead(addr)

        if len(result) == 3:
            return result
        else:
            return False

    #Utility
    '''
    Get information for a specific segment.
    arg : segment name
    return : segment start address, segment end address, segment size
    '''
    def getSegName(self, segName):
        for seg in idautils.Segments():
            if idc.SegName(seg) == segName:
                return idc.SegStart(seg), idc.SegEnd(seg), idc.SegEnd(seg) - idc.SegStart(seg)

    
    #처리 
    '''
    Find the first gadget in the form "mov R32, CONST".
    arg : address
    return : True/False
    '''
    def findFirstGadget(self, eip):
        if idc.GetDisasm(eip)[:4] == "mov ":
            if GetOpnd(eip,0)[0] == "e" and (GetOpnd(eip,1)[:7] == "(offset" or GetOpnd(eip,1)[:6] == "offset" or GetOpnd(eip,1)[-1] == "h"):
                return True
            else:
                return False
        else:
            return False

    '''
    Find the second gadget in the form "mov R32, [R32 + CONST]".
    arg : address, register
    return : True/False
    '''
    def findSecondGadget(self, eip,reg):
        
        if idc.GetDisasm(eip)[:4] == "mov ":
            if GetOpnd(eip,0) == reg and (GetOpnd(eip,1)[:2] == "[e" or GetOpnd(eip,1)[:-2] == "h]"):
                return True
            else:
                return False
        else:
            return False

    '''
    Find the third gadget in the form "lea R32, [R32 + CONST]".
    arg : address, register
    return : True/False
    '''
    def findThirdGadget(self, eip,reg):
        if idc.GetDisasm(eip)[:4] == "lea ":
            if GetOpnd(eip,0) == reg and (GetOpnd(eip,1)[:2] == "[e" or GetOpnd(eip,1)[:-2] == "h]"):
                return True
            else:
                return False
        else:
            return False
    
    '''
    get gadget from address
    arg : address, entrypoint address, gadget number
    return : True/False
    '''
    def getGadget(self, eip, ep, flow):
        return dict({ 'flow' : flow,'entrypoint' :ep, 'addr': eip, 'gadget': idc.GetDisasm(eip), 'reg': GetOpnd(eip,0), 'const': get_operand_value(eip,1)})
    
    '''
    decode address from gadget
    arg : None
    return : None
    '''
    def decodeAddress(self):
        idx = 0
        data = 0

        for gadget in self.gadget_list:
            for y in gadget:
                if y['flow'] == 2:
                    data = next(GetDataList(data + y['const'],1, itemsize=4))
                else:
                    data = data + y['const']

            data = data & 0xFFFFFFFF
            self.decoded_api.append(dict( \
                {'original_addr' : gadget[0]['entrypoint'], \
                'original_assembly' : idc.GetDisasm(gadget[0]['entrypoint']), \
                'decoded_address' : data}))
            data = 0





