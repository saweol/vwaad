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
    dummy_gadget_list = []
    dummy_fail_list = []

    dummy_patch_list = []

    decoded_api = []

    depth = 300



    def __init__(self, targetSeg = ".text", vmpSeg = ".vmp0"):      
        #Get Segment Info (start, end, size)
        self.vmpSeg = ".asp0"
        vmpSeg = ".asp0"
        if self.getVmpCallList(targetSeg, vmpSeg) is not True:
            print ("Get Call list Fail")
            return
        
        for x in self.call_list:
            print ""
            result = self.functionDummyTracer(x)
            if result is False:
                self.dummy_fail_list.append(x)
            else:
                if idaapi.get_bytes(x + 5,1) != '\x90':
                    self.dummy_patch_list.append(x + 5)
                    self.dummy_gadget_list.append(result)
                else:
                    self.dummy_patch_list.append(x + 5)
                    self.dummy_gadget_list.append(result)
        
        self.patchDummyCode()
        
        self.call_list = []

        if self.getVmpCallList(targetSeg, vmpSeg) is not True:
            print ("Get Call list Fail")
            return
        #self.dummy_patch_list = []
        #self.dummy_gadget_list = []

        for x in self.call_list:
            print ""
            result = self.functionDummyTracer(x)
            if result is False:
                self.dummy_fail_list.append(x)
            else:
                if idaapi.get_bytes(x + 5,1) != '\x90':
                    self.dummy_patch_list.append(x + 5)
                    self.dummy_gadget_list.append(result)
                '''
                else:
                    self.dummy_patch_list.append(x + 5)
                    self.dummy_gadget_list.append(result)
                '''
        
        self.patchDummyCode()
        self.call_list = []

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
        
        print("################### Decoded Dummy Api List ###################")
        self.printDummyGadget()

        for x in self.dummy_patch_list:
            print hex(x).rstrip('L')
    

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
    
    def printDebugFailList(self):
        print ("Debug Fail List")

        for x in self.fail_list:
            self.functionTracer(x, debug = True)
            print ("")
    
    def printDebugDummyFailList(self):
        print ("Debug Fail List")

        for x in self.dummy_fail_list:
            self.functionDummyTracer(x, debug = True)
            print ("")


    ############################## PRINT DUMMY FUNCTION ##############################

    def printDummyGadget(self):
        idx = 0
        print ("gadget_list")
        for gadget in self.dummy_gadget_list:
            print ('DUMMY gadget address : {0}'.format(hex(gadget[0]['entrypoint']).rstrip('L')))
            #self.dummy_patch_list.append(hex(gadget[0]['entrypoint']).rstrip('L')+5)
            for y in gadget:
                print( '{0} {1} : {2} '.format(y['flow'],hex(y['addr']).rstrip('L'), y['gadget']))
            print ("")
            data = 0
        print ("")
    
    def printDebugFailList(self):
        print ("Debug Fail List")

        for x in self.fail_list:
            self.functionTracer(x, debug = True)
            print ("")
    
    ############################## UTILITY FUNCTION ##############################

    '''
    patch script for ollydbg
    arg : None
    return : None
    '''
    def getbyte_test(self,addr,size):
        if get_bytes(addr, size) == '\x90':
            print data
        else:
            print "NONONO"
        

    def patchOllyScript(self):
        for gadget in self.decoded_api:
            print ('asm {0}, \"call {1}\"'.format(hex(gadget['original_addr']).rstrip("L").lstrip("0x"), 
                hex(gadget['decoded_address']).rstrip("L")))
    
    def patchDummyOllyScript(self):
        for gadget in self.dummy_patch_list:
            print ('fill {0}, 1, 90'.format(hex(gadget).rstrip("L").lstrip("0x")))
    
    

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

        dummy = False
        
        while idx < depth:
            idx = idx + 1
            if debug is True:
                print( '{0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'), idc.GetDisasm(addr), hex(get_operand_value(addr,0)) ))

            #dummy = self.findDummyGadget(addr)

            
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
        
        if debug is True and len(result) > 0:
            for x in result:
                print ("{0} : {1} {2} ".format(hex(x['addr']).rstrip('L'), hex(x['const']), x['gadget']  ))
            

        if len(result) == 3:
            return result
        else:
            return False

    
    '''
    Function Tracing without conditional branching
    arg : function address, debug falg
    return : gadget list / False
    '''
    def functionDummyTracer(self, addr, debug = False):
        idx = 0
        depth = self.depth
        result = []
        ep = addr

        dummy = False

        
        
        
        while idx < depth:
            idx = idx + 1
            #print( 'DUMMY : {0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'), idc.GetDisasm(addr), hex(get_operand_value(addr,0)) ))
            if debug is True:
                print( '{0} {1} {2} {3}'.format(idx, hex(addr).rstrip('L'), idc.GetDisasm(addr), hex(get_operand_value(addr,0)) ))

            #dummy = self.findDummyGadget(addr)


            
            if idc.GetDisasm(addr)[:4] == "retn":
                break
            
            elif idc.GetDisasm(addr)[:3] == "jmp" or idc.GetDisasm(addr)[:4] == "call":
                #print get_operand_value(addr,0)
                addr = get_operand_value(addr,0)
            
            elif self.findFirstDummyGadget(addr) == True:
                #print "MATCH FIRST"
                if len(result) > 0:
                    result = []
                result.append(self.getGadget(addr, ep, 1))
                addr = idc.NextHead(addr)

            elif len(result) == 1 and self.findSecondDummyGadget(addr, result[0]['reg']) == True:
                #input gadget
                result.append(self.getGadget(addr,ep, 2))
                addr = idc.NextHead(addr)

            elif len(result) == 2 and self.findThirdDummyGadget(addr, result[0]['reg']) == True:
                result.append(self.getGadget(addr,ep, 3))
                addr = idc.NextHead(addr)
            
            else:
                addr = idc.NextHead(addr)
        
        if debug is True and len(result) > 0:
            for x in result:
                print ("{0} : {1} {2} ".format(hex(x['addr']).rstrip('L'), hex(x['const']), x['gadget']  ))
            


        print ""
        if len(result) == 3:
            return result
        else:
            return False


    #Utility

    def fullMakeCode(self):
        segStart, segEnd, segSize = self.getSegName('.text')

        eip = segStart

        while eip < segEnd:
            MakeCode(eip)
            eip = NextHead(eip)



    def patchDummyCode(self):
        for x in self.dummy_patch_list:
            self.idaBytePatch(x,0x90)

    def idaBytePatch(self,addr, opcode):
        PatchByte(addr, opcode)
    '''
    Get information for a specific segment.
    arg : segment name
    return : segment start address, segment end address, segment size
    '''
    def getSegName(self, segName):
        for seg in idautils.Segments():
            if idc.SegName(seg) == segName:
                return idc.SegStart(seg), idc.SegEnd(seg), idc.SegEnd(seg) - idc.SegStart(seg)

    
    #API 가젯 처리 
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
    
    #Dummy 가젯 처리 
    '''
    DummyGadget
    10062696    8B4424 30                      MOV EAX,DWORD PTR SS:[ESP+30]
    10069014    8D80 01000000                  LEA EAX,DWORD PTR DS:[EAX+1]
    10069028    894424 38                      MOV DWORD PTR SS:[ESP+38],EAX
    '''

    '''
    Find the first dummy gadget in the form "mov R32, [ESP+CONST]".
    arg : address
    return : True/False
    '''
    def findFirstDummyGadget(self, eip):
        
        if idc.GetDisasm(eip)[:4] == "mov ":
            if GetOpnd(eip,0)[0] == "e" and GetOpnd(eip,1)[:5] == "[esp+":
                print "FIRST MATCH TRUE", idc.GetDisasm(eip)
                return True
            else:
                return False
        else:
            return False

    '''
    Find the second gadget in the form "lea R32, [R32 + 1]".
    arg : address, register
    return : True/False
    '''
    def findSecondDummyGadget(self, eip,reg):
        if idc.GetDisasm(eip)[:4] == "lea ":
            if GetOpnd(eip,0) == reg and GetOpnd(eip,1)[1:4] == reg and GetOpnd(eip,1)[-3:] == "+1]":
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
    def findThirdDummyGadget(self, eip,reg):
        
        if idc.GetDisasm(eip)[:4] == "mov ":
            if GetOpnd(eip,0)[:5] == "[esp+" and GetOpnd(eip,1) == reg:
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
    
    '''
    DummyGadget
    10062696    8B4424 30                      MOV EAX,DWORD PTR SS:[ESP+30]
    10069014    8D80 01000000                  LEA EAX,DWORD PTR DS:[EAX+1]
    10069028    894424 38                      MOV DWORD PTR SS:[ESP+38],EAX
    '''

    '''
    def findDummyGadget(self,eip):
        idx = 0
        data = 0

        disass = idc.GetDisasm(eip)
        print ("[DEBUG] DUMMY VALUE FIND : {0} : {1}\t{2}\t{3}".format(hex(eip).rstrip('L'), disass, GetOpnd(eip,0), GetOpnd(eip,1)))

        if disass[:4] == "lea" and (GetOpnd(eip,0)[:2] == "e" and GetOpnd(eip,1)[:2] == "[e" and GetOpnd(eip,1)[:-3] == "+1]"):
            print ("[DEBUG] DUMMY VALUE FIND : {0} : {1}\t{2}\t{3}".format(hex(eip).lstrip('L'), disass, GetOpnd(eip,1), GetOpnd(eip,1)))
            return True
        else:
            return False
    '''




