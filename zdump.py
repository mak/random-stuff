import os,sys,re
from struct import *
V_DIR = 'c:\\vivisect'
sys.path.append('.')
sys.path.append(V_DIR)
#sys.path.append('c:\\Python2.7\')
import vtrace,vstruct,envi
import envi.archs.i386 as e_i386
from vtrace.platforms.win32 import *
from envi.archs.i386.disasm import i386Disasm
from envi.archs.i386.regs import i386regs as regs

import PE
from ctypes import *
from hashlib import md5
import socket,base64,json

#PSAPI.DLL
psapi = windll.psapi
#Kernel32.DLL
kernel = windll.kernel32
BPADDRESSES = set()
HITS = set()
RC4 = {}
CFG={}
T = None
IE = None

# class PESettings(Structure):
#     compId = None
#     _have_data = False
#     _pack_ = 1
#     _fields_ = 
[('size',c_dword),('_compId',c_wchar*60),('guid',c_char*0x10),('_RC4KEY',c_byte*0x102),
#                 
('exeFile',c_char*20),('reportFile',c_char*20),('RegKey',c_char*10),('regDynamicConfig',c_char*10),
#                 
('regLocalConfig',c_char*10),('regLocalSettings',c_char*10),('processInfectionId',c_dword),('storageArrayKey',c_dword)
#     ]

def finish():
 if T and T.isAttached():  
  T.sendBreak()
  T.release()

 if IE: ie.Quit()
 print '[*] My work is done. bye.'
 sys.exit(1)

def send_data():
    CFG.update(RC4)
    
    s = socket.socket()
    s.connect(('195.164.49.208', 7124))
    s.send(json.dumps(CFG))
    s.close()

def visEncry(datA):
    i = len(datA)-1
    ret =map(ord,(datA))
    for idx in range(1,len(datA)):
        ret[idx] ^= ret[idx-1]
    return ''.join(map(chr,ret))


def rc4crypt(data, key):
    box = map(ord,key)
    x = 0
    y = 0
    out = []
    for byt in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(byt) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)


# def getRegs(data):
#    data = PESettings(data)
#    try:
#       key = 
win32api.RegOpenKeyEx(HKEY_CURRENT_USER,'SOFTWARE\\MICROSOFT\\' + 
data.RegKey ,0,KEY_READ)
#       ret =[]
#       for k in filter(lambda x: x.find('reg') !=-1,data.__dict__):
#           d,t = win32api.RegQueryValueEx(key,gettattr(data,k))
#           ret.append({k:d.encode('hex')})
#    finally:
#        win32api.RegCloseKey(key)
#    return ret

class Finished(Exception): pass

def readDword(tr,a):
    return unpack('I',tr.readMemory(a,4))[0]

def disasm(t,a,s,is_function=False):
    dis = i386Disasm()
    off = 0
    b = t.readMemory(a,s)
    r = []
    while off < s:
        try:
            d = dis.disasm(b,off,a+off)
           # print `d`
            off += len(d)
            r.append(d)
            if is_function and d.mnem == 'ret': break
        except IndexError:
            break
        except envi.InvalidInstruction:
            break
    return r
    
def analCode(t,addr):
    code = disasm(t,addr,64,is_function=True)
    ncorrect = True
    for c in code: 
        if c.mnem == 'and' and c.getOperValue(1) == 0x70000000:
            ncorrect = False
            break
    if ncorrect:
        for c in code: 
            if c.mnem == 'call':
                return analCode(t,c.getOperValue(0))
    return addr
        
def Find_GetItem(t,hit):
    global BPADDRESSES,HITS

    for op in disasm(t,hit,20):
        if op.mnem == 'call':
            a  = analCode(t,op.getOperValue(0))
            if a not in BPADDRESSES:
                print '[*]..Found BinStorage::_getItem @ %X ' %  a
                bp = CfgDumpBP(a)
                t.addBreakpoint(bp)
                BPADDRESSES.add(a)

## this is only for VMZeus
def VMZEUS_Find_RC4(t,hit):
    global BPADDRESSES
    for op in disasm(t,hit,32):
        if op.mnem == 'call':
            a = op.getOperValue(0)
            if a not in HITS:
                print '[*]..Found getPESettigns @ %X ' % a
                c = disasm(t,a,100,is_function=True)
                HITS.add(a)
                rc4_a = (filter(lambda x: x.mnem == 
'call',c)[-1]).getOperValue(0)
                if rc4_a not in BPADDRESSES:
                    print '[*]..Found VMZeus - rc4 @ %X' % rc4_a
                    bp = RC4DumpBP(rc4_a)
                    t.addBreakpoint(bp)
                    BPADDRESSES.add(rc4_a)
                    CFG['type']='vmzeus'


## Find and get data about VM used to encrypt BaseConfig
def VMZEUS_GetBaseConfig(t,hit):

    def getVMData(code):
       r = [];flag = 0
       for c in code:
          if flag == 0 and c.mnem == 'push' and c.opers[0].isImmed():
             r.append(c.getOperValue(0))
             flag = len(r)-1
          elif flag == 1 and c.mnem == 'mov' and c.opers[0].reg == 
e_i386.REG_ESI:
             r.append(c.getOperValue(1))
             flag = 2
          elif flag == 2 and c.mnem == 'mov' and c.opers[0].reg == 
e_i386.REG_ECX:
             r.append(c.getOperValue(1)) 
             flag =3 
          elif flag == 3 and c.mnem == 'call' and c.opers[0].isDeref():
             r.append(c.opers[0].imm) 
             break
       return r

    def getXor(code):
       _r16=[e_i386.REG_AL,e_i386.REG_BL,e_i386.REG_CL,e_i386.REG_DL]
       for c in code:
          if c.mnem  == 'xor' and c.opers[0].reg in _r16 and 
c.opers[1].isImmed():
              return c.getOperValue(1)
                                       
    hit = hit-62
    code = disasm(t,hit,100,is_function=True)
    s1,a1,a2,s2,a3 = getVMData(code)
    print '[*]..vmcode %X (%d) vmdata %X (%d) handlers %x' % 
(s1,a1,a2,s2,a3)
    xors = []
    while readDword(t,a3):
       code = disasm(t,readDword(t,a3),64,is_function=True)
       xor = getXor(code)
       if xor: xors.append(xor)
       elif str(code) == '[xor al,al, ret ]': pass
       else: return  
       a3 +=4
    CFG['BaseConfig'] = { 'code': t.readMemory(a1,s1).encode('hex')
                        , 'data': t.readMemory(a2,s2).encode('hex')
                        , 'magic': xors}


def KINS_Find_RC4(t,hit):
    for hit in t.searchMemoryRange(".\xc3",hit,32,regex=True):
      code = disasm(t,hit+2,100,is_function=True)
      if map(str,code[:2]) != ['push ebp','mov esp,ebp']: return

      idx = len(code)-1
      for c in code[::-1]:
       if c.mnem == 'call':
          p =filter(lambda x:x.mnem == 'pop' and x.getOperands()[0].reg 
== REG_EDX ,code[idx-5:idx][::-1])
          if p and filter(lambda x:x.mnem == 'push' and 
x.getOperValue(0) == 5,code[idx-5:idx][::-1]):
            print "[*]..Found KiNS - GetPESettings @ %X" % (hit+2)
            CFG['type']='kins'
            a = code[idx].va + code[idx].size
            bp = PESettingsDumpBP(a)
            t.addBreakpoint(bp)
            BPADDRESSES.add(a)
       idx -= 1

def get_version(t,hit):
   code = disasm(t,hit,14)
   return code[3].getOperValue(1)

# def findStructReg(t,addr):
#     code = 
#     r = set()
#     for op in code:
#         ops = op.getOperands()
#         if len(ops) == 2 and ops[1].isDeref():
#             r.add(regs[ops[1].reg][0])
#     r = filter(lambda x: x not in ['esp','ebp'],r)
#     if len(r) != 1:
#         print "[!] Too many registers. panic!"
#         print `r`
#         raise Finished()

#     return list(r)[0]




class Notifier(vtrace.Notifier):
   def notify(self, event, trace):
        ## pass exception
        if event == vtrace.NOTIFY_SIGNAL:
            trace.runAgain()

class PESettingsDumpBP(vtrace.Breakpoint):

    # def stepo(self,tr):
    #     op = self.trace.parseOpcode(self.trace.getProgramCounter())
    #     bp = vtrace.breakpoints.OneTimeBreak(op.va + op.size)
    #     tr.addBreakpoint(bp)
    #     tr.trace.run()

    def notify(self,ev,tr):
        SIZE = 0x2a6
        ebp = tr.getRegisterByName('ebp')
        addr = unpack('I',tr.readMemory(ebp+8,4))
        data = tr.readMemory(addr,SIZE)
        if 'pesettings' not in CFG:
           print '[*]... PESettigns @ %X' % addr
           CFG['pesettings'] = data.encode('hex')
        tr.runAgain()

class RC4DumpBP(vtrace.Breakpoint):
    def notify(self,ev,tr):
        eax = tr.getRegisterByName('eax')
        esp = tr.getRegisterByName('esp')
        r,d,s = unpack('III',tr.readMemory(esp,12))
        if (r &0xffff) != 0xf0ff :
		#,tr.readMemory(esp+4,4),tr.readMemory(esp+8,4))
          rc4k = tr.readMemory(eax,0x102)
          data  = rc4crypt(tr.readMemory(d,s),rc4k)
          h = md5(data).hexdigest()
          if s == 0x1e6 and not 'pesettings' in CFG: 
            CFG['pesettings'] = {'key': rc4k.encode('hex'), 'data': 
data.encode('hex')}
            print '[*]... Found PESettigns @ %X' % d
          elif (s == 0x66 and CFG['type'] == 'vmzeus') and not 'cfgurl' 
in CFG :
            CFG['cfgurl'] = {'key':rc4k.encode('hex'), 
'data':data.encode('hex')}
            print '[*]... Got DynamicConfig url %s' % 
(data.split("\x00")[0])
          elif s == 0x10 and not 'mutex' in CFG: 
            CFG['mutex'] = {'key': rc4k.encode('hex'), 'data': 
data.encode('hex')}
            print '[*]... Got Mutex/Guid - %s' % data.encode('hex')
          elif h not in RC4:
            RC4[h] = {'key': rc4k.encode('hex'), 'data': 
data.encode('hex')}
            print '[*]....About to decode %x bytes' % s
            print '[*]... RC state @ %X ' % eax
            print '[*]... Return @ %X' % r
#            with open('C:\\%s.dump'%h,'w') as f: 
#                f.write("key: %s\n\n"%rc4k.encode('hex'))
#                f.write(data)
        tr.runAgain()



class CfgDumpBP(vtrace.Breakpoint):
    def notify(self,ev,tr):
#        tr.setMode("RunForever", False)
#        pc  = self.getAddress()
#        reg = tr.getMeta('reg_%x'%pc)
        ptr = 
unpack('I',tr.readMemory(tr.getRegisterByName('esp')+4,4))[0]
        print '[*]...BinStorage @ %X ' % ptr
        self.dumpSections(tr,ptr)
        
    def dumpSections(self,tr,addr):
        global CFG
#   addr = addr if addr else GetRegValue('EAX')
        with open('c:\\xcfg','wb') as f:
            hdr = tr.readMemory(addr,0x30)
 #           r = hdr
            f.write(hdr)
            f.flush()
            count = unpack('I',tr.readMemory(addr + 20 + 8,4))[0]
            addr += 0x30
            off  = 0x30
            CFG['cfg'] = hdr
            print "attempt to dump %d sections" % count
            for i in range(count):
                size = unpack('I',tr.readMemory(addr+8,4))[0]
                print "Section size: %d - off: %x" % (size,off)
                sec = tr.readMemory(addr,0x10 + size)
                CFG['cfg'] += sec
                f.write(sec)
                f.flush()
                addr += 0x10 + size
                off += 0x10 + size
            CFG['cfg'] = base64.b64encode(CFG['cfg'])
            self.exit_dbg(tr)
    def exit_dbg(self,tr):
        for bp in tr.getBreakpoints():
            bp.deactivate(tr)
        tr.detach()
        send_data()
        finish()
#                r += sec
#                return r


def run(pid):

   global T
   global IE


   print '[*] attaching to %d ...' % pid,
   T.attach(pid)
   print 'done.'
 
   for a,l,p,n in T.getMemoryMaps():
      if p == perm_lookup[PAGE_EXECUTE_READWRITE]:
         print '[*]Found RWX segment @ %X - %X (%s)' % (a,a+l,n if n 
else '-')
        ## rc4 state
         for hit in T.searchMemoryRange("\x83.\x72",a,l,regex=True):
             print "[*].Found `cmp ??,0x72` @ %X" % hit
             VMZEUS_Find_RC4(T,hit)
        ## dynamic config
         for hit in T.searchMemoryRange("\x68\x21\x4e\x00\x00",a,l):
             print "[*].Found `push 20001` @ %X"  % hit
             Find_GetItem(T,hit)
        ## VMZeus/KiNS VM 
         for hit in 
T.searchMemoryRange("\x8b\x45.\x0f\xb6\x00\x8d\x4d.\xff\x14\x85....\x84\xc0\x75",a,l,regex=True):
             print '[*].Found VM::run @ %X' % hit
             print '[*].Got KiNS/VMZeus!'
             KINS_Find_RC4(T,hit)
             VMZEUS_GetBaseConfig(T,hit)
         for hit in T.searchMemoryRange("\x68\x13\x27\x00\x00",a,l):
	     pass
             #ver = get_version(hit)
             #print '[*].Found Version: %X' % ver
             #CFG['version']=ver
   try:
      notif = Notifier()
      T.registerNotifier(vtrace.NOTIFY_ALL,notif)
      if T.getBreakpoints():
         print '[*] All set. running for gold'
         if IE:
            IE.set()
         T.run()
      else:
         print '[-] I failed. sorry'
         T.detach()
         sys.exit(1)

   except KeyboardInterrupt:
       print '[*] Counth C-c. bail out'
   except Finished:
       pass
   finally:
       finish()

def run_external():
   global T,IE,ie
   T = vtrace.getTrace()
   pr = T.ps()
   IE = None
   from win32com.client import Dispatch
   import pythoncom
   from threading import Event,Thread
   def start_ie(ev,iem):
      ev.wait()
      Event().wait(5)
      print '[*] Navigate to google.com'
      pythoncom.CoInitialize()
      ie = Dispatch(pythoncom.CoGetInterfaceAndReleaseStream(
                    iem,pythoncom.IID_IDispatch))
      ie.Navigate('http://example.com')

   IE = Event()
   pythoncom.CoInitialize()
   ie = Dispatch('InternetExplorer.Application')
   ie.Visible = 0
   iem = 
pythoncom.CoMarshalInterThreadInterfaceInStream(pythoncom.IID_IDispatch,ie)
   Thread(target=start_ie,args=(IE,iem)).start()
   IE.wait(10)
   pid = filter(lambda x: x[1].lower() == 'iexplore.exe',T.ps())[-1][0] 
   run(pid)
   
if __name__ == '__main__':

   T = vtrace.getTrace()
   pr = T.ps()
   IE = None

   if sys.argv[1] == '-e':
      pid = filter(lambda x: x[1].lower() == 'explorer.exe',pr)[0][0]

   elif sys.argv[1] == '-a':
      for pid,name, in enumerate(pr):
         T.attach(pid)
         for  a,l,p,n in T.getMemoryMaps():
             if p == perm_lookup[PAGE_EXECUTE_READWRITE]:
                print '[*]Found RWX segment inside %s @ %X - %X (%s)' % 
(name,a,a+l,n if n else '-')
         T.detach()
      sys.exit(1)
   elif sys.argv[1] == '-i':
      from win32com.client import Dispatch
      import pythoncom
      from threading import Event,Thread
      def start_ie(ev,iem):
          ev.wait()
          Event().wait(5)
          print '[*] Navigate to google.com'
          pythoncom.CoInitialize()
          ie = Dispatch(pythoncom.CoGetInterfaceAndReleaseStream(
                        iem,pythoncom.IID_IDispatch))
          ie.Navigate('http://example.com')

      IE = Event()
      pythoncom.CoInitialize()
      ie = Dispatch('InternetExplorer.Application')
      ie.Visible = 0
      iem = 
pythoncom.CoMarshalInterThreadInterfaceInStream(pythoncom.IID_IDispatch,ie)
      Thread(target=start_ie,args=(IE,iem)).start()
      IE.wait(10)
      pid = filter(lambda x: x[1].lower() == 
'iexplore.exe',T.ps())[-1][0]
   else:
      for i,x in enumerate(pr):
          print '[%03d] %s' % (i,x[1])
      idx = raw_input('Choose proces: ')
      pid = pr[int(idx)][0]

   run(pid)

