import os,sys
from struct import *
V_DIR = 'c:\\vivisect'
sys.path.append(V_DIR)

import vtrace,vstruct
import PE

class Notifier(vtrace.Notifier):
        def notify(self, event, trace):
                ## pass exception
                if event == vtrace.NOTIFY_SIGNAL:
                        trace.runAgain()
                		
class WorkDbg(vtrace.Breakpoint):
	def notify(self,ev,tr):
		print '[*] Trying to find config data'
		esp = tr.getRegisterByName('esp')
		reta = unpack('I',tr.readMemory(esp,4))[0]
		print '[*] OpenProcess called from ' + hex(reta)
		for hit in tr.searchMemory("\x00\x00\x5b"):
			if hit >= reta-0x10000 and hit<= reta+0x10000:
				if tr.readMemory(hit+3,1) not in ['\x00','\x25']:
					print self.decodecf(tr,hit+2)
					
	def decodecf(self,tr,addr):
		key,size = unpack('II',tr.readMemory(addr-12,8))
		mem = tr.readMemory(addr,size)
		print '[+] Found Config[0..%d] @ 0x%x with key: %X' % (size,addr,key)
		return ''.join([chr(ord(mem[i]) ^ (key % (i+1))) for i in range(0,size)])
		
t = vtrace.getTrace()
t.execute(sys.argv[1])

peb = t.parseExpression('peb')
off = vstruct.getStructure('win32.PEB').vsGetOffset('BeingDebugged')
t.writeMemory(peb+off,"\x00")

notif = Notifier()
t.registerNotifier(vtrace.NOTIFY_ALL,notif)

bp = WorkDbg(t.parseExpression('kernel32.OpenProcess'))
t.addBreakpoint(bp)
#print t.getBreakpoints()

t.run()

