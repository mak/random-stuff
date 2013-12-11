
import os,re,sys,hashlib
import requests
import argparse
from Crypto.Cipher import ARC4
import random
from threading import Event
from urlparse import urlparse

class alureonStuff :
  def __init__(self,url,k=None):
    if not k:
      k = ''.join( random.choice("ABCDEFGHUIJZX12450872356_") for i in range( random.randint(10,20) ) )
    self.key = k
    self.url = url if isinstance(url,str) else self._url(url)
    self.domain = urlparse(self.url).netloc
    print "RDY ( %s , %s , %s )" % ( self.key, self.domain, self.url  ) 


  def _url(self,urls):
    url = random.choice(urls)
    return url

  def code(self,k,d):
    c = ARC4.new(k)
    return c.decrypt(d)
    
  def doReq(self,data):
    #print " code "
    data = self.code( self.domain , data )
    #print " send : [%s] " % `data`
    r = requests.post(self.url,data=data,verify=False)
    if r.ok :
      #print " decode"
      print " POST OK "
      return self.code( self.key , r.content ) 
    else :
      print "FAIL"
      return None


  def buildReq(self,act,data):
    pay = "%s|%d|%s" % ( self.key , act , data )
    print " PAYLOAD : % s " % pay 
    return self.doReq(pay)

  def getOsStr(self):
     s = "%s %04d sp%d.%1d %s" % ("Windows XP",5111,3,1,"32bit")
     return s

  def bot_signup(self,os=None,bid=None) :
    if not os  : os  = self.getOsStr()
    if not bid : bid = 'main'
    return self.buildReq(33 , "os=%s&bid=%s" % ( os,bid ) )


  def bot_reqbin(self,fid=1):
    return self.buildReq( 35 , "fid=%d"%int(fid))

  def bot_report(self,tid=0,msg="OK",c=0):
    return self.buildReq( 34 , "tid=%d&ta=%s-%x" % ( int(tid),msg,c) )
 
  def bot_raw(self,n,raw):
    return self.buildReq(int(n),raw)


def sha(d):
    return hashlib.sha256(d).hexdigest()

ul = ['https://viewonlinevideo.ru/dropfilms/data.php','https://filmsonline2004.ru/dropfilms/data.php','https://filmsonline2004.ru/dropfilms2/data.php']
ul='https://viewonlinevideo.ru/dropfilms/data.php'
alu = alureonStuff(url=ul)
ddir = '/home/nigga/alur/drops/'
while True:
  resp = alu.bot_signup()
  print "Resp: %s" % `resp`
  
  if resp.find('Download') != -1:
    args = re.search('\((.*)\)',resp).group(1).split(',')
    print args
    tid = args[0]
    fid = args[2]

    data = alu.bot_reqbin(fid)
    if data[:4] == 'OK\r\n':
      with open(ddir + '/' + sha(data[4:]) + '.bin','w') as f:
                f.write(data[4:])
    alu.bot_report(tid)
    
  Event().wait(900)
