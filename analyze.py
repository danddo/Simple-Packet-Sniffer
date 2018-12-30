from scapy.all import *
import string

def printGeneric (x):
 print "MAC Source:", x[0].src
 print "MAC Destination:", x[0].dst
 if IP in x:
     print "IP Source:", x[IP].src
     print "IP Destination:", x[IP].dst

def printTCP (x):
 print "Source port number: ", x[TCP].sport
 print "Destination port number: ", x[TCP].dport
 print "Flags: ", x.sprintf("%TCP.flags%")
 printPayload (x)

def printUDP (x):
 print "Source port number: ", x[UDP].sport
 print "Destination port number: ", x[UDP].dport
 printPayload (x)

def printICMP (x):
 print "ICMP Type: ", x[ICMP].type
 print "ICMP Subtyper: ", x[ICMP].code

def printPayload (x):
 s = x.sprintf("%Raw.load%")
 printable = set(string.printable)
 s_decode = ''.join(map(lambda x: x if x in printable else '.', s))
 if s_decode != '??':
   print "Load: ", s_decode

def printEnd ():
 print ("----------------------------------")



def printPacket(x):
  if TCP in x:
    print ("Type: TCP")
    print "Length: %d" % len(x)
    printGeneric(x)
    printTCP (x)
    printEnd()
  elif UDP in x:
    print ("Type: UDP")
    print "Length: %d" % len(x)
    printGeneric(x)
    printUDP (x)
    printEnd()
  elif ICMP in x:
    print ("Type: ICMP")
    print "Length: %d" % len(x)
    printGeneric(x)
    printICMP(x)
    printEnd()
  else:
    print ("Type: other")
    print "Length: %d" % len(x)
    printEnd()


pkts = sniff (prn=lambda x:printPacket(x))


