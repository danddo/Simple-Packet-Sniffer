from scapy.all import *
from multiprocessing.dummy import Pool as ThreadPool
import time
import threading
start_time = time.time()


def scanner(ip, ports):
    list_of_ports = make_valid_argument(ports)
    pool = ThreadPool(15)
    results = pool.map(lambda x: singleScan(ip, x), list_of_ports)
    pool.close()
    pool.join()
    compress_results (results)

    return None


def make_valid_argument (ports):
    if isinstance(ports, basestring):
        if ports.find("-")!=-1:
            rangenumbers = ports.split("-")
            start =int(rangenumbers[0])
            end  = int(rangenumbers [1])
            return range (start,end+1)
        elif ports.find(",")!=-1:
            listnumbers = ports.split(",")
            listnumbers2 = map(int, listnumbers)
            return listnumbers2
        elif isinstance(int(ports), int):
            return [int(ports)]
        else:
            print ("input error")
            exit(3)


def compress_results (results):
    results.sort(key=lambda x: x[0])
    i=0
    while i<len(results):
        k=i
        d=i
        while k<len(results)-1 and results[k+1][1]==results[i][1] and results[k+1][0]==(results[d][0]+1):
            k += 1
            d +=1
        if k!=i:
            print (str(results[i][0])+ " - " + str(results[k][0])+ " " + str(results[i][1]))
            i=k+1
        else:
            print (str(results[i][0]) + " " + str(results[i][1]))
            i+=1
    return None


def singleScan (d_ip, port):

    dst_ip = d_ip
    src_port = RandShort()
    dst_port=port

    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
      return (port,"Filtered")
    elif(stealth_scan_resp.haslayer(TCP)):
       if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
           send_rst = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=3)
           return (port,"Open")
       elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
           return (port,"Closed")
    elif(stealth_scan_resp.haslayer(ICMP)):
       if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
          return (port,"Filtered")


singleScan("132.72.42.23",80)
scanner ("31.13.72.36","1-100" )  #facebook
scanner ("132.72.42.23","1-100" )   #bgu mail service
print("--- %s seconds ---" % (time.time() - start_time))



