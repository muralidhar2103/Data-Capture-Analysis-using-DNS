import pandas as pd
import numpy as np
import re
from csv import writer
from scapy.all import *
Cols=["Type","Version","Protocol","Source_ip","Dest_ip","Id","Source_port",
     "Dest_port","Transaction_id","Flag_QR","Flag_AA","Flag_TC","Flag_RD"
     ,"Flag_RA","Flag_Z","Flag_AD","Flag_CD","Flag_OPCODE","Flag_RCODE"
     ,"QD_COUNT","AN_COUNT","NS_COUNT","AR_COUNT","QUERY_NAME","QUERY_TYPE"
     ,"QUERY_CLASS","RR_name","ns_type","an_type","rr_name","ar_type"]

def findDNS(p):
 
 
  Type=[]
  if p.haslayer(DNS):
    print(p.summary())
    pr=p
    pro=repr(pr)
    print(pro)
    prop=re.search(r'proto',pro)
    # print(p.display())
    print("Type:"+str(p.type))
    print("Version:"+str(p.version))
    if prop==None:
      print("Protocol: None")
    else:
      print("Protocol:"+str(p.proto))
    src_ip = p.getlayer(IP).src
    dest_ip = p.getlayer(IP).dst
    print("Source IP:"+str(src_ip))
    print("Destination IP:"+str(dest_ip))
    id = p.getlayer(IP).id
    print("id:"+str(id))
    print("Source Port:" + str(p.sport))
    print("Destination Port:" + str(p.dport))
    print("___________________________DNS____________________________________")
    Transc_id = p.getlayer(DNS).id
    print("Transaction id:"+str(Transc_id))
    print("Flag_QR:"+str(p.qr))
    print("Flag_OPcode:"+str(p.opcode))
    print("Flag_AA:"+str(p.aa))
    print("Flag_TC:"+str(p.tc))
    print("Flag_RD:"+str(p.rd))
    print("Flag_RA:"+str(p.ra))
    print("Flag_Z:"+str(p.z))
    print("Flag_AD:"+str(p.ad))
    print("Flag_CD:"+str(p.cd))
    print("Flag_Rcode:"+str(p.rcode))
    print("QDcount:"+str(p.qdcount))
    print("ANcount:"+str(p.ancount))
    print("NScount:"+str(p.nscount))
    print("ARcount:"+str(p.arcount))
    Type.append(str(p.type))
    
    Type.append(str(p.version))
    if prop==None:
      Type.append("NAN")
    else:
      Type.append(str(p.proto))
    
    src_ip = p.getlayer(IP).src
    dest_ip = p.getlayer(IP).dst
    Type.append(str(src_ip))
    
    Type.append(str(dest_ip))
    id = p.getlayer(IP).id
    Type.append(str(id))
    Type.append(str(p.sport))
    Type.append(str(p.dport))
 
    Transc_id = p.getlayer(DNS).id
    Type.append(str(Transc_id))
    
    Type.append(str(p.qr))
    
    Type.append(str(p.opcode))
    
    Type.append(str(p.aa))
    Type.append(str(p.tc))
    Type.append(str(p.rd))
    Type.append(str(p.ra))
    Type.append(str(p.z))
    Type.append(str(p.ad))
    Type.append(str(p.cd))
    Type.append(str(p.rcode))
    Type.append(str(p.qdcount))
    Type.append(str(p.ancount))
    Type.append(str(p.nscount))
    Type.append(str(p.arcount))
    a=p[DNS].qd
    b=p[DNS].ns
    c=p[DNS].an
    d=p[DNS].ar
    pa=(repr(a))
    pb=(repr(b))
    pc=(repr(c))
    pd=(repr(d))
    if pa == 'None':
      Type.append("NAN")
      Type.append("NAN")
      Type.append("NAN")
    else:

      p=(re.search(r'qname=\W[_0-9A-Za-z\.-]+\W',pa))
      if p==None:
        Type.append("NAN")
      else:
        print(p)
        Type.append((p[0][7:-2]))
      
      p=(re.search(r'qtype=[A-Z0-9]+\s',pa))
      Type.append(p[0][6:-1])
      p=(re.search(r'qclass=[A-Z0-9]+\s',pa))
      Type.append(p[0][7:-1])
    

    
    if pb == 'None':
      Type.append("NAN")
      Type.append("NAN")
    else:
    
      p=(re.search(r'rrname=\W[_0-9A-Za-z\.-]+\W',pb))
      if p==None:
        Type.append("NAN")
      else:
        Type.append(p[0][8:-2])
      p=(re.search(r'type=[A-Z]+\s',pb))
      Type.append(p[0][5:-1])
    if pc == 'None':
      Type.append("NAN")
      Type.append("NAN")
    else:
 
      p=(re.search(r'type=[A-Z]+\s',pc))
      Type.append(p[0][5:-1])
      p=(re.search(r'rrname=\W[_0-9A-Za-z\.-]+\W',pc))
      Type.append(p[0][8:-2])
      print(p[0][8:-2])
    if pd == 'None':
      Type.append("NAN")
    else:
   
      p=(re.search(r'type=[A-Z]+\s',pd))
      Type.append(p[0][5:-1])
    print(Type)
    with open("please_work12.csv", 'a') as csvfile: 
    # creating a csv writer object 
      csvwriter = writer(csvfile) 
      csvwriter.writerow(Type)
      csvfile.close()


sniff(prn=findDNS,count=1000)


