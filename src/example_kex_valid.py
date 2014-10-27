#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>


def padding_fix(p):
    padd= 8-len(p)%8
    if p.haslayer(Raw):
        p[Raw].load += 'P'*padd
    else:
        p=p/('P'*padd)
    return p

if __name__=="__main__":
    from scapy.all import *
    
    # for local testing only ---->
    import sys
    sys.path.append("scapy/layers")
    from ssh import *
    # <------
    
    import socket

    try:
        target = ('192.168.220.131',22) 
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(target)
        
        p = SSH()/SSHIdent(ident="SSH-2.0-x\r\n")
    
    
        p.show()
    
        print "sending payload"
        s.sendall(str(p))
    
        resp = s.recv(1024)
        print "received, %s"%repr(resp)
        SSH(resp).show()
    
        
        
        p=SSHMessage()/SSHKexInit( \
                                  #encryption_algorithms_client_to_server=SSH_ALGO_CIPHERS[0], \
                                  #encryption_algorithms_server_to_client=SSH_ALGO_CIPHERS[0], \
                                  #kex_algorithms=SSH_ALGO_CIPHERS[0], \
                                  languages_client_to_server="de,uk,de,uk", \
                                  #languages_client_to_server_length=999,\
                                  #languages_server_to_client="xx", \
                                  #kex_first_packet_follows=2, \
                                  reserved=0) \
                                  #/('a'*100) 

        p = padding_fix(p)
     
        p.show2()
        print "sending payload"
        s.sendall(str(p))
        for i in range(3):
            resp = s.recv(1024)
            print "received, %s"%repr(resp)
        
            SSH(resp).show()
        s.close()
        
    except: pass