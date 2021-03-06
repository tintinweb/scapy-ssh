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

    import sys
    sys.path.append("../scapy/layers")
    from scapy.all import *
    from ssh import *
    
    import socket
    import sys
    from thread import *
    
    
    # 
    HOST = ''   # Symbolic name meaning all available interfaces
    PORT = 22 # Arbitrary non-privileged port
     
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'Socket created'
     
    #Bind socket to local host and port
    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
         
    print 'Socket bind complete'
     
    #Start listening on socket
    s.listen(10)
    print 'Socket now listening'
     
    #Function for handling connections. This will be used to create threads
    def clientthread(conn):
        #Sending message to connected client
        conn.send('Welcome to the server. Type something and hit enter\n') #send only takes string
         
        #infinite loop so that function do not terminate and thread do not end.
        while True:
             
            #Receiving from client
            data = conn.recv(1024)
            reply = 'OK...' + data
            if not data: 
                break
            
            print reply
         
            reply =  SSH()/SSHIdent(ident="SSH-2.\r\n")/fuzz(Raw())
            conn.sendall(str(reply))

            reply=SSHMessage()/fuzz( \
                                 SSHKexInit(encryption_algorithms_client_to_server=(','+SSH_ALGO_CIPHERS[1])*2, \
                                      languages_client_to_server="de,uk,de,uk", \
                                      #languages_client_to_server_length=999,\
                                      languages_server_to_client="xx", \
                                      kex_first_packet_follows=2,
                                      reserved=0x0a0b0c0d)/('aa'*2) \
                                )
            conn.sendall(str(reply))
         
        #came out of loop
        conn.close()
     
    #now keep talking with the client
    while 1:
        #wait to accept a connection - blocking call
        conn, addr = s.accept()
        print 'Connected with ' + addr[0] + ':' + str(addr[1])
         
        #start new thread takes 1st argument as a function name to be run, second is the tuple of arguments to the function.
        start_new_thread(clientthread ,(conn,))
     
    s.close()
    
    exit()