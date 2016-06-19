import sys
from threading import Thread
import time
import socket

sys.path.append("..")

from libDiameter import *


class Server():
    # Define server_host:port to use (empty string means localhost)
    HOST = "localhost"
    DIAM_PORT = 3869

     
    ORIGIN_HOST = "server.test.com"
    ORIGIN_REALM = "test.com"
    DEST_REALM = ""
    

    def __init__(self,port):
        print "init"
        self.DIAM_PORT=port


        
    def listen(self):
        
        self.originHostAndRealmAVPs=[
            encodeAVP("Origin-Host",self.ORIGIN_HOST),
            encodeAVP("Origin-Realm",self.ORIGIN_REALM),
        ]
        self.okAVP=[
            encodeAVP("Result-Code",2000),
        ]
        print "listen"
        BUFFER_SIZE=1024    
        MAX_CLIENTS=10
        sock_list=[]
        threads = []
        # Create the server, binding to HOST:DIAM_PORT
        PCRF_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #fix "Address already in use" error upon restart
        PCRF_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        PCRF_listen.bind((self.HOST, self.DIAM_PORT))  
        PCRF_listen.listen(MAX_CLIENTS) 

        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        while True:
            conn,addr=PCRF_listen.accept()
            print str(conn)
            print str(addr)
            t = Thread(target=self.handleSession, args=(conn,))
            threads.append(t)
            t.start()

    def handleSession(self,con):
        packets=diameterGenerator(con)
        
        h,avps = packets.next()
        while h!=None:
            #print "appid %d cmd code %d"%(h.appId,h.cmd)
            #print str(avps)
            #print str(h.msg)

            if 'Origin-Host' in avps:
                del avps['Origin-Host']
            if 'Origin-Realm' in avps:
                del avps['Origin-Realm']

            res_avps=[]+self.originHostAndRealmAVPs + [encodeAVP(name,value) for name,value in avps.iteritems()] + self.okAVP
            
            res_msg = createResponse(h,res_avps)
            con.send(res_msg.decode('hex'))
            
            h,avps = packets.next()
        print "closed socket"
        con.close()
        
if __name__ == "__main__":
    print "main"
    LoadDictionary("../dictDiameter.xml")
    print "dictionary loaded"
    server = Server(3869)
    server.listen()
