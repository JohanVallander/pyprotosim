#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Nov 2012
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode diameter messages

import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import string
import select

# Diameter Header fields

DIAMETER_FLAG_MANDATORY = 0x40
DIAMETER_FLAG_VENDOR    = 0x80

DIAMETER_HDR_REQUEST    = 0x80
DIAMETER_HDR_PROXIABLE  = 0x40
DIAMETER_HDR_ERROR      = 0x20
DIAMETER_HDR_RETRANSMIT = 0x10

# Include common routines for all modules
ERROR = -1
 
# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    code=0
    name=""
    vendor=0
    basic_type=""
    type=""
    mandatory=""
    enumerations={}
    names={}
    encode_fun=None
    decode_fun=None

    def __init__(self):
        pass

class HDRItem:
    ver=0
    flags=0
    len=0
    cmd=0
    appId=0
    HobByHop=0
    EndToEnd=0
    msg=""

    def __init__(self):
        pass
    
    
#----------------------------------------------------------------------

utf8encoder=codecs.getencoder("utf_8")
utf8decoder=codecs.getdecoder("utf_8")

#----------------------------------------------------------------------
# Dictionary routines

# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_avps
    global dict_vendors
    global dict_commands
    global dict_typedefs
    global typedef_dict
    global asString
    global asUTF8
    global asU32
    global asI32
    global asU64
    global asI64
    global asF32
    global asF64
    global asIPAddress
    global asIP
    global asTime
    global dict_avps
    global dict_vendors
    global dict_commands
    global avps_by_name
    global avps_by_code
    global vendor_code_by_name
    global vendor_name_by_code
    global command_name_by_code
    global command_code_by_name

    doc = minidom.parse(file)
    node = doc.documentElement
    dict_avps = doc.getElementsByTagName("avp")

    dict_vendors = doc.getElementsByTagName("vendor")
    dict_commands=doc.getElementsByTagName("command")
    # Now lets process typedefs
    asString=["OctetString"]
    asUTF8=["UTF8String"]
    asI32=["Integer32","Enumerated"]
    asU32=["Unsigned32"]
    asF32=["Float32"]
    asI64=["Integer64"]
    asU64=["Unsigned64"]
    asF64=["Float64"]
    asIPAddress=["IPAddress"]
    asIP=["IP"]    
    asTime=["Time"]
    asGrouped=["Grouped"]
    dict_typedefs=doc.getElementsByTagName("typedef")
    typedef_dict={"Enumerated":"Integer32",
                  "OctetString":"OctetString",
                  "UTF8String":"UTF8String",
                  "Integer32":"Integer32",
                  "Unsigned32":"Unsigned32",
                  "Float32":"Float32",
                  "Integer32":"Integer32",
                  "Unsigned64":"Unsigned64",
                  "Integer64":"Integer64",
                  "Float64":"Float64",
                  "IPAddress":"IPAddress",
                  "IP":"IP",
                  "Time":"Time",
                  "Grouped":"Grouped",
              }
    for td in dict_typedefs:
        tName=td.getAttribute("name")
        tType=td.getAttribute("type")
        if tType in asString:
            typedef_dict[tName]='OctetString'
            asString.append(tName)
        if tType in asUTF8:
            typedef_dict[tName]='UTF8String'
            asUTF8.append(tName)
        if tType in asU32:
            typedef_dict[tName]='Unsigned32'
            asU32.append(tName)
        if tType in asI32:
            typedef_dict[tName]='Integer32'
            asI32.append(tName)
        if tType in asI64:
            typedef_dict[tName]='Integer64'
            asI64.append(tName)    
        if tType in asU64:
            typedef_dict[tName]='Unsigned64'
            asU64.append(tName)           
        if tType in asF32:
            typedef_dict[tName]='Float32'
            asF32.append(tName)           
        if tType in asF64:
            typedef_dict[tName]='Float64'
            asF64.append(tName)           
        if tType in asIPAddress:
            typedef_dict[tName]='IPAddress'
            asIPAddress.append(tName)
        if tType in asIP:
            typedef_dict[tName]='IP'
            asIP.append(tName)           
        if tType in asTime:
            typedef_dict[tName]='Time'
            asTime.append(tName)   
        if tType in asGrouped:
            typedef_dict[tName]='Grouped'
            asGrouped.append(tName)
        
    #speeds up lookups by creating a python dictionary with all names, using the old function _dictAVPname2code
    print "creating dictionaries"
    command_name_by_code={}
    command_code_by_name={}
    for command in dict_commands:
         cName=command.getAttribute("name")
         cCode=int(command.getAttribute("code"))
         command_name_by_code[cCode]=cName
         command_code_by_name[cName]=cCode
    print "command dict created"
    
    vendor_code_by_name={}
    vendor_name_by_code={}
    for vendor in dict_vendors:
        vCode=int(vendor.getAttribute("code"))
        vId=vendor.getAttribute("vendor-id")
        vendor_code_by_name[vId]=vCode
        vendor_name_by_code[vCode]=vId
    print "vendor dict created"

    avps_by_name={}
    avps_by_code={}
    for avp in dict_avps:
        A=AVPItem()
        A.name=avp.getAttribute("name")
        A.code=int(avp.getAttribute("code"))
        try:
            A.vendor=int(vendor_code_by_name[avp.getAttribute("vendor-id")])
        except:
            A.vendor=0
        avps_by_name[A.name]=A
        avps_by_code[(A.vendor,A.code)]=A

        A.type=avp.getAttribute("type")
        try:
            A.basic_type=typedef_dict[A.type]
        except:
            A.basic_type="OctetString"
        if A.type=="Enumerated":
            enumerations = avp.getElementsByTagName("enum")
            for e in enumerations:
                A.enumerations[e.getAttribute('code')]=e.getAttribute('name')
                A.names[e.getAttribute('name')]=e.getAttribute('code')

        if A.type in asUTF8:
            A.encode_fun=encode_UTF8String
            A.decode_fun=decode_UTF8String
        elif A.type in asI32:
            A.encode_fun=encode_Integer32
            A.decode_fun=decode_Integer32 
        elif A.type in asU32:
            A.encode_fun=encode_Unsigned32
            A.decode_fun=decode_Unsigned32
        elif A.type in asI64:
            A.encode_fun=encode_Integer64
            A.decode_fun=decode_Integer64
        elif A.type in asU64:
            A.encode_fun=encode_Unsigned64
            A.decode_fun=decode_Unsigned64
        elif A.type in asF32:
            A.encode_fun=encode_Float32
            A.decode_fun=decode_Float32
        elif A.type in asF64:
            A.encode_fun=encode_Float64
            A.decode_fun=decode_Float64
        elif A.type in asIPAddress:
            A.encode_fun=encode_Address
            A.decode_fun=decode_Address
        elif A.type in asIP:
            A.encode_fun=encode_IP
            A.decode_fun=decode_IP
        elif A.type in asTime:
            A.encode_fun=encode_Time
            A.decode_fun=decode_Time
        elif A.type=="Enumerated":
            A.encode_fun=encode_Enumerated
            A.decode_fun=decode_Enumerated
        else:
            A.encode_fun=encode_OctetString
            A.decode_fun=decode_OctetString
    print "avp dict created"
        
    
# Find AVP definition in dictionary: User-Name->1
# on finish A contains all data
# faster version
def dictAVPname2code(A,avpname,avpvalue):
    global avps_by_name
    try:
        avp = avps_by_name[avpname]
        A.name = avp.name
        A.code = avp.code
        A.mandatory=avp.mandatory
        A.type = avp.type
        A.vendor=avp.vendor
        return
    except:
        dbg="Searching dictionary failed for N",avpname,"V",avpvalue
        bailOut(dbg)

 
# Find AVP definition in dictionary: 1->User-Name
# on finish A contains all data
# stupid function for backwards compatibility
def dictAVPcode2name(A,avpcode,vendorcode):
    global avps_by_code
    try:
        avp=avps_by_code[(vendorcode,avpcode)]
    except:
        dbg="Search for AVP with vendor-id %d and code %d failed"%(vendorcode,avpcode)
        bailOut(dbg)
        
    A.vendor=avp.vendor
    A.name = avp.name
    A.type = avp.type
    A.code = avp.code
    A.mandatory=avp.mandatory
    A.vendor=avp.vendor
    return

# Find Vendor definition in dictionary: 10415->TGPP    
def dictVENDORcode2id(code):
    global vendor_name_by_code
    try:
        return vendor_name_by_code[code]
    except:
        dbg="Searching Vendor dictionary failed for C",code
        bailOut(dbg)

# Find Vendor definition in dictionary: TGPP->10415    
def dictVENDORid2code(vendor_id):
    global vendor_code_by_name
    try:
        return vendor_code_by_name[vendor_id]
    except:
        dbg="Searching Vendor dictionary failed for V",vendor_id
        bailOut(dbg)

# Find Command definition in dictionary: Capabilities-Exchange->257    
def dictCOMMANDname2code(name):
    global command_code_by_name
    try:
        return command_code_by_name[name]
    except:
        dbg="Searching CMD dictionary failed for N",name
        bailOut(dbg)

# Find Command definition in dictionary: 257->Capabilities-Exchange
def dictCOMMANDcode2name(flags,code):
    global command_name_by_code
    cmd=ERROR
    try:
        cmd=command_name_by_code["code"]
    except:
        pass
    if cmd==ERROR:
        return cmd
    if flags&DIAMETER_HDR_REQUEST==DIAMETER_HDR_REQUEST:
        dbg=cmd+" Request"
    else:
        dbg=cmd+" Answer"
    return dbg

#----------------------------------------------------------------------
# These are defined on Unix python.socket, but not on Windows
# Pack/Unpack IP address
def inet_pton(address_family, ip_string): 
    #Convert an IP address from text represenation to binary form
    if address_family == socket.AF_INET:
        return socket.inet_aton(ip_string)
    elif address_family == socket.AF_INET6:
        # IPv6: The use of "::" indicates one or more groups of 16 bits of zeros.
        # We deal with this form of wildcard using a special marker. 
        JOKER = "*"
        while "::" in ip_string:
            ip_string = ip_string.replace("::", ":" + JOKER + ":")
        joker_pos = None
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in ip_string:
            ipv4_addr = ip_string.split(":")[-1]
        result = ""
        parts = ip_string.split(":")
        for part in parts:
            if part == JOKER:
                # Wildcard is only allowed once
                if joker_pos is None:
                   joker_pos = len(result)
                else:
                   bailOut("Illegal syntax for IP address")
            elif part == ipv4_addr:
                # FIXME: Make sure IPv4 can only be last part
                # FIXME: inet_aton allows IPv4 addresses with less than 4 octets 
                result += socket.inet_aton(ipv4_addr)
            else:
                # Each part must be 16bit. Add missing zeroes before decoding. 
                try:
                    result += part.rjust(4, "0").decode("hex")
                except TypeError:
                    bailOut("Illegal syntax for IP address")
        # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes) 
        if JOKER in ip_string:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
        if len(result) != 16:
            bailOut("Illegal syntax for IP address")
        return result
    else:
        bailOut("Address family not supported")

def inet_ntop(address_family, packed_ip): 
    #Convert an IP address from binary form into text represenation
    if address_family == socket.AF_INET:
        return socket.inet_ntoa(packed_ip)
    elif address_family == socket.AF_INET6:
        # IPv6 addresses have 128bits (16 bytes)
        if len(packed_ip) != 16:
            bailOut("Illegal syntax for IP address")
        parts = []
        for left in [0, 2, 4, 6, 8, 10, 12, 14]:
            try:
                value = struct.unpack("!H", packed_ip[left:left+2])[0]
                hexstr = hex(value)[2:]
            except TypeError:
                bailOut("Illegal syntax for IP address")
            parts.append(hexstr.lstrip("0").lower())
        result = ":".join(parts)
        while ":::" in result:
            result = result.replace(":::", "::")
        # Leaving out leading and trailing zeros is only allowed with ::
        if result.endswith(":") and not result.endswith("::"):
            result = result + "0"
        if result.startswith(":") and not result.startswith("::"):
            result = "0" + result
        return result
    else:
        bailOut("Address family not supported yet")

#Pack IP address  
def pack_address(address):
    # This has issue on Windows platform
    # addrs=socket.getaddrinfo(address, None)
    # This is NOT a proper code, but it will do for now
    # unfortunately, getaddrinfo does not work on windows with IPv6
    if address.find('.')!=ERROR:
        raw = inet_pton(socket.AF_INET,address);
        d=struct.pack('!h4s',1,raw)
        return d
    if address.find(':')!=ERROR:
        raw = inet_pton(socket.AF_INET6,address);
        d=struct.pack('!h16s',2,raw)
        return d
    dbg='Malformed IP'
    bailOut(dbg)

#----------------------------------------------------------------------
#
# Decoding section
#

def decode_Integer32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)

def decode_Integer64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)
  
def decode_Unsigned64(data):
    ret=struct.unpack("!Q",data.decode("hex"))[0]
    return int(ret)

def decode_Float32(data):
    ret=struct.unpack("!f",data.decode("hex"))[0]
    return ret

def decode_Float64(data):
    ret=struct.unpack("!d",data.decode("hex"))[0]
    return ret
    
def decode_Address(data):
    if len(data)<=16:
        data=data[4:12]
        ret=inet_ntop(socket.AF_INET,data.decode("hex"))
    else:
        data=data[4:36]    
        ret=inet_ntop(socket.AF_INET6,data.decode("hex"))
    return ret

def decode_IP(data):
    if len(data)<=16:
        ret=inet_ntop(socket.AF_INET,data.decode("hex"))
    else:
        ret=inet_ntop(socket.AF_INET6,data.decode("hex"))
    return ret
    
def decode_OctetString(data,dlen):
    fs="!"+str(dlen-8)+"s"
    dbg="Deconding String with format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-8])[0]
    return ret

#Hex          Comments
#0x00..0x7F   Only byte of a 1-byte character encoding
#0x80..0xBF   Continuation characters (1-3 continuation characters)
#0xC0..0xDF   First byte of a 2-byte character encoding
#0xE0..0xEF   First byte of a 3-byte character encoding
#0xF0..0xF4   First byte of a 4-byte character encoding
#Note:0xF5-0xFF cannot occur    
def decode_UTF8String(data,dlen):
    fs="!"+str(dlen-8)+"s"
    dbg="Decoding UTF8 format:",fs
    logging.debug(dbg)
    ret=struct.unpack(fs,data.decode("hex")[0:dlen-8])[0]
    utf8=utf8decoder(ret)
    return utf8[0]

def decode_Grouped(data):
    dbg="Decoding Grouped:"
    ret=[]
    for gmsg in splitMsgAVPs(data):
        ret.append(decodeAVP(gmsg))
    return ret


#AVP_Time contains a second count since 1900    
def decode_Time(data):
    seconds_between_1900_and_1970 = ((70*365)+17)*86400
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)-seconds_between_1900_and_1970
    
#----------------------------------------------------------------------
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
#----------------------------------------------------------------------    

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           AVP Code                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |V M P r r r r r|                  AVP Length                   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Vendor-ID (opt)                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Data ...
#   +-+-+-+-+-+-+-+-+

# Common finish routine for all encoded AVPs
# Result is properly encoded AVP as hex string (padding is added separately)
def encode_finish(A,flags,pktlen,data):
    ret=data
    if A.vendor!=0:
       ret=("%08X" % int(A.vendor)) + ret
       flags|=DIAMETER_FLAG_VENDOR
       pktlen+=4
    ret=("%08X"%int(A.code))+("%02X"%int(flags))+("%06X"%pktlen)+ret
    return ret
    
def encode_OctetString(A,flags,data):
    fs="!"+str(len(data))+"s"
    ret=struct.pack(fs,data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)

def encode_UTF8String(A,flags,data):
    utf8data=utf8encoder(data)[0]
    fs="!"+str(len(utf8data))+"s"
    ret=struct.pack(fs,utf8data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer32(A,flags,data):
    r=struct.pack("!I",data)
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned32(A,flags,data):
    r=struct.pack("!I",int(data))
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

def encode_Float32(A,flags,data):
    ret=struct.pack("!f",data).encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)
    
def encode_Integer64(A,flags,data):
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Unsigned64(A,flags,data):
    ret=struct.pack("!Q",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Float64(A,flags,data):
    ret=struct.pack("!d",data).encode("hex")
    pktlen=16
    return encode_finish(A,flags,pktlen,ret)

def encode_Address(A,flags,data):
    ret=pack_address(data).encode("hex")
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)
    
def encode_IP(A,flags,data):
    ret=pack_address(data).encode("hex")[4:]
    pktlen=8+len(ret)/2
    return encode_finish(A,flags,pktlen,ret)    

def encode_Enumerated(A,flags,data):
    global dict_avps
    if isinstance(data,str):
        # Replace with enum code value
        ####################################################Fix here ##########################################
        for avp in dict_avps:
            Name = avp.getAttribute("name")
            if Name==A.name:
                for e in avp.getElementsByTagName("enum"):
                    if data==e.getAttribute("name"):
                        return encode_Integer32(A,flags,int(e.getAttribute("code")))
                dbg="Enum name=",data,"not found for AVP",A.name
                bailOut(dbg)
    else:
        return encode_Integer32(A,flags,data)
    
#AVP_Time contains a second count since 1900    
#But unix counts time from EPOCH (1.1.1970)
def encode_Time(A,flags,data):
    seconds_between_1900_and_1970 = ((70*365)+17)*86400 
    r=struct.pack("!I",data+seconds_between_1900_and_1970)
    ret=r.encode("hex")
    pktlen=12
    return encode_finish(A,flags,pktlen,ret)

#----------------------------------------------------------------------     
#Set mandatory flag as specified in dictionary
def checkMandatory(mandatory):
    flags=0
    if mandatory=="must":
        flags|=DIAMETER_FLAG_MANDATORY
    return flags
    
def do_encode(A,flags,data):
    return A.encode_fun(A,flags,data)

# Find AVP Definition in dictionary and encode it
def getAVPDef(AVP_Name,AVP_Value):
    global avps_by_name
    A=avps_by_name[AVP_Name]
    dictAVPname2code(A,AVP_Name,AVP_Value)
    flags=checkMandatory(A.mandatory)
    return do_encode(A,flags,AVP_Value)

################################
# Main encoding routine  
def encodeAVP(AVP_Name,AVP_Value):
    if type(AVP_Value).__name__=='list':
        p=''
        for x in AVP_Value:
            while len(x)/2<calc_padding(len(x)/2):
                x=x+'00'
            p=p+x
        msg=getAVPDef(AVP_Name,p.decode("hex"))
    else:
        msg=getAVPDef(AVP_Name,AVP_Value)
    return msg

# Calculate message padding
def calc_padding(msg_len):
    return (msg_len+3)&~3 


#----------------------------------------------------------------------    
################################
# Main decoding routine  
# Input: single AVP as HEX string
def decodeAVP_As_Dict(msg):
    (scode,msg)=chop_msg(msg,8)
    (sflag,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    dbg="Decoding ","C",scode,"F",sflag,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=struct.unpack("!I",scode.decode("hex"))[0]
    mflags=ord(sflag.decode("hex"))
    data_len=struct.unpack("!I","\00"+slen.decode("hex"))[0]
    mvid=0
    if mflags & DIAMETER_FLAG_VENDOR:
        (svid,msg)=chop_msg(msg,8)
        mvid=struct.unpack("!I",svid.decode("hex"))[0]
        data_len-=4
    A=AVPItem()
    dictAVPcode2name(A,mcode,mvid)

    ret=""

    decoded=False
    if A.type in asI32:
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        ret= decode_Unsigned32(msg)
    if A.type in asU64:
        decoded=True
        ret= decode_Unsigned64(msg)
    if A.type in asF32:
        decoded=True
        ret= decode_Float32(msg)
    if A.type in asF64:
        decoded=True
        ret= decode_Float64(msg)        
    if A.type in asUTF8:
        decoded=True
        ret= decode_UTF8String(msg,data_len)
    if A.type in asIPAddress:
        decoded=True
        ret= decode_Address(msg)
    if A.type in asIP:
        decoded=True
        ret= decode_IP(msg)        
    if A.type in asTime:
        decoded=True
        ret= decode_Time(msg)
    if A.type=="Grouped":
        decoded=True
        ret= dictFromMsgAVPs(msg)
    if not decoded:
      # default is OctetString
      ret= decode_OctetString(msg,data_len)
    return {A.name:ret}

#----------------------------------------------------------------------    
################################
# Main decoding routine  
# Input: single AVP as HEX string
def decodeAVP(msg):
    (scode,msg)=chop_msg(msg,8)
    (sflag,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    dbg="Decoding ","C",scode,"F",sflag,"L",slen,"D",msg
    logging.debug(dbg)
    mcode=struct.unpack("!I",scode.decode("hex"))[0]
    mflags=ord(sflag.decode("hex"))
    data_len=struct.unpack("!I","\00"+slen.decode("hex"))[0]
    mvid=0
    if mflags & DIAMETER_FLAG_VENDOR:
        (svid,msg)=chop_msg(msg,8)
        mvid=struct.unpack("!I",svid.decode("hex"))[0]
        data_len-=4
    A=avps_by_code[(mvid,mcode)]
    #A=AVPItem()
    #dictAVPcode2name(A,mcode,mvid)
    ret=""
    decoded=False
    if A.type in asI32:
        ret= decode_Integer32(msg)
        decoded=True
    if A.type in asI64:
        decoded=True
        ret= decode_Integer64(msg)
    if A.type in asU32:
        decoded=True
        ret= decode_Unsigned32(msg)
    if A.type in asU64:
        decoded=True
        ret= decode_Unsigned64(msg)
    if A.type in asF32:
        decoded=True
        ret= decode_Float32(msg)
    if A.type in asF64:
        decoded=True
        ret= decode_Float64(msg)        
    if A.type in asUTF8:
        decoded=True
        ret= decode_UTF8String(msg,data_len)
    if A.type in asIPAddress:
        decoded=True
        ret= decode_Address(msg)
    if A.type in asIP:
        decoded=True
        ret= decode_IP(msg)        
    if A.type in asTime:
        decoded=True
        ret= decode_Time(msg)
    if A.type=="Grouped":
        decoded=True
        ret= decode_Grouped(msg)
    if not decoded:
      # default is OctetString
      ret= decode_OctetString(msg,data_len)
    return (A.name,ret)

# Search for AVP in undecoded list
# Return value if exist, ERROR if not    
def findAVP(what,list):
    for avp in list:
        if isinstance(avp,tuple):
           (Name,Value)=avp
        else:
           (Name,Value)=decodeAVP(avp)
        if Name==what:
           return Value
    return ERROR
    
#---------------------------------------------------------------------- 

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |    Version    |                 Message Length                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | command flags |                  Command-Code                 |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                         Application-ID                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Hop-by-Hop Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      End-to-End Identifier                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  AVPs ...
#   +-+-+-+-+-+-+-+-+-+-+-+-+-

# Join AVPs (add padding)
def joinAVPs(avps):
    data=""
    for avp in avps:
        while len(avp)/2<calc_padding(len(avp)/2):
            avp=avp+"00"
        data=data+avp
    return data

# Set flags to desired state    
def setFlags(H,flag):
    H.flags|=flag
    return

# Create diameter Request from <avps> and fields from Header H    
def createReq(H,avps):
    H.flags|=DIAMETER_HDR_REQUEST
    return createRes(H,avps)

# Create diameter Response from <avps> and fields from Header H     
def createRes(H,avps):
    # first add all avps into single string
    data=joinAVPs(avps)
    # since all data is hex ecoded, divide by 2 and add header length
    H.len=len(data)/2+20
    ret="01"+"%06X" % H.len+"%02X"%int(H.flags) + "%06X"%int(H.cmd)
    ret=ret+"%08X"%H.appId+"%08X"%H.HopByHop+ "%08X"%H.EndToEnd+data
    return ret

##########################johan egna funktioner#################################
# Create diameter Response from <avps> and fields from Header H and clear request flag and is also slimmed down
def createResponse(H,avps):
    data=joinAVPs(avps)
    H.len=len(data)/2+20
    ret="01"+"%06X" % H.len+"%02X"%int(H.flags&127) + "%06X"%int(H.cmd)
    ret=ret+"%08X"%H.appId+"%08X"%H.HopByHop+ "%08X"%H.EndToEnd+data
    return ret

# Create diameter Response from <avps> and fields from Header H and clear request flag and is also slimmed down
def createRequest(H,avps):
    data=joinAVPs(avps)
    H.len=len(data)/2+20
    ret="01"+"%06X" % H.len+"%02X"%int(H.flags|DIAMETER_HDR_REQUEST) + "%06X"%int(H.cmd)
    ret=ret+"%08X"%H.appId+"%08X"%H.HopByHop+ "%08X"%H.EndToEnd+data
    return ret
###############################################################################


# Set Hop-by-Hop and End-to-End fields to sane values    
def initializeHops(H):
    # Not by RFC, but close enough
    try:
        initializeHops.Hop_by_Hop+=1
        initializeHops.End_to_End+=1
    except:
        initializeHops.Hop_by_Hop=int(time.time())
        initializeHops.End_to_End=(initializeHops.Hop_by_Hop%32768)*32768
    H.HopByHop=initializeHops.Hop_by_Hop
    H.EndToEnd=initializeHops.End_to_End
    return 
    
#---------------------------------------------------------------------- 

# Main message decoding routine
# Input: diameter message as HEX string    
# Result: class H with splitted message (header+message)
# AVPs in message are NOT splitted
def stripHdr(H,msg):
    if len(msg)==0:
        return ERROR
    (sver,msg)=chop_msg(msg,2)
    (slen,msg)=chop_msg(msg,6)
    (sflag,msg)=chop_msg(msg,2)
    (scode,msg)=chop_msg(msg,6)
    (sapp,msg)=chop_msg(msg,8)
    (shbh,msg)=chop_msg(msg,8)
    (sete,msg)=chop_msg(msg,8)
    H.ver=ord(sver.decode("hex"))
    H.flags=ord(sflag.decode("hex"))
    H.len=struct.unpack("!I","\00"+slen.decode("hex"))[0]
    H.cmd=struct.unpack("!I","\00"+scode.decode("hex"))[0]
    H.appId=struct.unpack("!I",sapp.decode("hex"))[0]
    H.HopByHop=struct.unpack("!I",shbh.decode("hex"))[0]
    H.EndToEnd=struct.unpack("!I",sete.decode("hex"))[0]
    H.msg=msg
    return 

# Split AVPs from message
# Input: H.msg as hex string
# Result: list of undecoded AVPs
def splitMsgAVPs(msg):
    ret=[]
    while len(msg)<>0:
      slen="00"+msg[10:16]
      mlen=struct.unpack("!I",slen.decode("hex"))[0]
      #Increase to boundary
      plen=calc_padding(mlen)
      (avp,msg)=chop_msg(msg,2*plen)
      ret.append(avp)
    return ret

def dictFromMsgAVPs(msg):
    ret={}
    i=0
    
    while i<len(msg):
        slen="00"+msg[i+10:i+16]
        mlen=struct.unpack("!I",slen.decode("hex"))[0]
        #Increase to boundary
        plen=calc_padding(mlen)
        j=i+plen*2
        #(avp,msg)=chop_msg(msg,2*plen)
        ret.update(decodeAVP_As_Dict(msg[i:j]))
        i+=j
    return ret


#---------------------------------------------------------------------- 
 

def diameterGenerator(con):
    BUFFER_SIZE=4096
    msg="".encode('hex')
    while True:
        read,write,error=select.select([con],[],[],1)
        for r in read :
            if r == con:
                
                msg+=con.recv(BUFFER_SIZE).encode('hex')
                try:
                    length = int(msg[2:8],16)*2
                except:
                    length=0
                while len(msg)>=length:
                    rawdata,msg = chop_msg(msg,length)
                    if len(rawdata) == 0:
                        yield (None,None)
                    else:
                        H=HDRItem()
                        stripHdr(H,rawdata)
                        yield (H,dictFromMsgAVPs(H.msg))
                    if len(msg) < 9:
                        break
                    length = int(msg[2:8],16)*2



# Connect to host:port (TCP) 
def Connect(host,port):
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
    
#---------------------------------------------------------------------- 
# DateTime routines

def getCurrentDateTime():
    t=time.localtime()
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

# converts seconds since epoch to date
def epoch2date(sec):
    t=time.localtime(sec)
    return t.tm_year,t.tm_mon,t.tm_mday,t.tm_hour,t.tm_min,t.tm_sec

# converts to seconds since epoch
def date2epoch(tYear,tMon,tDate,tHr,tMin,tSec):  
    t=time.strptime("{0} {1} {2} {3} {4} {5}".format(tYear,tMon,tDate,tHr,tMin,tSec),"%Y %m %d %H %M %S")
    return time.mktime(t)    

######################################################        
# History
# Ver 0.1   - Feb 06, 2012 - initial version
# Ver 0.1.1 - Feb 07, 2012 - commands moved into dictionary
# Ver 0.1.2 - Feb 11, 2012 - internal reorganization, code cleanup
# Ver 0.2.0 - Feb 17, 2012 - EAP-Payload decoder
# Ver 0.2.1 - Feb 19, 2012 - EAP-Payload + AKA/AKA' C calculations
# Ver 0.2.2 - Feb 23, 2012 - Testing client AKA/AKA'
# Ver 0.2.3 - Feb 25, 2012 - Multiple bugfixes, logging
# Ver 0.2.4 - Mar 05, 2012 - Simplified dictionary, AVP types in sets
# Ver 0.2.5 - Mar 14, 2012 - Windows support (socket.inet_ntop, inet_pton)
# Ver 0.2.6 - Mar 18, 2012 - inet_ntop&pton now supports IPv6 on all platforms
# Ver 0.2.7 - May 12, 2012 - Grouped, Float support
# Ver 0.2.8 - May 25, 2012 - EAP functions moved to separate source
# Ver 0.3.1 - Nov 12, 2012 - bugfix in encoding grouped list (fixed wrong length)
#                          - ipv6 encoding bugfix, comments added
#                          - logging levels modified, Time support added
#                          - Enumerated now supports named values
#                          - Fixed IP handling (now supports IP & IPAddress packing)

#######################################################
#Johan Vallander's modifications
# Ver ??? - Jun 20, 2016 - speeded up using dictionaries, also added diameterGenerator function which returns the header, and a python dictionary of AVPs
