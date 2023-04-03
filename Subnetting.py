import argparse
from termcolor import colored
import re
from os import sys
import math

# ===========================================================================================================================================================================================================
# Low level Functions
# Used by the core functions to modify and retrive data from the user input.
# Those Functions can be described as a low level functionality
# cod Var is always used for local variable use only

def str_dot(cod):# ---------------------------------- Add dots to a string containing an address without dots used for processing input data
    return '.'.join(cod[i:i+8] for i in range(0, len(cod), 8))

def ExpressPos():#---------------------------------- Index position of the splitted DDN Mask where the sub.host part beigan
    global expos
    mask = sid[1].split('.')#Insert the splitted dotted notation value of the 'mask' in a variable

    for x in range(0, len(mask)):		 #|
        if mask[x] != '255' and x != '0':#|			For loop used for finding the 'expos'(Index Position),
            expos = x 					 #| where the host part has given away bits in order to create the subnet
        elif mask[x] == '0':			 #|
            expos = x 					 #|

    return expos #Return expos (int)

def binadd(cod):#----------------------------------- convert from decimal address to binary address
    cod = cod.split('.') # Address is splitted in a list removing dots

    for i in range(0, len(cod)):		#|
        cod[i] = bin(int(cod[i]))[2:]   #|			For loop used to convert every item of the spletted address
                                        #|								in binary
        if len(cod[i]) < 8:				#|
            n = 8 - len(cod[i])			#|
            cod[i] = ('0' * n) + cod[i] #|

    return '.'.join(cod)# The Binary address is now returned from the function as a string adding dots preaviusly deleted.

def decadd(cod):#----------------------------------- convert from binary address to decimal address
    cod = cod.split('.') # Address is splitted in a list removing dots

    for i in range(0, len(cod)):	#|			For loop used to convert the address fom binary to
        cod[i] = str(int(cod[i], 2))#|								decimal.

    return '.'.join(cod)#Return the address in string format adding dots


#=============================================================================================================================================================================
#CORE FUNCTIONS
#Used by the Main function, are the core Functions of the program

def subadd():#----------------------------------- Find the subnet id
    global subid
    cod = binadd(add).replace('.', '')# Var containing the argument passed(address), without dots
    hostb  = 32 - sid[0]#-------------- Hostbit (TOTAL BITS(32) - NETWORK.SUB BITS)
    payload = '0' * hostb#------------- Payload of zero's needed to find the subnet ID
    cod1 = cod[:-hostb] + payload #---- Attach the payload to the address
    cod2 = str_dot(cod1)#-------------- Add dots to the address
    subid = decadd(cod2)#-------------- Transform the address in to the decimal version

    return subid # Return the Subnet ID

def brodadd():#---------------------------------- Find the brodcast id
    global brodid
    hostb = 32 - sid[0]#--------------------Hostbit (TOTAL BITS(32) - NETWORK.SUB BITS)
    netb = 32 - hostb#----------------------Networkbits (TOTAL BITS(32) - HOST BITS))
    payload = '1' * hostb #-----------------Payload of zero's needed to find the Brod ID
    cod = binadd(subid).replace('.', '')#-----Var containing the argument passed(address), without dots
    cod1 = cod[:-hostb] + payload #---------Attach the payload to the address
    cod2 = str_dot(cod1)#-------------------Add dots to the address
    brodid = decadd(cod2)#------------------Transform the address in to the decimal version

    return brodid# Return The Brodcast ID  as a string

def SetVarId(mask):#---------------------------------- Set in a global list the 2 mask format(Prerfix[0] and DDN[1])
    global sid
    sid = []
    if len(mask) == 3 or len(mask) == 2:							#|					Check if the input passed is a Prefix format,
        sid.append(int(mask[1:]))									#|						append Prefix to the global sid[0]
        maskb = ('1' * int(mask[1:])) + ('0' * (32 - int(mask[1:])))#|			create a the relative DDN Format, append the DDN to the global sid[1]
        maskd = str_dot(maskb)										#|
        sid.append(decadd(maskd))									#|
    else:
        cod = binadd(mask).replace('.', '')							#|					Check if the input passed is a DDN format,
        mask1 = 0 													#|						append DDN to the global sid[1];
        for x in cod: 												#|			create a the relative Prefix Format, append the DDN to the global sid[0]
            if x == '1': 											#|
                mask1 = mask1 + 1 									#|
        sid.append(mask1)											#|
        sid.append(mask)											#|

    return #Nothing returned Global List(sid[]) already initialaized

def FirstAdd(): #---------------------------------- Find the addresses range of the subnet
    global Fadd
    exsub = subid.split('.')

    if ExpressPos() == '3':							#|			Chek if the mask is /24
        exsub[expos] = str(int(exsub[expos]) + 1)	#|		Add 1 to the sub ID to find the first address
        Fadd = '.'.join(exsub)						#|			merge the list elemtents in a string
        bina = binadd(Fadd)							#|		create a binary address of the first address

    else:
        for x in range((expos + 1), 2):				#|		Skip items the list till the last octect,
            exsub[x] = '0'							#|
        exsub[3] = str(int(exsub[3]) + 1)			#|				add 1 to the last octect,
        Fadd = '.'.join(exsub)						#|			join all the octect in a string
        bina = binadd(Fadd)							#|		save the binary version of the First address

    return Fadd# Return the first address

def LastAdd(): #---------------------------------- Find the lat address of the subnet
    global LastAdd

    exbrod = brodid.split('.')				#|
    exbrod[3] = str(int(exbrod[3]) - 1)		#|		Sottract 1 to the last octect of the address,
    Ladd = '.'.join(exbrod)					#|				join the address in a string
    bina = binadd(Ladd)						#|			create a binary version of the adress

    return Ladd # Return Last Address

def Add_map():#---------------------------------- Print the mapped range of the given address using the global variable initialazed in the other functions
    if iteration == 0 or iteration == None: #If Global variable iteration is greater than 0 use the return value of subadd() to initialize the subid global variable
        print("Sub ID:  \n" + colored(subadd(), 'green'))
    else:
        print("Sub ID:  \n" + colored(subid, 'green'))
    print("Brod ID:  \n" + colored(brodadd(),'green'))
    print("First Address:  \n" + colored(FirstAdd(), 'green'))
    print("Last Address:  \n" + colored(LastAdd(), 'green'))
    print("DDN and CIDR Prefix: \n" + colored(str(sid[1]), 'green') + colored('/', 'red') + colored(str(sid[0]), 'red'))

    return

def Set_mask(cod):#----------------------------------------------- Set the mask in order to fit the given hosts passed to the function
    return str('/' + str(32 - int(math.ceil(math.log(int(cod) + 2)/math.log(2)))))

def Next_sub():#------------------------- calculate the next subnet from the preavius Broadcast address
    cod = brodid.split('.')
    cod1 = expos
    if cod[cod1]!= "255":
        cod[cod1] = str(int(cod[cod1]) + 1)
        return '.'.join(cod)
    else:
        while cod[cod1] == "255":
            cod1 = cod1 - 1
        cod[cod1] = str(int(cod[cod1]) + 1)
        for x in range((cod1 + 1), len(cod)):
            cod[x] = "0"
        return '.'.join(cod)

#=========================================================================================================================================
#ERROR INPUT HANDLING
#Needed for validate the command-line input

def Check_hosts(cod):#-------------------------------- Check the input given for the hosts to be an integer between a range (1-16777216)
    for item in cod:
        if int(item) not in range(16777217):
            raise argparse.ArgumentTypeError('\n\nInput "{0}" not valid (Got to be an integer rappresenting hosts needed on a subnet)\n\nType "-h" for help'.format(colored(cod, 'red')))
        else:
            pass
    return cod

def Check_class(add, mask):#------------------------------------ Check if the mask is valid compared to the address' class minimum prefix (Network)
    global Prfx_class
    if re.fullmatch('^([1-9]?\d|1[01]\d|12[0-6])(\.([1-9]?\d|[12]\d\d)){3}$', add) == None:
        if re.fullmatch('^(12[89]|1[3-8]\d|19[01])(\.([1-9]?\d|[12]\d\d)){3}$', add) == None:
            if re.fullmatch('^(19[2-9]|2[01]\d|22[0-3])(\.([1-9]?\d|[12]\d\d)){3}$', add) == None:
                raise sys.exit('Address "{0}" not valid, class D addresses can\'t be subnetted'.format(colored(add, 'red')))
            else:
                Prefix_class = [24, 2]
                if mask < Prefix_class[0]:
                    raise sys.exit('Address "{0}" not valid with  mask "/{2}"({3}), mask can\'t be less than "/{1}" for a Class C Address!'.format(colored(add, 'green'), colored(Prefix_class[0], 'green'), colored(mask, 'red'), colored(sid[1], 'red')))
                else:
                    return
        else:
            Prefix_class = [16, 1]
            if mask < Prefix_class[0]:
                raise sys.exit('Address "{0}" not valid with  mask "/{2}"({3}), mask can\'t be less than "/{1}" for a class B address!'.format(colored(add, 'green'), colored(Prefix_class[0], 'green'), colored(mask, 'red'), colored(sid[1], 'red')))
            else:
                return
    else:
        Prefix_class = [8, 0]
        if mask < Prefix_class[0]:
             raise sys.exit('Address "{0}" not valid with  mask "/{2}"({3}), mask can\'t be less than "/{1}" for a class A Address!'.format(colored(add, 'green'), colored(Prefix_class[0], 'green'), colored(mask, 'red'), colored(sid[1], 'red')))
        else:
            return

def CheckAdd(cod):
    if re.fullmatch(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', cod) == None:
        raise argparse.ArgumentTypeError('\n\nInput "{0}" not valid\n\nType "-h" for help'.format(colored(cod, 'red')))
    else:
        return cod

def CheckMask(cod):
    if re.fullmatch(r'^\/((3[0-1])|([1-2][0-9]{1})|([1-9]))$', cod) == None:
        if re.fullmatch(r'^(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))$', cod) == None:
            raise argparse.ArgumentTypeError('\n\nInput "{0}" not valid\n\nType "-h" for help'.format(colored(cod, 'red')))
        else:
            return cod
    else:
        return cod
#=============================================================================================================================================================================
#Main function
#find a way to operate with files
if __name__ == '__main__':
    global add

    parser = argparse.ArgumentParser(prog='Subnetting', usage='Calculate the range address,the subnet ID and broadcast ID from a given address and mask.\nYou can also subnet a given network from given hosts for every subnet, giving as argumets NETWORK and a list of HOSTS needed for every subnet.\n\nExemple: \n-a 10.0.0.0 -n 200 123 25',
            description='Type an IPV4 address, a mask and the magic will happend', epilog='D4x3R', formatter_class=argparse.RawDescriptionHelpFormatter, prefix_chars='-',
            fromfile_prefix_chars='@', argument_default=None, conflict_handler='error', add_help=True, allow_abbrev=True, exit_on_error=True)

    parser.add_argument('-a', '--add', type=CheckAdd, required=True, metavar='', help='IPV4 Address')
    parser.add_argument('-m', '--mask', type=CheckMask, required=False, metavar='', help='Prefix or DDN Mask')
    parser.add_argument('-n', '--hosts', nargs = '*', type=Check_hosts, required=False, metavar='', help='Hosts nedeed for every Subnet')
    args = parser.parse_args()

    global iteration
    iteration = None

    if args.hosts:
        args.hosts.sort(key = int, reverse = True)
        for iteration, item in enumerate(args.hosts):
            if iteration == 0:
                add = args.add
            else:
                subid = Next_sub()
            mask = Set_mask(item)
            SetVarId(mask)
            Check_class(add, int(sid[0]))
            print('Subnet for {0} Hosts'.format(colored(item, 'red')))
            Add_map()
            print('=================================')
    else:
        add = args.add
        SetVarId(args.mask)
        Check_class(add, int(sid[0]))
        Add_map()
