import socket
import struct
import textwrap
import binascii
import struct
import sys
import http
'''
Un sniffer es una herramienta de software o hardware que permite al usuario
supervisar su tráfico en Internet en tiempo real y capturar todo el tráfico de datos
que entran y salen de su equipo.Aqui se presenta una implementación de un sniffer que 
analiza los protocolos UDP TCP e ICMP en base a una red ethernet LAN la cual este conectada
el dispotivo que se ejecuta
'''
TAB_1 = '\t - '
DATA_TAB_1 = '\t   '

def main():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  #Definiendo nuestro socket como socket_raw se incluyen los paquetes de cabezera del protocolo, y recibira un entero que represente el protocolo a utilizar 
    #Listas con el nombre respectivo del protocolo junto con su entero identificador
    filters = (["ICMP", 1, "ICMPv6"],["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    #Cuando se declare un protocolo en particular en la ejecución
    #> sudo python3 sniffer.py [PROTOCOLO_NOMBRE]
    #Imprimira el nombre del protocolo
    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        for f in filters:
            if sys .argv[1] == f[0]:
                filter = f



    while True: #Esuchando todo el tiempo
        raw_data, addr = conn.recvfrom(65536) # Va a estar escuchando a traves del puerto 65536 para recibir datos
        
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data) # Se recebiran los bytes que corresponden a la dir_destino mac, dir_ fuete mac y el protocolo utilizado 

        #Solo pueden ser IPV4 o IPV6 entonces se imprimen los respectivos paquetes(con su formato)
        if eth_proto == 'IPV6':
            newPacket, nextProto = ipv6Header(data, filter)
            printPacketsV6(filter, nextProto, newPacket)

        elif eth_proto == 'IPV4':
            printPacketsV4(filter, data, raw_data)


'''
En caso de que el protocolo del frame de internet sea IPV4 se
imprimiran los datos de los datagramas(del respectivo protocolo de transporte) que tenga su paquete 
'''
def printPacketsV4(filter, data, raw_data):
    (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data) #desempaqueta los paquetes recibidos de IPv4

    # PROTOCOLO ICMP
    if proto == 1 and (len(filter) == 0 or filter[1] == 1): #En caso de que se llamen en la linea de comandos o no se llame ningún conmando
        icmp_type, code, checksum, data = icmp_packet(data) #Datos de ICMP
        print ("*******************ICMP***********************")
        print (DATA_TAB_1+"ICMP type: %s" % (icmp_type))
        print (DATA_TAB_1+"ICMP code: %s" % (code))
        print (DATA_TAB_1+"ICMP checksum: %s" % (checksum))

    # PROTOCOLO  TCP
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6): #En caso de que se llamen en la linea de comandos o no se llame ningún conmando
        print("*******************TCPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24]) # H 16 bits L 32 bits
        print('*****TCP Segment*****')
        print('Source Port: {}\nDestination Port: {}'.format(src_port, dest_port))
        print('Sequence: {}\nAcknowledgment: {}'.format(sequence, acknowledgment))
        print('*****Flags*****')
        print('URG: {}\nACK: {}\nPSH: {}'.format(flag_urg, flag_ack, flag_psh))
        print('RST: {}\nSYN: {}\nFIN:{}'.format(flag_rst, flag_syn, flag_fin))

        if len(data) > 0:
            # HTTP
            if src_port == 80 or dest_port == 80:
                print('*****HTTP Data*****')
                try:
                    http = HTTP(data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(format_output_line("",data))
            else:
                print('*****TCP Data*****')
                print(format_output_line("",data))
    # PROTOCOLO UDP
    elif proto == 17 and (len(filter) == 0 or filter[1] == 17):#En caso de que se llamen en la linea de comandos o no se llame ningún conmando
        print("*******************UDPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, length, data = udp_seg(data)
        print('*****UDP Segment*****')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, length))

'''
Función que dependiendo del protocolo
siguiente se llamara elegira el formato
de impresión correspondiente a los protocolos: ICMPv6, TCP o UDP
'''
def printPacketsV6(filter, nextProto, newPacket):
    remainingPacket = ""

    if (nextProto == 'ICMPv6' and (len(filter) == 0 or filter[2] == "ICMPv6")):
        remainingPacket = icmpv6Header(newPacket)
    elif (nextProto == 'TCP' and (len(filter) == 0 or filter[2] == "TCP")):
        remainingPacket = tcpHeader(newPacket)
    elif (nextProto == 'UDP' and (len(filter) == 0 or filter[2] == "UDP")):
        remainingPacket = udpHeader(newPacket)

    return remainingPacket

'''
Se desempaquetaran los valores del encabezado
y los datos que contiene cada segmento tipo TCP
*Puerto de origen (16 bits)
*Puerto de destino (16 bits)
*Número de secuencia (32 bits)
*Número de confirmación de recepción (32 bits)
*Longitud del encabezado TCP (4 bits)
*Banderas de TCP: URG, ACK, PSH, RST, SYN,FIN (1 bit c/uno)
*Tamaño de ventana(16 bits)
*Checksum (16 bits)
*Apuntador urgente (16 bits)
'''
def tcpHeader(newPacket):
    packet = struct.unpack("!2H2I4H", newPacket[0:20]) #Se desampaquetaran varios datos del paquete H representa 2 bits(unsigned short), I representa 4 bits(unsigned int), 2H+2I+4H =20 
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12 #Lo recorre 12 bits quedan 4 
    reserved = (packet[4] >> 6) & 0x003F #Lo recorre  6 bits a la izquierda quedan 10 ignora los primeros 4(los de longitud)  y se queda con los 6 que representan los bits sin utilizar
    tcpFlags = packet[4] & 0x003F # Con el operador  "&"  y 0x003F = 111111 ignora los 10 primeros bits y se enfoca en los 6 bits que corresponden a las banderas   
    urgFlag = tcpFlags & 0x0020  # Con el operador "&"  y  0x0020 = 100000 solo considera el bit de urg
    ackFlag = tcpFlags & 0x0010 # Con el operador "&"  y  0x0010 = 010000 solo considera el bit de ack
    pushFlag = tcpFlags & 0x0008 # Con el operador "&"  y  0x0008 = 001000 solo considera el bit de push 
    resetFlag = tcpFlags & 0x0004 # Con el operador "&"  y  0x0004 = 000100 solo considera el bit de reset
    synFlag = tcpFlags & 0x0002 # Con el operador "&"  y  0x0002 = 000010 solo considera el bit de syn
    finFlag = tcpFlags & 0x0001 # Con el operador "&"  y  0x0001 = 000001 solo considera el bit de fin
    window = packet[5]  
    checkSum = packet[6]
    urgPntr = packet[7]

    #Imprime los datos de la cabezera
    print ("*******************TCP***********************")
    print (DATA_TAB_1+"Source Port: "+str(srcPort) )
    print (DATA_TAB_1+"Destination Port: "+str(dstPort) )
    print (DATA_TAB_1+"Sequence Number: "+str(sqncNum) )
    print (DATA_TAB_1+"Ack. Number: "+str(acknNum) )
    print (DATA_TAB_1+"Data Offset: "+str(dataOffset) )
    print (DATA_TAB_1+"Reserved: "+str(reserved) )
    print (DATA_TAB_1+"TCP Flags: "+str(tcpFlags) )

    #Si en caso dado que tengan un bit de confirmación se manda a imprimir el mensaje de la respectiva bandera
    if(urgFlag == 32):
        print (DATA_TAB_1+"Urgent Flag: Set")
    if(ackFlag == 16):
        print (DATA_TAB_1+"Ack Flag: Set")
    if(pushFlag == 8):
        print (DATA_TAB_1+"Push Flag: Set")
    if(resetFlag == 4):
        print (DATA_TAB_1+"Reset Flag: Set")
    if(synFlag == 2):
        print (DATA_TAB_1+"Syn Flag: Set")
    if(finFlag == True):
        print (DATA_TAB_1+"Fin Flag: Set")

    print (DATA_TAB_1+"Window: "+str(window))
    print (DATA_TAB_1+"Checksum: "+str(checkSum))
    print (DATA_TAB_1+"Urgent Pointer: "+str(urgPntr))
    print (" ")

    packet = packet[20:]
    return packet

'''
Se imprimira del segmento(transmitido por el 
protocolo UDP) los primeros 8 bytes que conforman 
 * Puerto de origen (16 bits)
 * Puerto de destino (16 bits)
 * Longitud de UDP (16 bits)
 * La suma de verificación (16 bits)
Y devolvera el conjunto de datos(que son los bytes restantes)  
'''
def udpHeader(newPacket):
    packet = struct.unpack("!4H", newPacket[0:8]) # ! big endian(network), H 16 bits por lo que cada posición del arreglo packet sera de 2 bytes 
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    #Imprime los valores
    print ("*******************UDP***********************")
    print (DATA_TAB_1+"Source Port: "+str(srcPort))
    print (DATA_TAB_1+"Destination Port: "+str(dstPort))
    print (DATA_TAB_1+"Lenght: "+str(lenght))
    print (DATA_TAB_1+"Checksum: "+str(checkSum))
    print (" ")

    packet = packet[8:] 
    return packet


'''
Obtiene los datos del paquete de ICMPv6
*Tipo (8 bits)
*Código (8 bits)
*Checksum (16 bits)
*Datos(32 bits)
Los campos de ID y secuencia de número son ineccesarios debido que ipv6 no hay fragmentación
'''
def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4]) #> representa big endian, B 8 bits, H 16 bits, la suma es 32 bits que corresponde al total del 1er renglon del encabezado

    #Imprime los valores de la cabezera 
    print ("*******************ICMPv6***********************")
    print (DATA_TAB_1+"ICMPv6 type: %s" % (ipv6_icmp_type))
    print (DATA_TAB_1+"ICMPv6 code: %s" % (ipv6_icmp_code))
    print (DATA_TAB_1+"ICMPv6 checksum: %s" % (ipv6_icmp_chekcsum))

    data = data[4:]
    return data


'''
Dependiendo del número que dicte el paquete  IPv6 se dictara el campo  
de la siguiente cabezera
'''
def nextHeader(ipv6_next_header):
    if (ipv6_next_header == 6):
        ipv6_next_header = 'TCP'
    elif (ipv6_next_header == 17):
        ipv6_next_header = 'UDP'
    elif (ipv6_next_header == 43):
        ipv6_next_header = 'Routing'
    elif (ipv6_next_header == 1):
        ipv6_next_header = 'ICMP'
    elif (ipv6_next_header == 58):
        ipv6_next_header = 'ICMPv6'
    elif (ipv6_next_header == 44):
        ipv6_next_header = 'Fragment'
    elif (ipv6_next_header == 0):
        ipv6_next_header = 'HOPOPT'
    elif (ipv6_next_header == 60):
        ipv6_next_header = 'Destination'
    elif (ipv6_next_header == 51):
        ipv6_next_header = 'Authentication'
    elif (ipv6_next_header == 50):
        ipv6_next_header = 'Encapsuling'

    return ipv6_next_header

'''
Metodo que devuelve los datos
y el tipo de encabezado de extensión(decide como 
dirigir o procesar un paquete IPV6)
*Version (4 bits)
*Trafic class (8 bits)
*Etiqueta de flujo (20 bits)
*Longitud de carga (16 bits)
*Next Header (8 bits)
*Limite de salto (8 bits)
*Dirección fuente (128 bits)
*Dirección destino (97 bits)

 
'''
def ipv6Header(data, filter):
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(
        ">IHBB", data[0:8]) #> Representa big endian, I 32 bits, H 16 bits, B 8 bits haciendo la suma toma los datos que corresponde a  los campos de : version, trafic class y flow label
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24]) # 16 bytes (8-24 valores de 1 byte) los datos se convierten en str   
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40]) # 16 bytes (24-40 valores de 1 byte) los datos se convierten en str

    bin(ipv6_first_word) #la primera palabra se traduce a binario
    "{0:b}".format(ipv6_first_word) #Tendra un formato de binario
    version = ipv6_first_word >> 28 #Se toman los primeros 4 bits que representan los bits
    traffic_class = ipv6_first_word >> 16 #Luego de tomar los bits de version se mueven menos espacios a la derecha para obtener los campos de trafic class y etiqueta de flujo
    traffic_class = int(traffic_class) & 4095 # bin(4095) = 0000111111111111  con el operador & se omiten los bits que corresponden al campo version  
    flow_label = int(ipv6_first_word) & 65535 # bin(65535)= 00000000000000001111111111111111 con el operador se omiten los bits que corresponden a los anteriores campos

    ipv6_next_header = nextHeader(ipv6_next_header) #Dependiendo del número que dicte el paquete sera la  siguiente cabezera 
    data = data[40:] 

    return data, ipv6_next_header

'''
En una red Ethernet multiples aparatos
comparten datos usando paquetes.
Estos contienen junto con otras cosas
un marco (ethernet frame). Este consiste
en código binario que provee información importante
como direcciones, información de control y el tipo de dato
que el marco carga    

Esta función desempaqueta el marco de Ethernet II
*Dirección destino MAC (24 bits)
*Dirección fuente MAC (24 bits)
* Tipo (16 bits)
* Datos (46-1500 bytes)
FCS no se considera 
'''
def ethernet_frame(data):
    proto = ""
    IpHeader = struct.unpack("!6s6sH",data[0:14]) # Se toman en cuenta tres valores a desempaquetar (dir-destino, dir-fuente y tipo)  la palabra clave s: arreglo de bytes(se define 6 así que 24 bits), H: 2 bytes(16 bits)
    #Como los datos estan en binarios se hace una traducción de hexadecimal
    dstMac = binascii.hexlify(IpHeader[0]) 
    srcMac = binascii.hexlify(IpHeader[1]) 
    protoType = IpHeader[2]
    #Para identificar si el tipo(ipv4,ipv6,ipx,arp,...) se necesita cambiar a hexadecimal 
    nextProto = hex(protoType) 

    if (nextProto == '0x800'): 
        proto = 'IPV4'
    elif (nextProto == '0x86dd'): 
        proto = 'IPV6'

    data = data[14:]

    return dstMac, srcMac, proto, data

'''
Función que le  
dara formato a las direcciones macs 
'''
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) #x Significa que el formato sera de hexadecimal, si la dirección esta como int o long lo convertira en un valor de ese tipo. Ahora el 02 significa si el digito contiene  menos de 2 cifras se antepondra un cero
    mac_addr = ':'.join(bytes_str).upper() #Se pondra en mayusculas algunos números que poseen letras
    return mac_addr

'''
Desempaqueta los paquetes recibidos de IPv4
eso incluye su cabezera y los datos que carga
*Versión
* Tiempo de vida
* Protocolo
* Dirección de origen 
* Dirección de destino
* Los demás valores del encabezado no se toman en cuenta
'''
def ipv4_Packet(data):
    version_header_len = data[0] #Se obtiene el tamaño de la version de la cabezera. Es el primer valor del data ya que así esta representado
    version = version_header_len >> 4 # Se obtiene la versión desplazando bits a la izquierda 
    header_len = (version_header_len & 15) * 4 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #Se obtienen los datos de la cabezera  correspondientes la x representa que se ignoran los bytes correspondientes: B representa un byte y s implica un arreglo de bytes 
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

'''
Devuelve la dirección Ipv4 en formato de cadena
'''
def ipv4(addr):
    return '.'.join(map(str, addr))


'''
Se desempaquetaran los valores  de encabezado y los datos
que carga el protocolo ICMP
*Tipo (8 bits)
*Código (8 bits)
*Checksum (8 bits)
Identificador, número de sequencia (no se consideran)
'''
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4]) # Se obtienen los primeros datos de cabezera y los datos las palabras claves B signifcan que se extrae 1 byte y H 2 bytes
    return icmp_type, code, checksum, data[4:]

'''
Se desempaquetaran los valores del encabezado
y los datos que contiene cada segmento tipo TCP
*Puerto de origen (16 bits)
*Puerto de destino (16 bits)
*Número de secuencia (32 bits)
*Número de confirmación de recepción (32 bits)
*Longitud del encabezado TCP (4 bits)
*URG, ACK, PSH, RST, SYN,FIN (1 bit c/uno)
Tamaño de ventana,Checksum,apuntador urgente (no se devuelven )
'''
def tcp_seg(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14]) # Se obtienen los primeros datos de cabezera las palabras claves H signifcan que se extrae 2 bytes y L 4 bytes
    offset = (offset_reserved_flag >> 12) * 4 #Se obtienen la posición donde se ubican los datos despues de las banderas
    #Para obtener las banderas correspondientes de URG, ACK, PSH, RST, SYN,FIN
    #se queda con un bit (o no) correspondiente al segmento de todas las banderas  y se desplaza hacia la derecha la posición que corresponde a la bandera  
    flag_urg = (offset_reserved_flag & 32) >> 5 
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


'''
A diferencia del udp_header
este no imprime el header de
un segmento de UDP  más bien devuelve
los valores  de cabezera (excepto por el checksum que 
es opcional) y los datos que envia 
'''
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8]) #Toma los bits de cada sección del encabezado pero lo de la suma de verificación los ignora 
    return src_port, dest_port, size, data[8:] # Los bytes que restan seran los datos del cuerpo de UDP

'''
Función que le dara formato a 
la linea de salida'''
def format_output_line(prefix, string):
    size=80
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
