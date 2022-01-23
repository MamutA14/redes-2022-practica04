# Manual de uso
### Alam Acosta Meza(Núm de cuenta: 315124569)
## Principios
Un sniffer es un analizador de todo el tráfico de red 
Analizara diferentes tipos de protocolos UDP ICMP y TCP
Se necesitan permisos de superusuario para poder así analizar todo el tráfico  
En la practica se hace la traducción de cada protocolo y la traducciṕn de sus bytes.
Ordenarlos por la cabecera . Se utilizan las cabezeras de ipv6 para la traducción. Y lo que se hace es una transformaciń de los datos
    
## Requerimientos
- Tener instalado python 3.x
- Tener privilegios de administrador
- Sistema operativo Linux
## Ejecucción
Para poder llamar el sniffer se requiere que haya ciertos permisos de superusuario. Por ello siempre debe de llamarse de la siguiente manera:

                                                       `> sudo python3 sniffer.py`
Con esta ejecucción el sniffer hace un analisis de red con los protocolos de transporte (UDP y TCP) y de ICMP al mismo tiempo si solo quiere monitorearse un protocolo en particular se debe seguir el patón anterior y agregar el nombre respectivo:
                                                       `> sudo python3 sniffer.py UDP`
													   `> sudo python3 sniffer.py TCP`
													   `> sudo python3 sniffer.py ICMP`
Todo el nombre del protocolo  mayusculas.
## Soporte
- Soporta IPv4 :ICMP ,UDP, TCP
- Soporta IPv6 :ICMP ,UDP, TCP