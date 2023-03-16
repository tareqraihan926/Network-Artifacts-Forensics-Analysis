**Network Forensics Report**

**Abstract**

This report contain the findings of a forensics investigation of attack scene on a series of packet Capture(PCAP) nad the vpn and access log. This report provides evidence that the attack scene & how they create this malformed connection in victim server. Suspect established the cross Connection via the vpn connection from the ducducgo services to permoed the malformed attack In the victim server by user & root in the valid ssh connection.

This Report attachment services & the evidence  also finds the attack & the addressing of the ips.

**Tools Used**

The tools used in this investigation were:

Sha1sum

Wireshark

Python 3

Visual Studio code Cyberchef Geolocation Founder Cat

Grep

wc

**File Hash:**

Access.log ( f33e0edc100c7746ce2892926b64209455245423 ) Route\_1.pcapng ( a552dec3e454f94e9c91921be9832c3823e9aa93 ) Route.pcap ( 49b557c22ed66589ac05556860301a345b012565 )

**Methodology & Findings**

**Capture 1 ( Access.log )**

Information given to the forensics investigator indicated the suspect download files which contained important or sensitive information from the authentication log file. Its included successful login attempt, invalid login, attack on user login, protocol and others various scenario. Upon Analysis, there were files transferred using various protocol using ssh & openvpn local server connection, protocol commonly used to access or tried authentication in the victim router network by their ovpn connection. All ip address can be found from this log that was tried to attempt.

Network Diagram:

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.001.png)

Access.log File or auth.log file with openvpn.log files can be found from setup virtual machine file system log directory. Like **/var/log**

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.002.jpeg)

Here are some invalid login user attempt by the hacker connection tried to access in

server.

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.003.jpeg)

Like Length, How much tried to attempt using to user login & root access login included fault login attempt & successful login attempt in this attack.![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.004.png)

Its also means the Authentication failure s list from this log, seen in given below image.Remote host also included in this log by the consider with openvpn connection. We need to find the attackers multiple changing ip address that we can clarify that their tried connection where its from. List will be shown in below.

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.005.jpeg)

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.006.jpeg)

Logname with uid & euid with the server response

\*All IP addresses list & their details will be shown in attachment files. We can check from these.

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.007.jpeg)

Here is the exact Accepted publickey means accepted user from the tried section. Hacker using a random server by using open vpn connection and established the connection. SHA256 hash for RSA encryption secure connection presented in this log.

**Capture 2 ( Openvpn.log )**

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.008.jpeg)

Openvpn file .ovpn connection for attack and attempt to the user & root session in the Target server.

Openvpn log data also included in the authentication access log dataset. **Capture 2 ( router packet from Destination site )**

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.009.jpeg)

De-authentication & Acknowledgement

- Account was used to log into the local server via TELNET- (username and password)

p2-server login: sstevenson

.

Password: R3@LLYG00Dp@$$w0rd!

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.010.png)

- Account was used to log into the local router via HTTP- http\_id=TIDd60f245957fb603a

Associated js & source File Attached.

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.011.jpeg)

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.012.jpeg)

This is the source file screenshot and main source file attached with the evidence

section.

- According to DNS in the capture, IP address hosts the duckduckgo.com website–

IP: 40.89.244.232

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.013.jpeg)

In this section, we can see that hacker using duckduckgo service for hide the source connection. From the previous authentication log files we saw that multiple ip connection attempt for authentication in pam\_unix. We can find from dns packet section for ducducgo.

- DNS server(s) is/are being used to resolve names to IPs-

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.014.jpeg)

Here we found the most phase of network forensics, dns resolve names ips for The openvpn connection.

**Capture 2 ( router packet from source site )**

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.015.jpeg)

Routing Information packet Generation for Deauthentication & Acknowledgement

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.016.jpeg)

Capture source site packet when attacker used openvpn connection for setup and target the attack

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.017.jpeg)

Wireless Packet Statistics

We are extracted the packet for the wireless to check the hacker activities. We found their Malformed source code here(Also attached in evidence)-

//

wl\_ifaces = [['eth1','0',0,-1,'FreshTomato24','A0:04:60:CA:6C:B6',1,16,'ap','00:00:00:00:00:00']];

//

wl\_bands = [ [ '2'] ];

//

nvram = {

'wl\_nband': '2',

'wl0\_nband': '2',

'wl\_unit': '0',

'http\_id': 'TIDd60f245957fb603a', 'web\_mx': 'status,bwm',

'web\_pb': ''};

function wl\_fface(uidx) { return wl\_ifaces[uidx][1]; }

function wl\_unit(uidx) { return wl\_ifaces[uidx][2]; }

function wl\_sunit(uidx) { return wl\_ifaces[uidx][3]; }

function wl\_uidx(unit) {

for (var u = 0; u < wl\_ifaces.length; ++u) {

if (wl\_ifaces[u][2] == unit) return u;

}

return -1;

}

function wl\_ifidx(ifname) {

for (var u = 0; u < wl\_ifaces.length; ++u) {

if (wl\_ifaces[u][0] == ifname) return u;

}

return -1;

}

function wl\_ifidxx(ifname) {

for (var u = 0; u < wl\_ifaces.length; ++u) {

if (wl\_ifaces[u][1] == ifname) return u;

}

return -1;

}

function wl\_display\_ifname(uidx) {

return wl\_ifaces[uidx][0]+(wl\_sunit(uidx) < 0 ?

- (wl'+wl\_fface(uidx)+')' : '')+((wl\_bands[uidx].length == 1) ?

((wl\_bands[uidx][0] == '1') ? ' / 5 GHz' : ' / 2.4 GHz') : ((nvram['wl'+wl\_unit(uidx)+'\_nband'] ==1) ?

- / 5 GHz' : ' / 2.4 GHz'));

}

And the status section is-

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.018.jpeg)From Analyze the source packet & the source code, we can identify the pptp server ip stat and The netmask of hacker connection. We can prove it from the Authentication log file again. Let Me check that-

![](Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.019.jpeg)
