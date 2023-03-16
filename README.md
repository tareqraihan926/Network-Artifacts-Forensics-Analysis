<div align="center">
  <h2 align="center">Network Forensics Report</h2>
 


</div>

## Abstract

This report contain the findings of a forensics investigation of attack scene on a series of packet Capture(PCAP) nad the vpn and access log. This report provides evidence that the attack scene & how they create this malformed connection in victim server. Suspect established the cross Connection via the vpn connection from the ducducgo services to permoed the malformed attack In the victim server by user & root in the valid ssh connection.

This Report attachment services & the evidence  also finds the attack & the addressing of the ips.


## Tools Used

The tools used in this investigation were:

      Sha1sum

      Wireshark

      Python 3

      Visual Studio code Cyberchef Geolocation Founder Cat

      Grep

      wc

## File Hash:

      Access.log ( f33e0edc100c7746ce2892926b64209455245423 )
      Route_1.pcapng ( a552dec3e454f94e9c91921be9832c3823e9aa93 )
      Route.pcap ( 49b557c22ed66589ac05556860301a345b012565 )

## Methodology & Findings

<b>Capture 1 ( Access.log )</b>

Information given to the forensics investigator indicated the suspect download files which contained important or sensitive information from the authentication log file. Its included successful login attempt, invalid login, attack on user login, protocol and others various scenario. Upon Analysis, there were files transferred using various protocol using ssh & openvpn local server connection, protocol commonly used to access or tried authentication in the victim router network by their ovpn connection. All ip address can be found from this log that was tried to attempt.

Network Diagram:

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.001.png" width="" height="">
</p>

Access.log File or auth.log file with openvpn.log files can be found from setup virtual machine file system log directory. Like **/var/log**

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.002.jpeg" width="" height="">
</p>


Here are some invalid login user attempt by the hacker connection tried to access in

server.

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.003.jpeg" width="" height="">
</p>


<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.004.png" width="" height="">
</p>


Like Length, How much tried to attempt using to user login & root access login included fault login attempt & successful login attempt in this attack.

Its also means the Authentication failure s list from this log, seen in given below image.Remote host also included in this log by the consider with openvpn connection. We need to find the attackers multiple changing ip address that we can clarify that their tried connection where its from. List will be shown in below.

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.005.jpeg" width="" height="">
</p>


<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.006.jpeg" width="" height="">
</p>

<p align="center"> Logname with uid & euid with the server response </p>

*All IP addresses list & their details will be shown in attachment files. We can check from these.

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.007.jpeg" width="" height="">
</p>

Here is the exact Accepted publickey means accepted user from the tried section. Hacker using a random server by using open vpn connection and established the connection. SHA256 hash for RSA encryption secure connection presented in this log.

<b>Capture 2 ( Openvpn.log )</b>

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.008.jpeg" width="" height="">
</p>


Openvpn file .ovpn connection for attack and attempt to the user & root session in the Target server.

Openvpn log data also included in the authentication access log dataset. 

<b>Capture 2 ( router packet from Destination site ) </b>

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.009.jpeg" width="" height="">
</p>

<p align="center"> De-authentication & Acknowledgement </p>

● Account was used to log into the local server via TELNET- (username and password)

    p2-server login: sstevenson

    Password: R3@LLYG00Dp@$$w0rd!

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.010.png" width="" height="">
</p>

● Account was used to log into the local router via HTTP- http\_id=TIDd60f245957fb603a

Associated js & source File Attached.

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.011.jpeg" width="" height="">
</p>

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.012.jpeg" width="" height="">
</p>

This is the source file screenshot and main source file attached with the evidence

section.

● According to DNS in the capture, IP address hosts the duckduckgo.com website–

IP: 40.89.244.232

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.013.jpeg" width="" height="">
</p>

In this section, we can see that hacker using duckduckgo service for hide the source connection. From the previous authentication log files we saw that multiple ip connection attempt for authentication in pam\_unix. We can find from dns packet section for ducducgo.

● DNS server(s) is/are being used to resolve names to IPs-

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.014.jpeg" width="" height="">
</p>

Here we found the most phase of network forensics, dns resolve names ips for The openvpn connection.

<b>Capture 2 ( router packet from source site )</b>

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.015.jpeg" width="" height="">
</p>

<p align="center"> Routing Information packet Generation for Deauthentication & Acknowledgement </p>

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.016.jpeg" width="" height="">
</p>

Capture source site packet when attacker used openvpn connection for setup and target the attack

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.017.jpeg" width="" height="">
</p>

<p align="center"> Wireless Packet Statistics </p>

We are extracted the packet for the wireless to check the hacker activities. We found their Malformed source code here(Also attached in evidence)-

      //
      wl_ifaces = [
      ['eth1','0',0,-1,'FreshTomato24','A0:04:60:CA:6C:B6',1,16,'ap','00:00:00:00:00:00']];
      //
      wl_bands = [ [ '2'] ];
      //
      nvram = {
      'wl_nband': '2',
      'wl0_nband': '2',
      'wl_unit': '0',
      'http_id': 'TIDd60f245957fb603a',
      'web_mx': 'status,bwm',
      'web_pb': ''};
      function wl_fface(uidx) {
      return wl_ifaces[uidx][1];
      }
      function wl_unit(uidx) {
      return wl_ifaces[uidx][2];
      }
      function wl_sunit(uidx) {
      return wl_ifaces[uidx][3];
      }function wl_uidx(unit) {
      for (var u = 0; u < wl_ifaces.length; ++u) {
      if (wl_ifaces[u][2] == unit) return u;
      }
      return -1;
      }
      function wl_ifidx(ifname) {
      for (var u = 0; u < wl_ifaces.length; ++u) {
      if (wl_ifaces[u][0] == ifname) return u;
      }
      return -1;
      }
      function wl_ifidxx(ifname) {
      for (var u = 0; u < wl_ifaces.length; ++u) {
      if (wl_ifaces[u][1] == ifname) return u;
      }
      return -1;
      }
      function wl_display_ifname(uidx) {
      return wl_ifaces[uidx][0]+(wl_sunit(uidx) < 0 ?
      ' (wl'+wl_fface(uidx)+')' : '')+((wl_bands[uidx].length == 1) ?
      ((wl_bands[uidx][0]
      == '1') ? ' / 5 GHz' : ' / 2.4 GHz') : ((nvram['wl'+wl_unit(uidx)+'_nband'] ==
      1)
      ?
      ' / 5 GHz' : ' / 2.4 GHz'));
      }

And the status section is-

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.018.jpeg" width="" height="">
</p>


From Analyze the source packet & the source code, we can identify the pptp server ip stat and The netmask of hacker connection. We can prove it from the Authentication log file again. Let Me check that-

<p align="center">

<img src="https://github.com/tareqraihan926/Network-Artifacts-Forensics-Analysis/blob/main/Screenshots/Aspose.Words.b6296dcb-298e-49b4-bada-f504d6427885.019.jpeg" width="" height="">
</p>
