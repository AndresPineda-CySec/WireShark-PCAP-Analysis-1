<h1>Wireshark PCAP Analysis 1</h1>

<h2>Description</h2>

In this analysis, I examined network traffic within the IP LAN segment 10.1.17.0/24, which has an IP range of 10.1.17.0 - 10.1.17.255. I also know the LAN gateway is 10.1.17.0, and the LAN broadcast address is 10.1.17.255. The scenario involves an employee who downloaded a suspicious file from a supposed "Google authenticator" website and is suspected of communicating with a Command and Control (C2) server. My goal was to identify any unusual traffic patterns or connections to external IPs that could indicate data exfiltration or C2 communication. <br />

<h2>Utilities Used</h2>

- <b>WireShark</b>
- <b>Linux Terminal</b> 

<h2>Environments Used</h2>

- <b>Kali Linux</b>

<h2>Skills Demonstrated</h2>

- <b>Network Traffic Analysis</b>
- <b>Packet Filtering</b>
- <b>Forensic Analysis</b>
- <b>Incident Identification</b>
- <b>Exfiltration Detection</b>
- <b>Troubleshooting</b>

<h2>Project Walk-Through:</h2>

<h3 align="center">Identifying the C2 Server IP Addresses:</h3>
<p align="center">
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_09-56.png?raw=true" height="200%" width="200%"/> <br />
Knowing that there is a compromised host in the LAN segment 10.1.17.0/24 communicating with a C2 server, I can view unusual amounts of traffic by selecting "Statistics" and then selecting "Conversations." This will open the Conversations window, allowing me to view the packets sent from IP A to IP B. In the Conversations Window, I select the IPv4 tab and sort the lines by the most packets being sent. Right away, the first two lines jump off the screen due to the high amounts of packets being sent from one another. Before labeling this as malicious, I have to take a deeper dive; but seeing that IP A is sending out 822 KB of data while both IP B's are sending 17 MB of data, I can almost already determine that the IP 10.1.17.215 is the compromised host, and IP addresses 45.125.66.32 and 5.252.153.241 are being used for c2 traffic.<br />
<br />
<br />
If my assumptions are correct, I will also focus on the IP address 45.125.66.252 because it comes from the same network as the aforementioned IP 45.125.66.32.
The next step of my investigation will be to check each external IP address that has sent over one thousand packets. For now, I will start with the three IP addresses I am suspicious of, starting with 45.125.66.32<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_10-33.png?raw=true" height="70%" width="70%"/> <br />
I apply the filter "ip.addr == 45.125.66.32" to view the traffic from or to the suspicious IP address. Once applied, it reveals a back-and-forth conversation with the IP address, which I think is the infected host.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_10-43.png?raw=true" height="200%" width="200%"/> <br />
To further analyze the conversation I right click the first frame to view the "TCP Stream." Just a couple lines down I see "Self-signed certificate," which in many cases allows C2 servers to encrypt their traffic.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_10-54.png?raw=true" height="100%" width="100%"/> <br />
Specifying a string filter to show the results of the packets with "encrypted" in the "Info" column, I gather further evidence that this external IP address uses a self-signed Certificate to encrypt data. For now, I'm going to skip over IP 5.252.153.214, and I'm going to check the other IP from the same network to continue my investigation.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_11-05.png?raw=true" height="100%" width="100%"/> <br />
Once again, I applied the same filter as before but updated the IP to "45.125.66.252." Once I have all traffic involving the suspicious IP address, I right-click on the first frame and open the "TCP Stream" window. In the new window, I again see a self-signed Certificate, but this time, there is also a "JDOWNGRD" above the self-signed certificate. This is extremely dangerous because it resembles a downgrade attack.<br />
<br />
<br />
Now, it's time to check the IP address 5.252.153.241. I start by applying the filter "ip.addr == 5.252.153.241" to see traffic involving only 5.252.153.241. Once again I see the victim IP, 10.1.17.215, being communicated with.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/mal1.png?raw=true" height="100%" width="100%"/> <br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/mal2.png?raw=true" width="100%"/> <br />  
I then right-click an HTTP frame, select "follow," then select "HTTP Stream." This provides the first hard evidence of a C2 server and data exfiltration, proving that 10.1.17.215 is the infected host. Inside the HTTP Stream I found an Indicator of compromise (IOC); a PowerShell script that facilitates data exfiltration by sending logs to a remote server. The script creates a directory named "jsLeow" and stores a malicious file called "skqllz.ps1" inside it. It constructs an upload URL by appending stolen data to a predefined variable and uses the "System.Net.WebClient" object to exfiltrate the information via HTTP requests. The presence of obfuscated PowerShell commands, encoded payloads, and suspicious directory creation strongly indicates malicious activity designed to evade detection while maintaining persistence on the compromised system.<br />
<br />
<br />
<br />
<br />
<h3 align="center">Checking other IP Addresses with unusually high traffic:</h3>
<p align="center">
The next IPs I need to check are 82.221.136.26, 23.55.125.176, and 10.1.17.2.
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-14_08-41.png?raw=true" height="100%" width="100%"/> <br />
The first IP address I’ll examine from the three is 82.221.136.26. Immediately, I notice an associated domain named "authenticatoor.org". Several red flags stand out since this domain should logically belong to Google. First, the misspelling of the word "authenticator" as "authenticatoor" is highly suspicious. Second, the use of the ".org" top-level domain further raises concerns, as Google typically adheres to a consistent domain pattern, such as "---.google.com." These inconsistencies strongly suggest that the domain is not legitimate and likely malicious. The use of encryption, in this case, is also very suspicious.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/whois.png?raw=true" height="100%" width="100%"/> <br />
To further prove the invalidity of the domain, I used the command "whois" in my Linux terminal to view key information about the IP, further proving this IP does not belong to Google.<br />
<br />
<br /> 
While the IP is malicious, it only spoofs the user into downloading a malicious file and is not one of the C2 server IP addresses.<br />
<br />
<br />
The IP address 23.55.125.176 does not seem malicious but may have been compromised due to its communication with the infected host. the conversation between 10.1.17.215 and 23.55.125.176 is an attempt to exfiltrate data from an Azure.microsoft server.<br />
The next IP I will review is 10.1.17.2, a local host on the network.<br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-14_09-55.png?raw=true" height="100%" width="100%"/> <br />
Once filtered to only show traffic involving the IP address 10.1.17.2, I found that 10.1.17.215 has been communicating with this host. It appears the infected host has been requesting information about the database, specifically querying for sensitive data. The communication includes multiple requests to access database records, which could indicate an attempt to exfiltrate or manipulate data. The nature of these requests, coupled with the unusual behavior observed from the originating host, suggests that it may be compromised or involved in malicious activity.<br />
<br />
<br />
After thoroughly reviewing the remaining IP addresses the infected host communicated with, I determined that all interactions focused on retrieving information. None of the other IP addresses exhibited any signs of malicious activity.<br />
<br />
<br />
<br />
<br />
<h3 align="center">The Infected Host:</h3>
<p align="center">
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/hostInfo.png?raw=true" height="100%" width="100%"/> <br />
To identify the infected host, I applied the filter "ip.src == 10.1.17.215 && kerberos" in Wireshark, narrowing the results to traffic where the compromised machine is the source and involved in Kerberos-related communication. I then searched for a request packet containing host identification details. I examined frame 250 and found that the infected host's name is "DESKTOP-L8C5GSJ", and its MAC address is 00:d0:b7:26:4a:74. <br />
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/hostName.png?raw=true" height="100%" width="100%"/> <br />
I then opened the TCP Stream for frame 250 and learned the user's Windows account user name is "shutchenson."<br />
<br />
<br />
<br />
<br />
<h3 align="center">Conclusion:</h3>
<p align="center">
Through my investigation, I identified the infected host with the IP address 10.1.17.215, MAC address 00:d0:b7:26:4a:74, hostname DESKTOP-L8C5GSJ, and Windows account username shutchenson. Additionally, I uncovered three command and control (C2) servers communicating with the compromised machine: 45.125.66.32, 45.125.66.252, and 5.252.153.241. I also discovered a malicious phishing domain, authenticatoor.org, hosted at 82.221.136.26, which was masquerading as a Google Authenticator website. Network traffic analysis confirmed that this IP was used solely for downloading the malicious payload, with no evidence of data exfiltration. Furthermore, I examined other IP addresses communicating with the infected host to assess potential data leaks and found no indications of further compromise.<br />
<br />
<br />
My recommendation for the organization is to immediately isolate the affected machines, 10.1.17.215 and 10.1.17.2, from the network to prevent further spread of the potential threat. This includes disabling network interfaces, revoking access permissions, and monitoring for any residual connections that may indicate persistence or ongoing malicious activity. Additionally, forensic evidence must be preserved by following the order of volatility and prioritizing the collection of live memory, system logs, and active network connections before capturing disk images. This ensures that crucial evidence is not lost and allows for a thorough investigation into the root cause of the compromise. Lastly, employee security awareness training should be implemented to reduce human-related security risks. Training should focus on recognizing phishing attempts, handling suspicious files, and following proper cybersecurity protocols to prevent similar incidents in the future..<br />

