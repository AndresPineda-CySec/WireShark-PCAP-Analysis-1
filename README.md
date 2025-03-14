<h1>WireShark PCAP Analysis 1</h1>

<h2>Description</h2>

In this analysis, I examined network traffic within the IP LAN segment 10.1.17.0/24, which has a range of 10.1.17.0 - 10.1.17.255. I also know the LAN gateway is 10.1.17.0 and the LAN broadcast address is 10.1.17.255. The scenario involves an employee who downloaded a suspicious file and is suspected of communicating with a Command and Control (C2) server. My goal was to identify any unusual traffic patterns or connections to external IPs that could indicate data exfiltration or C2 communication. <br />

<h2>Languages and Utilities Used</h2>

- <b>WireShark</b> 

<h2>Environments Used</h2>

- <b>Kali Linux</b>

<h2>Skills Demonstrated</h2>

- <b></b>
- <b></b>
- <b></b>
- <b></b>
- <b></b>
- <b></b>

<h2>Project Walk-Through:</h2>

<h3 align="center">Identifying the C2 IP Addresses:</h3>
<p align="center">
<br />
<br />
<img src="https://github.com/AndresPineda-CySec/WireShark-PCAP-Analysis-1/blob/main/images/2025-03-13_09-56.png?raw=true" height="200%" width="200%"/> <br />
Knowing that there is a Compromised host in the LAN segment 10.1.17.0/24 communicating with a C2 server, we can view unusual amounts of traffic through "Statistics," then selecting "Conversations." This will open up the Conversations window, which allows me to view the amount of packets being sent from IP A to IP B. In the Conversations Window, I select the IPv4 tab and sort the lines by the most packets being sent. Right away, the first two lines jump off the screen due to the high amounts of packets being sent from one another. Before labeling this as malicious, I have to take a deeper dive; but seeing that IP A is sending out 822 KB of data while the IP B's are sending 17 MB of data, I can almost already determine that the IP 10.1.17.215 is the compromised host, and IP addresses 45.125.66.32 and 5.252.153.241 are being used for c2 traffic.
<br />
<br />
If my assumptions are correct, I will also be focusing on the IP address 45.125.66.252 due the fact that it comes form the same network as the aformentioned IP 45.125.66.32.
The next step of my investigation will be to check each external IP address sending over one thousand packets. For now I will start with the three IP addresses I am suspicous of, starting with 45.125.66.32
<br />
<br />
<img src="" height="200%" width="200%"/> <br />
I apply the filter "ip.addr == 45.125.66.32" to view the traffic from or to the suspicious IP address.
