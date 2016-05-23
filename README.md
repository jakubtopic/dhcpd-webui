dhcpd-webui
===========

dhcpd-webui provides a sleek web-based interface for visualizing a database of 
leases assigned by the Internet Systems Consortium DHCP Server
(isc-dhcp-server). The interface basically consists of two tables with static 
and dynamic addresses accompanied with hostnames, physical addresses and lease 
times. The dhcp-webui is also able to use arp-scan so it can identify whether 
a device is currently connected or not and count devices that are configured 
manually (not via DHCP). Another additional feature is ability to wake up 
devices using `wakeonlan` shell command.

## Security

Web interface can be protected with a password and TOTP two-step verification. 
You have to prevent .ini file from serving. Unfortunately dhcpd-webui requires 
the `shell_exec` function to execute these bash commands: `wakeonlan`,
`arp-scan`, `ifconfig`, `awk` and `sed`. Next version will contain option to 
disable all additional features that require access to mentioned system 
commands.

## Setup

Setup is pretty straightforward. Just copy the directory from repository to 
wherever you want to in the directory of your preferred web server. Remember 
that you need php5, wakeonlan and arp-scan to get dhcpd-webui working. Do not forget to edit the config.ini file to adjust dhcpd-webui to your environment.

## Contributing

Pull requests and issues with suggestions are welcome!

## Screenshots
![alt tag](https://jakubtopic.cz/sub/share/dhcpd-webui.png)
