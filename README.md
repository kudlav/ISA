# dns-export
Parse DNS (Domain Name System) packets and export statistics to central log server.

## Description
Program parses DNS (Domain Name System) packets from pcap file or by sniffing interface and creates agregated statis‐tics that can be printed to stdout or sent to a syslog server.
Program supports the following DNS types: A, MX, NS, CNAME, SOA, TXT, AAAA, DNSKEY, RRSIG, NSEC, DS.

## Usage
```
dns-export [-r FILE] [-i INTERFACE] [-s SERVER] [-t INTERVAL]

 -r=FILE
      Parse packets from pcap file. When finished, print stats to stdout or send to syslog server if the
      SERVER is set. Cannot be used both with -r or -t.

 -i=INTERFACE
      Sniff this network interface to get packets. Set "any" to sniff from all interfaces. Program will
      periodically send stats to syslog server. To stop sniffing, send CTRL+C to the program. If you want
      to print stats to stdout, send SIGUSR1 to the program. Cannot be used both with -i.

 -s=SERVER
      Specify hostname/ipv4/ipv6 address of syslog server to send statistics to that server. Stats will be
      sent periodically when sniffing or after processing the whole pcap file.

 -t=INTERVAL
      Interval in seconds in which stats are sent to syslog server. Default value is 60. Can be used only
      with SERVER option.
```

## Examples
To write stats to the standard output from dump.pcap use command:  
```dns-export -r dump.pcap```  
To send stats from "ens33" network interface every 5 seconds to "syslog.fit.vutbr.cz" server use command:  
```dns-export -i ens33 -t 5 -s syslog.fit.vutbr.cz```

## Return codes
- 0 program finished successfully
- 1 error when parsing arguments
- 2 input/output error
- 3 internal error
- 4 network error

## Known issues
At this moment the parser is able to handle only DNS packets over UTP, TCP packets are thrown out.

## Authors
Written by Vladan Kudlac - [kudlav](https://github.com/kudlav).

## License
This project is licensed under the Apache License 2.0.
