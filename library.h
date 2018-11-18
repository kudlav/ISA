//
// Created by Vladan Kudlac on 14.10.2018.
//

#ifndef PROJEKT_LIBRARY_H
#define PROJEKT_LIBRARY_H

/* Requirements */
#include <iostream> // IO operations
#include <sstream> // stringstream
#include <string.h> // memset, memcpy
#include <unistd.h> // getopt
#include <pcap/pcap.h> // pcap
#include <netinet/if_ether.h> // struct ether_header
#include <netinet/ip.h> // struct ip, sockaddr_in
#include <netinet/udp.h> // struct udphdr
#include <arpa/inet.h> // htons, inet_pton
#include <sys/types.h> // sendto, getaddrinfo
#include <sys/socket.h> // getaddrinfo
#include <signal.h> // signal
#include <netdb.h> // getaddrinfo
#include <vector> // vector
#include <ctime> // ctime
#include "time.h" // gmtime, time
#include <thread>

/* Error codes: */
#define EXIT_ARG 1 // error when parsing arguments
#define EXIT_IOE 2 // I/O error
#define EXIT_INT 3 // internal error
#define EXIT_NET 4 // network error

#endif //PROJEKT_LIBRARY_H
