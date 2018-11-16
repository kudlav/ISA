//
// Created by Vladan on 14.10.2018.
//

#ifndef PROJEKT_MAIN_H
#define PROJEKT_MAIN_H

#include "library.h"
#include "struct.h"
#include "stats.h"

static const char *base64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

using namespace std;

string dnsTypeName(unsigned int code);
void printHelp();
void parseArguments(int argc, char *argv[], string *file, string *interface, string *server, long *duration);
string dnsDomain(const unsigned char *data, unsigned int *octet, unsigned int dnsBase);
void dnsDomainFromPointer(const unsigned char *data, unsigned int octet, unsigned int dnsBase, string* name);
unsigned int parseInt4(unsigned int *octet, const unsigned char *data);
unsigned int parseInt2(unsigned int *octet, const unsigned char *data);
void setDnsFilter(pcap_t *pcap);
unsigned int parseQuestion(const unsigned char *data, unsigned int octet);
string getCanonicalIp(uint16_t origin[8]);
string getBase64(const unsigned char *data, unsigned int length, unsigned int *octet);
unsigned int parseAnswers(const unsigned char *data, unsigned int octet, unsigned int dnsBase, Stats* stats);
bool parsePacket(const unsigned char *data, Stats *stats);
void quit(int signum);
int main(int argc, char *argv[]);

#endif //PROJEKT_MAIN_H
