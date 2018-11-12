//
// Created by Vladan on 14.10.2018.
//
#ifndef PROJEKT_STRUCT_H
#define PROJEKT_STRUCT_H

#include <string> // string

using namespace std;

typedef struct dns_header {
	uint16_t id;
	unsigned char flags[2];
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} dns_header;

typedef struct dns_response {
	string domainName;
	string rrType;
	string rrAnswer;
	unsigned int count;
} dns_response;

#endif //PROJEKT_STRUCT_H
