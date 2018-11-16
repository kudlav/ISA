//
// Created by Vladan on 14.10.2018.
//
#ifndef PROJEKT_STATS_H
#define PROJEKT_STATS_H

#include "library.h"
#include "struct.h" // dns_response

using namespace std;

class Stats {
	vector<dns_response> values;

	public:
		Stats();
		void add(dns_response record);
		string print();
		bool send(int sock, struct sockaddr_in *serverAddr);
};


#endif //PROJEKT_STATS_H
