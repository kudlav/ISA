//
// Created by Vladan on 14.10.2018.
//

#include "stats.h"

using namespace std;

Stats::Stats() = default;

void Stats::add(dns_response record) {
	for (unsigned int i = 0; i < values.size(); i++) {
		dns_response item = values[i];
		if (item.domainName == record.domainName && item.rrType == record.rrType && item.rrAnswer == record.rrAnswer) {
			values[i].count++;
			return;
		}
	}
	record.count = 1;
	values.push_back(record);
}

string Stats::print() {
	string records;
	for (dns_response item : values) {
		records += item.domainName + " " + item.rrType + " " + item.rrAnswer + " " + to_string(item.count) + "\n";
	}
	return records;
}

bool Stats::send(int sock, struct sockaddr_in *serverAddr) {

	char hostname[255];
	gethostname(hostname, sizeof(hostname));

	string msg;
	char timestring[25];
	for (dns_response item : values) {
		time_t timestamp = time(nullptr);
		tm *timeStruct = gmtime(&timestamp);
		strftime(timestring, sizeof(timestring), "%F-T%TZ", timeStruct);
		msg = "<134>1 ";
		msg += timestring;
		msg += " ";
		msg += hostname;
		msg += " dns-export - - - " + item.domainName + " " + item.rrType + " " + item.rrAnswer + " " + to_string(item.count);
		cout << "send" << endl;
		ssize_t sent = sendto(sock, msg.c_str(), msg.size(), 0, (const struct sockaddr*) serverAddr, sizeof(*serverAddr));
		if (sent != (ssize_t) msg.size()) return false;
		cout << "ok" << endl;
	}

	return true;
};