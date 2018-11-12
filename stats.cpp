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
	string records = "";
	for (unsigned int i = 0; i < values.size(); i++) {
		dns_response item = values[i];
		records += item.domainName + " " + item.rrType + " " + item.rrAnswer + " " + to_string(item.count) + "\n";
	}
	return records;
}
