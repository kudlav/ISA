// todo: 1. Kontrolovat ID odpovědí, zpracovávat pouze první odpověď na daný dotaz.
// todo 2. Přepínač -r a -t současně

#include "main.h"

// Global variable
Stats stats;

using namespace std;

string dnsTypeName(unsigned int code) {
	switch (code) {
		case 1:
			return "A";
		case 2:
			return "NS";
		case 3:
			return "MD";
		case 4:
			return "MF";
		case 5:
			return "CNAME";
		case 6:
			return "SOA";
		case 7:
			return "MB";
		case 8:
			return "MG";
		case 9:
			return "MR";
		case 10:
			return "NULL";
		case 11:
			return "WKS";
		case 12:
			return "PTR";
		case 13:
			return "HINFO";
		case 14:
			return "MINFO";
		case 15:
			return "MX";
		case 16:
			return "TXT";
		case 17:
			return "RP";
		case 18:
			return "AFSDB";
		case 24:
			return "SIG";
		case 25:
			return "KEY";
		case 28:
			return "AAAA";
		case 29:
			return "LOC";
		case 33:
			return "SRV";
		case 35:
			return "NAPTR";
		case 36:
			return "KX";
		case 37:
			return "CERT";
		case 39:
			return "DNAME";
		case 42:
			return "APL";
		case 43:
			return "DS";
		case 44:
			return "SSHFP";
		case 45:
			return "IPSECKEY";
		case 46:
			return "RRSIG";
		case 47:
			return "NSEC";
		case 48:
			return "DNSKEY";
		case 49:
			return "DHCID";
		case 50:
			return "NSEC3";
		case 51:
			return "NSEC3PARAM";
		case 55:
			return "HIP";
		case 99:
			return "SPF";
		case 249:
			return "TKEY";
		case 250:
			return "TSIG";
		case 32769:
			return "DLV";
		default:
			return "UNKNOWN";
	}
}

void printHelp() {
	exit(EXIT_ARG);
}

void parseArguments(int argc, char **argv, string *file, string *interface, string *server, long *duration) {
	int opt;
	while ((opt = getopt(argc, argv, "r:i:s:t:")) != -1) {
		switch (opt) {
			case 'r':
				if (interface->empty()) {
					*file = optarg;
				} else {
					cerr << "CHYBA: parametr -r nelze pouzit spolecne s -i" << endl;
					printHelp();
				}
				break;
			case 'i':
				if (file->empty()) {
					*interface = optarg;
				} else {
					cerr << "CHYBA: parametr -i nelze pouzit spolecne s -r" << endl;
					printHelp();
				}
				break;
			case 's':
				*server = optarg;
				break;
			case 't':
				char *endptr;
				*duration = strtol(optarg, &endptr, 10);
				if (*endptr != '\0' || *duration <= 0) {
					cerr << "CHYBA: hodnota parametru -t musi byt cele cislo vetsi nez 0" << endl;
					printHelp(); // exit(EXIT_ARG)
				}
				break;
			case '?':
				if (optopt == 'r' || optopt == 'i' || optopt == 's' || optopt == 't') {
					cerr << "CHYBA: chybi hodnota u argumentu -" << (char) optopt << endl;
				} else {
					cerr << "CHYBA: neznamy parametr -" << (char) optopt << endl;
				}
				[[fallthrough]];
			default:
				printHelp(); // exit(EXIT_ARG)
		}
	}
}

void setDnsFilter(pcap_t *pcap) {
	// Compile DNS filter
	struct bpf_program filter;
	if (pcap_compile(pcap, &filter, "port 53 and udp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
		cerr << "Nepodarilo se vytvorit filtr DNS paketu:" << endl;
		cerr << pcap_geterr(pcap) << endl;
		exit(EXIT_INT);
	}

	// Apply DNS filter
	if (pcap_setfilter(pcap, &filter) == -1) {
		cerr << "Nepodarilo se vyfiltrovat DNS pakety:" << endl;
		cerr << pcap_geterr(pcap) << endl;
		exit(EXIT_INT);
	}
}

unsigned int dnsDomain(const unsigned char *data, unsigned int octet, unsigned int dnsBase, string *name) {
	while (data[octet] != '\0' && data[octet] <= 63) {
		unsigned int length = data[octet++];
		for (unsigned int i = 0; i < length; i++) {
			*name += data[octet++];
		}
		*name += '.';
	}
	if (data[octet] != '\0') {
		dnsDomainFromPointer(data, octet, dnsBase, name);
		octet ++;
	}
	octet += 1;

	if (name->empty()) {
		*name += '.';
	}

	return octet;
}

void dnsDomainFromPointer(const unsigned char *data, unsigned int octet, unsigned int dnsBase, string *name) {
	unsigned int offset = (data[octet++] - 192) << 8;
	offset += data[octet] + dnsBase;
	octet = offset;

	while (data[octet] != '\0' && data[octet] <= 63) {
		unsigned int length = data[octet++];
		for (unsigned int i = 0; i < length; i++) {
			*name += data[octet++];
		}
		*name += '.';
	}
	if (data[octet] != '\0') {
		dnsDomainFromPointer(data, octet, dnsBase, name);
	}
}

unsigned int parseInt4(unsigned int *octet, const unsigned char *data) {
	unsigned int number;
	number = data[(*octet)++] << 24;
	number += data[(*octet)++] << 16;
	number += data[(*octet)++] << 8;
	number += data[(*octet)++];
	return number;
}

unsigned int parseInt2(unsigned int *octet, const unsigned char *data) {
	unsigned int number;
	number = data[(*octet)++] << 8;
	number += data[(*octet)++];
	return number;
}

unsigned int parseInt1(unsigned int *octet, const unsigned char *data) {
	return data[(*octet)++];
}

unsigned int parseQuestion(const unsigned char *data, unsigned int octet) {
	// Skip QNAME
	while (data[octet] != '\0') {
		unsigned int length = data[octet++];
		octet += length;
	}
	octet++;
	// Skip QTYPE
	octet += 2;
	// Skip QCLASS
	octet += 2;

	return octet;
}

string getCanonicalIp(uint16_t *origin) {

	//struct in6_addr ipv6nr;
	//inet_pton(AF_INET6, origin, &ipv6nr);

	string canonical;

	// Check zero parts
	unsigned int fromMax = 0;
	unsigned int lengthMax = 0;
	unsigned int from = 0;
	unsigned int length = 0;
	for (unsigned int i = 0; i < 8; ++i) {
		if (origin[i] == 0) {
			if (length == 0) {
				from = i;
			}
			length++;
		}
		else {
			if (length != 0) {
				if (lengthMax < length){
					fromMax = from;
					lengthMax = length;
				}
				from = 0;
				length = 0;
			}
		}
	}
	char numberStr[4];
	for (unsigned int i = 0; i < 8; i++) {
		if (i > 0) {
			canonical += ':';
		}
		if (i == fromMax && lengthMax > 1) {
			i = fromMax + lengthMax - 1;
			if (i >= 8) canonical += ':';
			continue;
		}
		sprintf(&numberStr[0], "%x", origin[i]);
		canonical += numberStr;
	}

	return canonical;
}

string getBase64(const unsigned char *data, unsigned int length, unsigned int *octet) {
	unsigned int base64in = 0;
	unsigned int i = 0;
	uint8_t base64index;
	string base64out;
	for (; i < length; i++) {
		base64in = base64in << 8;
		base64in += data[*octet];

		if ((i % 3) == 2) { // 3rd number (24 bit number)
			base64index = (uint8_t) (base64in >> 18); // XXXX XX00 0000 0000 0000 0000
			base64out += base64table[base64index];
			base64index = (uint8_t) ((base64in >> 12) & 0x3F); // 0000 00XX XXXX 0000 0000 0000
			base64out += base64table[base64index];
			base64index = (uint8_t) ((base64in >> 6) & 0x3F); // 0000 0000 0000 XXXX XX00 0000
			base64out += base64table[base64index];
			base64index = (uint8_t) (base64in & 0x3F); // 0000 0000 0000 0000 00XX XXXX
			base64out += base64table[base64index];

			base64in = 0;
		}

		(*octet)++;
	}

	if ((i % 3) == 1) { // 8 of 24 bits
		base64index = (uint8_t) (base64in >> 2); // ---- ---- ---- ---- XXXX XX00
		base64out += base64table[base64index];
		base64index = (uint8_t) ((base64in << 4) & 0x3f); // ---- ---- ---- ---- 0000 00XX
		base64out += base64table[base64index];
		base64out += '=';
		base64out += '=';
	}
	else if ((i % 3) == 2) { // 16 of 24 bits
		base64index = (uint8_t) (base64in >> 10); // ---- ---- XXXX XX00 0000 0000
		base64out += base64table[base64index];
		base64index = (uint8_t) ((base64in >> 4) & 0x3F); // ---- ---- 0000 00XX XXXX 0000
		base64out += base64table[base64index];
		base64index = (uint8_t) ((base64in << 2) & 0x3F); // ---- ---- 0000 0000 0000 XXXX
		base64out += base64table[base64index];
		base64out += '=';
	}

	return base64out;
}

unsigned int parseAnswers(const unsigned char *data, unsigned int octet, unsigned int dnsBase, Stats* stats) {
	// NAME
	string rName;
 	octet = dnsDomain(data, octet, dnsBase, &rName);

	// TYPE
	unsigned int typeCode = parseInt2(&octet, data);
	string rType = dnsTypeName(typeCode);

	// Skip CLASS
	octet += 2;

	// Skip TTL
	octet += 4;

	// RDLENGTH
	unsigned int rdlenght = data[octet++] << 8;
	rdlenght += data[octet++];

	// RDATA
	string rData;
	switch (typeCode) {

		case 1: // A
			for (unsigned int i = 0; i < rdlenght; i++) {
				if (!rData.empty()) {
					rData += '.';
				}
				rData += to_string(data[octet++]);
			}
			break;

		case 15: // MX
			{ // Preference
			unsigned int preference = data[octet++] << 8;
			preference += data[octet++];
			rData += '"' + to_string(preference) + ' ';
			octet = dnsDomain(data, octet, dnsBase, &rData);
			rData += '"';
			}break;

		case 2: // NS
			octet = dnsDomain(data, octet, dnsBase, &rData);
			break;

		case 5: // CNAME
			octet = dnsDomain(data, octet, dnsBase, &rData);
			break;

		case 6: // SOA
			{rData += '"';
			// Primary name server
			octet = dnsDomain(data, octet, dnsBase, &rData);
			rData += ' ';
			// Responsible authority's mailbox
			octet = dnsDomain(data, octet, dnsBase, &rData);
			// Serial number, Refresh interval, Retry interval, Expire limit, Minimum TTL
			for (unsigned int i = 0; i < 5; i++) {
				rData += ' ' + to_string(parseInt4(&octet, data));
			}
			rData += '"';
			}break;

		case 16: // TXT
			rData += '"';
			octet++;
			for (unsigned int i = 0; i < rdlenght-1; i++) {
				rData += data[octet++];
			}
			rData += '"';
			break;

		case 28: // AAAA
			uint16_t parts[8];
			for (uint16_t &part : parts) {
				// Convert to int (ommitting leading zeros)
				part = data[octet++] << 8;
				part += data[octet++];
			}
			rData += getCanonicalIp(parts);
			break;

		case 48: // DNSKEY
			{unsigned int number = 0;
			// Flags
			rData += '"' + to_string(parseInt2(&octet, data)) + ' ';
			// Protocol
			number = data[octet++];
			rData += to_string(number) + ' ';
			// Algorithm
			number = data[octet++];
			rData += to_string(number) + ' ';
			// Public Key
			rData += getBase64(data, rdlenght - 4, &octet) + '"';
			}break;

		case 46: // RRSIG
			{unsigned int number = 0;
			time_t timeEpoch;
			tm *timeStruct;
			stringstream ss;
			// Type Covered
			rData += '"' + dnsTypeName(parseInt2(&octet, data)) + ' ';
			// Algorithm
			number = data[octet++];
			rData += to_string(number) + ' ';
			// Labels
			number = data[octet++];
			rData += to_string(number) + ' ';
			// Original TTL
			rData += to_string(parseInt4(&octet, data)) + ' ';
			// Signature Expiration
			timeEpoch = (time_t) parseInt4(&octet, data);
			timeStruct = gmtime(&timeEpoch);
			ss << put_time(timeStruct, "%Y%m%d%H%M%S");
			rData += ss.str() + ' ';
			ss.str(string()); // clear
			// Signature Inception
			timeEpoch = (time_t) parseInt4(&octet, data);
			timeStruct = gmtime(&timeEpoch);
			ss << put_time(timeStruct, "%Y%m%d%H%M%S");
			rData += ss.str() + ' ';
			ss.str(string()); // clear
			// Key Tag
			rData += to_string(parseInt2(&octet, data)) + ' ';
			// Signer's Name
			string name;
			unsigned int nameLength = octet;
			octet = dnsDomain(data, octet, dnsBase, &name);
			nameLength = octet - nameLength;
			rData += name + ' ';
			// Signature
			rData += getBase64(data, rdlenght - (nameLength + 18), &octet) + '"';
			}break;

		case 47: // NSEC
			{string name;
			unsigned int recordEnd = octet + rdlenght;
			// Next Domain Name
			octet = dnsDomain(data, octet, dnsBase, &name);
			rData += '"' + name + ' ';
			// Type Bit Maps
			unsigned int blockNr;
			unsigned int bitmapLength;
			unsigned int octetValue;
			unsigned int bitValue;
			while (octet < recordEnd) {
				blockNr = data[octet++];
				bitmapLength = data[octet++];
				for (unsigned int octetPosition = 0; octetPosition < bitmapLength; octetPosition++) {
					octetValue = data[octet++] ;
					for (unsigned int bitPosition = 0; bitPosition < 8; bitPosition++) {
						bitValue = (octetValue >> (7 - bitPosition) & 0x1);
						if (bitValue) {
							rData += dnsTypeName( (blockNr * 256) + (octetPosition * 8) + bitPosition ) + ' ';
						}
					}
				}
			}
			}break;

		case 43: // DS
			{// Key Tag
			rData += '"' + to_string(parseInt2(&octet, data)) + ' ';
			// Algorithm
			rData += to_string(parseInt1(&octet, data)) + ' ';
			// Digest Type
			rData += to_string(parseInt1(&octet, data)) + ' ';
			// Digest
			char hex[3];
			for (unsigned int i = 0; i < (rdlenght - 4); i++) {
				sprintf(hex, "%02X", data[octet++]);
				rData += hex;
			}
			}break;

		default:
			octet += rdlenght;
			cout << "TYPE " << typeCode << " NOT IMPLEMENTED !!!" << endl;
			return octet;
	}

	dns_response response;
	response.domainName = rName;
	response.rrType = rType;
	response.rrAnswer = rData;
	stats->add(response);

	return octet;
}

bool parsePacket(const unsigned char *data, Stats *stats) {
	// Switch between length of IPv4 or IPv6 header
	unsigned int sizeOfHeaders = sizeof(struct ether_header) + sizeof(struct udphdr);
	uint8_t version = (uint8_t) (data[sizeof(struct ether_header)] >> 4);
	if (version == 4) {
		sizeOfHeaders += sizeof(struct ip);
	} else {
		sizeOfHeaders += 40;
	}

	// Check if DNS message is response, skip to next if not
	dns_header *dns = (dns_header *) (data + sizeOfHeaders);
	bool response = dns->flags[0] >> 7;
	if (!response) {
		return false;
	}

	// HERE THE MAGIC BEGINS!!!
	// TADY SE NĚCO DĚJE!!!
	unsigned int octet = sizeOfHeaders + sizeof(struct dns_header);

	// Handle question sections (skip them)
	unsigned int questions =  htons(dns->questions);
	for (unsigned int i = 0; i < questions; i++) {
		octet = parseQuestion(data, octet);
	}

	unsigned int answers = htons(dns->answers);
	for (unsigned int i = 0; i < answers; i++) {
		octet = parseAnswers(data, octet, sizeOfHeaders, stats);
	}

	return true;
}

void quit(int signum) {
	if (signum == SIGUSR1) {
		cout << stats.print();
	}
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {

	signal(SIGUSR1, quit);

	string file;
	string interface;
	string server;
	long duration = 60;

	parseArguments(argc, argv, &file, &interface, &server, &duration);

	pcap_t *pcap;

	if (!file.empty()) {
		char errbuf[PCAP_ERRBUF_SIZE];

		pcap = pcap_open_offline(file.c_str(), errbuf);

		if (pcap == NULL) {
			cerr << "CHYBA cteni souboru '" << file << "':" << endl << errbuf << endl;
			exit(EXIT_IOE);
		}
	}

	setDnsFilter(pcap); // exit(EXIT_INT);

	struct pcap_pkthdr *header;
	const unsigned char *data;
	int err;
	unsigned int packetNr = 0;

	while ((err = pcap_next_ex(pcap, &header, &data)) == 1) {
		if (parsePacket(data, &stats)) {
			packetNr++;
		}
	}

	if (err == -1) {
		cerr << "CHYBA behem zpracovavani " << packetNr + 1 << ". paketu" << endl;
	}

	pcap_close(pcap);

	if (server.empty()) {
		cout << stats.print();
	}
	else {
		// Send stats to server
	}

	return EXIT_SUCCESS;
}

