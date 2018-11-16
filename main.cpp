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

string dnsDomain(const unsigned char *data, unsigned int *octet, unsigned int dnsBase) {
	string name;
	while (data[*octet] != '\0' && data[*octet] <= 63) {
		unsigned int length = data[(*octet)++];
		for (unsigned int i = 0; i < length; i++) {
			name += data[(*octet)++];
		}
		name += '.';
	}
	if (data[*octet] != '\0') {
		dnsDomainFromPointer(data, *octet, dnsBase, &name);
		(*octet)++;
	}
	(*octet) += 1;

	if (name.empty()) {
		name += '.';
	}

	return name;
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
	string rName = dnsDomain(data, &octet, dnsBase);

	// TYPE
	unsigned int typeCode = parseInt2(&octet, data);
	string rType = dnsTypeName(typeCode);

	// Skip CLASS
	octet += 2;

	// Skip TTL
	octet += 4;

	// RDLENGTH
	unsigned int rdlenght = parseInt2(&octet, data);

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
			// Preference
			rData += '"' + to_string(parseInt2(&octet, data)) + ' ';
			// Exchange
			rData += dnsDomain(data, &octet, dnsBase) + '"';
			break;

		case 2: // NS
			rData += dnsDomain(data, &octet, dnsBase);
			break;

		case 5: // CNAME
			rData += dnsDomain(data, &octet, dnsBase);
			break;

		case 6: // SOA
			// Primary name server
			rData += '"' + dnsDomain(data, &octet, dnsBase) + ' ';
			// Responsible authority's mailbox
			rData += dnsDomain(data, &octet, dnsBase);
			// Serial number, Refresh interval, Retry interval, Expire limit, Minimum TTL
			for (unsigned int i = 0; i < 5; i++) {
				rData += ' ' + to_string(parseInt4(&octet, data));
			}
			rData += '"';
			break;

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
				part = (uint16_t) parseInt2(&octet, data);
			}
			rData += getCanonicalIp(parts);
			break;

		case 48: // DNSKEY
			// Flags
			rData += '"' + to_string(parseInt2(&octet, data)) + ' ';
			// Protocol
			rData += to_string(data[octet++]) + ' ';
			// Algorithm
			rData += to_string(data[octet++]) + ' ';
			// Public Key
			rData += getBase64(data, rdlenght - 4, &octet) + '"';
			break;

		case 46: // RRSIG
			{time_t timeEpoch;
			tm *timeStruct;
			char timeStr[15];
			// Type Covered
			rData += '"' + dnsTypeName(parseInt2(&octet, data)) + ' ';
			// Algorithm
			rData += to_string(data[octet++]) + ' ';
			// Labels
			rData += to_string(data[octet++]) + ' ';
			// Original TTL
			rData += to_string(parseInt4(&octet, data)) + ' ';
			// Signature Expiration
			timeEpoch = (time_t) parseInt4(&octet, data);
			timeStruct = gmtime(&timeEpoch);
			strftime(timeStr, sizeof(timeStr), "%Y%m%d%H%M%S", timeStruct);
			rData += timeStr;
			rData += ' ';
			// Signature Inception
			timeEpoch = (time_t) parseInt4(&octet, data);
			timeStruct = gmtime(&timeEpoch);
			strftime(timeStr, strlen(timeStr), "%Y%m%d%H%M%S", timeStruct);
			rData += timeStr;
			rData += ' ';
			// Key Tag
			rData += to_string(parseInt2(&octet, data)) + ' ';
			// Signer's Name
			unsigned int nameLength = octet;
			rData += dnsDomain(data, &octet, dnsBase) + ' ';
			nameLength = octet - nameLength;
			// Signature
			rData += getBase64(data, rdlenght - (nameLength + 18), &octet) + '"';
			}break;

		case 47: // NSEC
			{unsigned int recordEnd = octet + rdlenght;
			// Next Domain Name
			rData += '"' + dnsDomain(data, &octet, dnsBase) + ' ';
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
			rData += to_string(data[octet++]) + ' ';
			// Digest Type
			rData += to_string(data[octet++]) + ' ';
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

void sendStats(Stats *stats, string address) {

	/* DNS lookup for host address */
	struct hostent *server = gethostbyname(address.c_str());
	if (server == nullptr) {
		cerr << "CHYBA: adresa serveru nenalezena\n";
		exit(EXIT_NET);
	}

	/* Create socket */
	int sock = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET = IPv4, SOCK_STREAM = UDP
	if (sock < 0) {
		cerr << "CHYBA: nelze vytvorit socket\n";
		exit(EXIT_NET);
	}

	/* Prepare address for connection */
	struct sockaddr_in serverAddr;
	memset((char *) &serverAddr, 0, sizeof(serverAddr)); // Null undefined values
	memcpy((char *) &serverAddr.sin_addr.s_addr, server->h_addr, (size_t) server->h_length);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(514); // convert to uint16_t

	/* Send query */
	if (!(stats->send(sock, &serverAddr))) {
		cerr << "CHYBA: Chyba pri zasilani pozadavku\n";
		exit(EXIT_NET);
	}

}

void dump(int signum) {
	if (signum == SIGUSR1) {
		cout << stats.print();
	}
}

int main(int argc, char *argv[]) {

	signal(SIGUSR1, dump);

	string file;
	string interface;
	string server;
	long duration = 60;

	parseArguments(argc, argv, &file, &interface, &server, &duration);

	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!file.empty()) {
		pcap = pcap_open_offline(file.c_str(), errbuf);

		if (pcap == NULL) {
			cerr << "CHYBA cteni souboru '" << file << "':" << endl << errbuf << endl;
			exit(EXIT_IOE);
		}
	}
	else if (!interface.empty()) {
		if ((errbuf) == NULL) cout << errbuf << endl;
		pcap = pcap_open_live(interface.c_str(), 1518, 0, 0, errbuf);
		if (pcap == NULL) {
			cerr << "CHYBA zachytavani zarizeni '" << interface << "':" << endl << errbuf << endl;
			exit(EXIT_IOE);
		}
	}
	else {
		cerr << "CHYBA: musi byt zadan bud prepinac -i nebo -r" << endl;
		printHelp();
	}


	setDnsFilter(pcap); // exit(EXIT_INT);

	struct pcap_pkthdr header;
	const unsigned char *data;
	unsigned int packetNr = 0;
	while ((data = pcap_next(pcap, &header))) {
		if (parsePacket(data, &stats)) {
			packetNr++;
		}
	}

	if (err == -1) {
		cerr << "CHYBA behem zpracovavani " << packetNr + 1 << ". paketu" << endl;
	}

	pcap_close(pcap);

	// Send stats to server
	//sendStats(&stats, server);

	if (server.empty()) {
		cout << stats.print();
	}

	return EXIT_SUCCESS;
}
