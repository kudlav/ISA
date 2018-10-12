
// todo: 1. Kontrolovat ID odpovědí, zpracovávat pouze první odpověď na daný dotaz.
// todo 2. Přepínač -r a -t současně

/* Requirements */
#include <iostream> // IO operations
#include <unistd.h> // getopt
#include <pcap/pcap.h> // pcap
#include <netinet/if_ether.h> // struct ether_header
#include <netinet/ip.h> // struct ip
#include <netinet/udp.h> // struct udphdr
#include <arpa/inet.h> // htons

/* Error codes: */
#define EXIT_ARG 1 // error when parsing arguments
#define EXIT_IOE 2 // I/O error
#define EXIT_INT 3 // internal error

using namespace std;

typedef struct dns_header {
	uint16_t id;
	unsigned char flags[2];
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} dns_header;

string dnsTypeName(int code) {
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
		case 28:
			return "AAAA";
		default:
			return "UNKNOWN";
	}
}

void printHelp() {
	exit(EXIT_ARG);
}

void parseArguments(int argc, char *argv[], string *file, string *interface, string *server, long *duration) {
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

void dnsDomainFromPointer(const unsigned char *data, unsigned int octet, unsigned int dnsBase, string* name) {
	unsigned int offset = (data[octet++] - 192) << 8;
	offset += data[octet] + dnsBase;
	octet = offset;

	while (data[octet] != '\0' && data[octet] <= 63) {
		if (!name->empty() && name->back() != '.') {
			*name += ".";
		}
		unsigned int length = data[octet++];
		for (unsigned int i = 0; i < length; i++) {
			*name += data[octet++];
		}
	}
	if (data[octet] != '\0') {
		dnsDomainFromPointer(data, octet, dnsBase, name);
	}
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

unsigned int parseAnswers(const unsigned char *data, unsigned int octet, unsigned int dnsBase) {
	// NAME
	string rName = "";
	while (data[octet] != '\0' && data[octet] <= 63) {
		if (!rName.empty()) {
			rName += ".";
		}
		unsigned int length = data[octet++];
		for (unsigned int i = 0; i < length; i++) {
			rName += data[octet++];
		}
	}
	if (data[octet] != '\0') {
		dnsDomainFromPointer(data, octet, dnsBase, &rName);
		octet ++;
	}
	octet++;

	// TYPE
	unsigned int typeCode = data[octet++] << 8;
	typeCode += data[octet++];
	string rType = dnsTypeName(typeCode);

	// Skip CLASS
	octet += 2;

	// Skip TTL
	octet += 4;

	// RDLENGTH
	unsigned int rdlenght = data[octet++] << 8;
	rdlenght += data[octet++];

	// RDATA
	string rData = "";
	switch (typeCode) {

		case 1: // A
			for (unsigned int i = 0; i < rdlenght; i++) {
				if (!rData.empty()) {
					rData += ".";
				}
			 	rData += to_string(data[octet++]);
			}
			break;

		case 5: // CNAME
			while (data[octet] != '\0' && data[octet] <= 63) {
				if (!rData.empty()) {
					rData += ".";
				}
				unsigned int length = data[octet++];
				for (unsigned int i = 0; i < length; i++) {
					rData += data[octet++];
				}
			}
			if (data[octet] != '\0') {
				dnsDomainFromPointer(data, octet, dnsBase, &rData);
				octet++;
			}
			octet++;
			break;

		default:
			cout << "!!! EMERGENCY !!! NOT IMPLEMENTED: " << typeCode << endl;
			exit(42);
	}

	cout << rName << " " << rType << " " << rData << " " << endl;

	return octet;
}

bool parsePacket(const unsigned char *data) {
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
		octet = parseAnswers(data, octet, sizeOfHeaders);
	}

	cout << "===" << endl;

	return true;
}

int main(int argc, char *argv[]) {

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
		if (parsePacket(data)) {
			packetNr++;
		}
	}

	if (err == -1) {
		cerr << "CHYBA behem zpracovavani " << packetNr + 1 << ". paketu" << endl;
	}

	pcap_close(pcap);

	cout << "Bye!" << packetNr << endl;
	return EXIT_SUCCESS;
}
