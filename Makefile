all:dns-export

dns-export: main.cpp
	g++ -std=c++11 -static-libstdc++ main.cpp stats.cpp -o dns-export -lpcap -pthread

clear:
	rm dns-export
