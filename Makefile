all:dns-export

dns-export: main.cpp
	g++ -Wall -Wextra -Werror -std=c++14 -static-libstdc++ main.cpp stats.cpp -o dns-export -lpcap

clear:
	rm dns-export
