all: packet

packet: packet.o
	g++ -o packet packet.o -lpcap

packet.o: packet.cpp
	g++ -c -o packet.o packet.cpp -lpcap

clear:
	rm packet packet.o
