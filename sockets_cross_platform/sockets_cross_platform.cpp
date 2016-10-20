// sockets_cross_platform.cpp : Defines the entry point for the console application.
//
#include <iostream>
#include <string>
#include <cstring>

#ifdef _WIN32
//A copy operation gives a warning unless #pragma warning(disable : 4996) is used on MSVC
#pragma warning(disable : 4996)
#endif // _WIN32

//http://stackoverflow.com/questions/28027937/cross-platform-sockets
#ifdef _WIN32
/* See http://stackoverflow.com/questions/12765743/getaddrinfo-on-win32 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501  /* Windows XP. */
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
/* Assume that any non-Windows platform uses POSIX-style sockets instead. */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>  /* Needed for getaddrinfo() and freeaddrinfo() */
#include <unistd.h> /* Needed for close() */
#endif

int sockInit(void)
{
#ifdef _WIN32
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(1, 1), &wsa_data);
#else
	return 0;
#endif
}

int sockQuit(void)
{
#ifdef _WIN32
	return WSACleanup();
#else
	return 0;
#endif
}

/* Note: For POSIX, typedef SOCKET as an int. */
#ifndef _WIN32
typedef int SOCKET;
typedef sockaddr SOCKADDR;
typedef unsigned long DWORD;
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif // !INVALID_SOCKET


#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif // !SOCKET_ERROR

int sockClose(SOCKET sock)
{
	int status = 0;
#ifdef _WIN32
	status = shutdown(sock, SD_BOTH);
	if (status == 0) { status = closesocket(sock); }
#else
	status = shutdown(sock, SHUT_RDWR);
	if (status == 0) { status = close(sock); }
#endif
	return status;
}
//http://www.binarytides.com/raw-sockets-using-winsock/
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;


enum class GreetingType : unsigned char {
	HI = 1, HELLO = 2, BYE = 3
};

enum class HonorificType : unsigned char {
	MS = 1, MR = 2, LADY = 3, SIR = 4
};

struct myheader {
	GreetingType greeting;
	HonorificType honorific;
	unsigned short int len;
};

std::ostream& operator<<(std::ostream& os, const HonorificType& h)
{
	switch (h)
	{
	case HonorificType::MS:
		os << " Ms. ";
		break;
	case HonorificType::MR:
		os << " Mr. ";
		break;
	case HonorificType::LADY:
		os << " Lady ";
		break;
	case HonorificType::SIR:
		os << " Sir ";
		break;
	default:
		break;
	}
	return os;
}

std::ostream& operator<<(std::ostream& os, const GreetingType& g)
{
	switch (g)
	{
	case GreetingType::HI:
		os << "Hi";
		break;
	case GreetingType::HELLO:
		os << "Hello";
		break;
	case GreetingType::BYE:
		os << "Bye";
		break;
	default:
		break;
	}
	return os;
}

void printError()
{
#ifdef _WIN32
	int iError = WSAGetLastError();
	if (iError) {
		if (iError == WSAEACCES) {
			std::cout << "WSAEACCES error, this program needs administrative privileges" << std::endl;
		}
		else {
			std::cout << "Another type of error" << std::endl;
		}
	}
#else
	if (errno) {
		perror("Socket error: ");
	}
#endif // _WIN32
}

void forceExitAndCleanup(SOCKET fd) {
	sockClose(fd);
	sockQuit();
	exit(1);
}

#define PCKT_LEN 512
#define MY_PROTOCOL 253 //IP protocol number reserved for testing and experimentation http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define SEND_PORT 27015
#define LISTEN_PORT SEND_PORT+1

void exampleListenRAW(SOCKET fd) {
	char buffer[PCKT_LEN];
	struct sockaddr_in din;
	struct myheader *myheader = (struct myheader *) (buffer + sizeof(ip_hdr));
	memset(buffer, 0, PCKT_LEN);

	din.sin_family = AF_INET;
	din.sin_addr.s_addr = inet_addr("127.0.0.1");
	din.sin_port = htons(LISTEN_PORT);

	if (bind(fd, (SOCKADDR *)& din, sizeof(din)) == SOCKET_ERROR) {
		printError();
		forceExitAndCleanup(fd);
	};

	if (recvfrom(fd, buffer, PCKT_LEN, 0, NULL, NULL) == SOCKET_ERROR) {
		printError();
		forceExitAndCleanup(fd);
	};

	std::string name(buffer+sizeof(ip_hdr)+sizeof(myheader),myheader->len);
	std::cout << myheader->greeting << myheader->honorific << name << std::endl;
}

void exampleSendRAW(SOCKET fd) {
	char buffer[PCKT_LEN];
	struct sockaddr_in sin, din;
	IPV4_HDR *v4hdr = (IPV4_HDR *)buffer;
	struct myheader *myheader = (struct myheader *) (buffer + sizeof(ip_hdr));
	memset(buffer, 0, PCKT_LEN);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(SEND_PORT);

	din.sin_family = AF_INET;
	din.sin_addr.s_addr = inet_addr("127.0.0.1");
	din.sin_port = htons(LISTEN_PORT);

	if (bind(fd, (SOCKADDR *)& sin, sizeof(sin)) == SOCKET_ERROR) {
		printError();
		forceExitAndCleanup(fd);
	}

	const DWORD one = 1;
	const char *val = (const char *)&one;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == SOCKET_ERROR) {
		printError();
		forceExitAndCleanup(fd);
	}

	myheader->greeting = GreetingType::HELLO;
	myheader->honorific = HonorificType::MR;
	std::string name = "Socket McSocketFace";
	myheader->len = (unsigned short)name.length();
	//This is the operation that gives a warning in MSVC unless Checked Iterators are disabled with #pragma warning(disable : 4996)
	name.copy(buffer + sizeof(ip_hdr) + sizeof(myheader), myheader->len);

	int totalLength = sizeof(ip_hdr) + sizeof(myheader) + myheader->len;

	v4hdr->ip_version = 4;
	v4hdr->ip_header_len = 5;
	v4hdr->ip_tos = 0;
	v4hdr->ip_total_length = htons(totalLength);
	v4hdr->ip_id = htons(2);
	v4hdr->ip_frag_offset = 0;
	v4hdr->ip_frag_offset1 = 0;
	v4hdr->ip_reserved_zero = 0;
	v4hdr->ip_dont_fragment = 1;
	v4hdr->ip_more_fragment = 0;
	v4hdr->ip_ttl = 8;
	v4hdr->ip_protocol = MY_PROTOCOL;
	v4hdr->ip_srcaddr = inet_addr(inet_ntoa(sin.sin_addr));
	v4hdr->ip_destaddr = inet_addr(inet_ntoa(din.sin_addr));
	v4hdr->ip_checksum = 0;

	int result = sendto(fd, buffer, totalLength, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (result == SOCKET_ERROR) {
		printError();
		forceExitAndCleanup(fd);
	}
	else {
		std::cout << "Bytes sent: " << result << std::endl;
	}
}

int main(int argc, char **argv)
{
	sockInit();
	SOCKET fd = socket(AF_INET, SOCK_RAW, MY_PROTOCOL);
	if (fd!=INVALID_SOCKET) {
		std::cout << "Raw socket open" << std::endl;
	}
	else {
		printError();
		sockQuit();
		exit(1);
	}

	bool listen = false;
	if (argc == 2) {
		if (std::string(argv[1]) == "listen") {
			listen = true;
		}
	}
	if (listen) {
		exampleListenRAW(fd);
	}
	else {
		exampleSendRAW(fd);
	}

	sockClose(fd);
	sockQuit();
	return 0;
}