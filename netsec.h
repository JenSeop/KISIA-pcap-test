#include <stdint.h>
#include <arpa/inet.h>

#ifndef NETSEC_H
#define NETSEC_H

typedef int BOOL;

#define TRUE 1
#define FALSE 0

// ETHERNET HEADER
#define ETH_ALEN 6
#define ETH_HLEN 14

struct eth_hdr {
	uint8_t DA[ETH_ALEN]; // DA => Target Ethernet Adr
	uint8_t SA[ETH_ALEN]; // SA => Host Ethernet Adr
	uint16_t DT; // Data type
	uint8_t PI[0]; // Proctocol Inf
} __attribute__((packed));


// IPv4  HEADER
#define IPV4_VER(XX) ((uint8_t)(((XX)->VIHL & 0xF0) >> 4))
#define IPV4_HL(XX)  ((uint8_t)(((XX)->VIHL & 0x0F) << 2))

#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04

struct ipv4_hdr {
	uint8_t VIHL; // Version + IHL(Header Length)
	uint8_t TOS; // Typte Of Service
	uint16_t TL; // Total Length
	uint16_t ID; // Identification
	uint16_t FF; // Fragment Offset
	uint8_t TTL; // Time-to-live
	uint8_t PRI; // Protocol Identifier
	uint16_t HC; // Header Checksum
	uint8_t SIA[4]; // SIA => Source IP Address
	uint8_t DIA[4]; // DIA => Destination IP Address
	uint8_t INF[0];
} __attribute__((packed));

// TCP HEADER
#define TCP_HL(XX) ((uint8_t)((((uint8_t*)(&(XX)->DRF))[0] & 0xF0) >> 2))
#define TCP_PAYLOAD_MAXLEN 16

struct tcp_hdr {
	uint16_t SP; // Source Port
	uint16_t DP; // Destination Port
	uint32_t SN; // Sequence Number
	uint32_t AN; // Acknowledgement Number
	uint16_t DRF; // Header Length + Reserved + Code Bits
	uint16_t WSF; // Windows Size Field
	uint16_t CH; // Checksum
	uint16_t UR; // Urgent
	uint8_t payload[0];
} __attribute__((packed));

#endif