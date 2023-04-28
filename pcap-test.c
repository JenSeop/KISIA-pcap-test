#include <pcap.h>
#include <stdio.h>
#include "netsec.h"

char color[8][10] =
{
	"\033[0;30m",// Black
	"\033[0;31m",// Red
	"\033[0;32m",// Green
	"\033[0;33m",// Yellow
	"\033[0;34m",// Blue
	"\033[0;35m",// Purple
	"\033[0;36m",// Cyan
	"\033[0;37m" // White
};
#define BLACK color[0]
#define RED color[1]
#define GREEN color[2]
#define YELLOW color[3]
#define BLUE color[4]
#define PURPLE color[5]
#define CYAN color[6]
#define WHITE color[7]

void title() {
	printf("%s=======================\n",WHITE);
	printf("%sNETWROK SECURITY REPORT\n",RED);
	printf("%sCode by. JungsKim\n",CYAN);
	printf("%s=======================\n\n",WHITE);
	printf("%s\"PCAP-TEST\" STARTING...\n",WHITE);
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

BOOL parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		printf("%sERROR : PLZ INPUT COMMAND\n",RED);
		return FALSE;
	}
	param->dev_ = argv[1];
	return TRUE;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return FALSE;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "%spcap_open_live(%s) return null - %s\n",RED,param.dev_,errbuf);
		return FALSE;
	}
	title();
	while (TRUE) {
		struct pcap_pkthdr* hd;
		const u_char* pk;
		int res = pcap_next_ex(pcap, &hd, &pk);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("%spcap_next_ex return %d(%s)\n",RED,res,pcap_geterr(pcap));
			break;
		}
        // PACKET
		printf("\n%s★ PACKET\n",GREEN);
        printf("%s - Length : %u\n",WHITE,hd->caplen);

		// ETHERNET HEADER
        const struct eth_hdr* pk_eth = (const struct eth_hdr*)pk;
		printf("%s* ETHERNET\n",BLUE);
		// MAC HEADER : DA => SA => Type
        printf("%s - MAC : ",WHITE);
        // DA => Destination Address
        for (int i = 0; i < ETH_ALEN; ++i)
            printf("%s%02X", (i ? ":" : ""), pk_eth->DA[i]);
        // SA => Source Address
        for (int i = 0; i < ETH_ALEN; ++i)
            printf("%s%02X", (i ? ":" : ""), pk_eth->SA[i]);
		printf("\n");

		// IPv4  HEADER
        printf("%s* IPv4\n",YELLOW);
        const struct ipv4_hdr *pk_ipv4 = (const struct ipv4_hdr *)pk_eth->PI;
        printf("%s - IP : ",WHITE);
        // SIA => Source IP Address
		printf("(SA) ");
        for (int i = 0; i < IPV4_ALEN; ++i)
            printf("%s%d", (i ? "." : ""), pk_ipv4->SIA[i]);
        // DIA => Destination IP Address
		printf(" (DA) ");
        for (int i = 0; i < IPV4_ALEN; ++i)
            printf("%s%d", (i ? "." : ""), pk_ipv4->DIA[i]);
        printf("\n");

		// TCP HEADER
        printf("%s* TCP\n",PURPLE);
        uint8_t ihl = IPV4_HL(pk_ipv4);
        const struct tcp_hdr* pk_tcp = (const struct tcp_hdr*)&pk_ipv4->INF[ihl - IPV4_HL_MIN];
        uint16_t length = ntohs(pk_ipv4->TL) - ihl;
        printf("%s - PORT : (SA) %d (DA) %d\n",WHITE,ntohs(pk_tcp->SP),ntohs(pk_tcp->DP));
        uint8_t thl = TCP_HL(pk_tcp);
	}
	pcap_close(pcap);
}