#include<pcap.h>
#include<iostream>
#include<libnet.h>

void print_mac(uint8_t * mac)
{
  printf("Ethernet src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
      mac[0], mac[1],
      mac[2], mac[3],
      mac[4], mac[5]);
}


void handler(const u_char * packet)
{
	libnet_ethernet_hdr * eth = (libnet_ethernet_hdr *)packet;
	uint16_t eth_type = ((eth->ether_type & 0xff)<<8) + 
		                ((eth->ether_type & 0xff00)>>8);

	libnet_ipv4_hdr * ip = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
	libnet_tcp_hdr * tcp = (libnet_tcp_hdr *)((u_char *)ip+sizeof(libnet_ipv4_hdr));
	u_char * payload;

	if(eth_type != 0x0800)return;

	puts("-----------------------------------");
	//ETHERNET HEADER PARSING
	puts("+ETHERNET HEADER+");
  print_mac(eth->ether_shost);
  print_mac(eth->ether_dhost);
	printf("Ethernet Type : 0x%04x\n",eth_type);
	putchar(10);

	//IP HEADER PARSING
	puts("+IP HEADER+");
	printf("IP src : %s\n",inet_ntoa(ip->ip_src));
	printf("IP dst : %s\n",inet_ntoa(ip->ip_dst));

	//TCP PARSING
	puts("+TCP HEADER+");
	printf("PORT src : %5d\n",tcp->th_sport);
	printf("PORT dst : %5d\n",tcp->th_dport);

	//PAYLOAD(DATA) PARSING
	uint32_t length = ip->ip_len - sizeof(libnet_ipv4_hdr)
				      - sizeof(libnet_tcp_hdr);
	printf("PAYLOAD LENGTH : %d\n",length);

	if(length > 16) length = 16;

	payload = (u_char *)tcp + tcp->th_off * 4;

	printf("PAYLOAD(DATA) : ");

	for(int i=0 ; i<length ; i++){
		printf("%02x",payload[i]);
	}
	putchar(10);
	puts("-----------------------------------");
	printf("\n\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    handler(packet);
  }

  pcap_close(handle);
  return 0;
}
