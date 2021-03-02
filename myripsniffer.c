/**
 * @author Pavel Chlubna, xchlub02
 * @date November, 2018
 */

#include "myripsniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>

pcap_t *handle; //Handle of the device that shall be sniffed


int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        fprintf(stderr, "\nInvalid number of arguments\n");
        return -1;
    }

    if(strcmp("-i", argv[1]) != 0)
    {
        fprintf(stderr, "\nInvalid parameters\n");
        return -1;
    }

    char *interface = argv[2];

	signal(SIGINT, intHandler);

    sniffer(interface);

    return 0;
}


/*
 * Jak zpracovavat signaly jsem se docetl a inspiroval na tomto foru:
 * https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
 */
void intHandler()
{
    //breakes the inf loop
	pcap_breakloop(handle);
}


void rip_header_print(rip_header *header)
{
    time_t t;
    struct tm *time_inf;
    char c_t[10];

    time(&t);
    time_inf = localtime(&t);
    strftime(c_t, 10, "%T", time_inf);

	printf("*********************RIP Header*********************\n");
	
    printf("Time:\t\t\t%s\nProtocol:\t\tRIPv%d\n", c_t, header->version);

    if(header->command == 1)
        printf("Command:\t\tRequest\n");
    else if(header->command == 2)
        printf("Command:\t\tResponse\n");
    else
    {
        printf("Command:\t\tUnknown\n");
    }

	printf("****************************************************\n\n");
}


void ripng_header_print(rip_header *header)
{
    if (header->version != 1) {
        fprintf(stderr, "Invalid RIPng version\n");
        return;
    }

    time_t t;
    struct tm *time_inf;
    char c_t[10];

    time(&t);
    time_inf = localtime(&t);
    strftime(c_t, 10, "%T", time_inf);

	printf("*******************RIPng Header*********************\n");

    printf("Time:\t\t\t%s\nProtocol:\t\tRIPng\n", c_t);

    if(header->command == 1)
        printf("Command:\t\tRequest\n");
    else if(header->command == 2)
        printf("Command:\t\tResponse\n");
    else
    {
        printf("Command:\t\tUnknown\n");
    }

	printf("****************************************************\n\n");
}


void rip_authentication_print(rip_entry_table *entry)
{
    printf("***************RIP Authentication*******************\n");

    if(ntohs(entry->route_tag) == 2)
    {
        printf("Type:\t\t\tSimple password\n");
        char c_password[17]; //The remaining 16 octets contain the plain text password
        c_password[16] = 0;
        memcpy(c_password, entry->data.authentication, 16);
		printf("Password:\t\t%s\n",c_password);
    }
    else if(ntohs(entry->route_tag) == 3)
    {
        printf("Type:\t\t\tMD5\nKey ID:\t\t\t%d\nAuth data length:\t%d\nOffset:\t\t\t%d\n",
		entry->data.key_id, entry->data.auth_data_len, ntohs(entry->data.offset));
    }
    else if(ntohs(entry->route_tag) == 1)
    {
		char pswd[32] = {0};
		
		for(int i = 0; i < 16; ++i)
		{
			snprintf(pswd + (i * 2), 3, "%02x",entry->data.authentication[i]);
		}

		printf("MD5 Password:\t%s\n",pswd);
	}
    else
    {
        fprintf(stderr,"Invalid authentication\n");
        return;
    }

		printf("****************************************************\n\n");
}


void ripng_entry_print(ripng_entry_table *entry)
{
    char ip_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &entry->prefix, ip_addr, sizeof(ip_addr));

	printf("*******************RIPng ENTRY**********************\n");
    printf("Route tag:\t\t%d\nIPv6 Prefix:\t\t%s\nPrefix Length:\t\t%d\nMetric:\t\t\t%d\n",
	ntohs(entry->route_tag), ip_addr, entry->prefix_length, entry->metric);
	printf("****************************************************\n\n");
}


void ripng_hop_print(ripng_entry_table *entry)
{
	printf("******************RIPng Next Hop********************\n");
    char ip_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &entry->prefix, ip_addr, sizeof(ip_addr));
    printf("Next Hop:\t\t%s\n", ip_addr);
	printf("****************************************************\n\n");
}


void rip_entry_print(rip_entry_table *entry, uint8_t version)
{
	char hop[255];
	strcpy(hop, inet_ntoa(entry->data.next_hop)); 

    printf("*********************RIP ENTRY**********************\n");
    printf("Route tag:\t\t%d\n",ntohs(entry->route_tag));

    if(ntohs(entry->addr_faml) == AF_INET)
    {
        printf("AFI:\t\t\t%d (IP)\nIP Address:\t\t%s\n",
               ntohs(entry->addr_faml), inet_ntoa(entry->data.ip_addr));

        if(version == 2)
			printf("Mask:\t\t\t%s\nNext Hop:\t\t%s\n", inet_ntoa(entry->data.mask), hop);
		
		printf("Metric:\t\t\t%d\n", (int) ntohl(entry->data.metric));
    }
    else
	{
        printf("AFI:\t\t\t%d\n", ntohs(entry->addr_faml));
	}
	
	printf("****************************************************\n\n");
}


/*
 * Jak vypada strukturu prichozich dat jsem zjistoval v prednaskach
 * isa-architektura.pdf	a v prednaskach z IPK
 *
 * Pri parsovani packetu jsem se v kódu inspiroval v clanku
 * Programming with Libpcap, ktery je prilozen v prednasce isa-sniffing.pdf
 * http://www.programming-pcap.aldabaknocking.com/
 *
 * Dalsim zdrojem pri praci s packetem byly clanky:
 * https://www.devdungeon.com/content/using-libpcap-c
 * https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 *
 * a také vlakno na diskuznim foru:
 * https://ubuntuforums.org/showthread.php?t=954426
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void) header;
    (void) args;

    ipv4_header *ip_hdr;
    udp_header *udp_hdr;
    rip_header *rip_hdr;
    int rip_length;
    char srcip[255], dstip[255];

    ip_hdr = (ipv4_header *) (packet + 14); //14 == length of ethrnet header

    if((ip_hdr->ver_hlen >> 4) == 4)
    {
        //ipv4
        udp_hdr = (udp_header *) (packet + 14 + ((ip_hdr->ver_hlen & 0x0f) * 4)); //14 == length of ethrnet header
        rip_length = ntohs(udp_hdr->udp_length) - 8; //8 == length of udp header
        rip_hdr = (rip_header *) (packet + 14 + ((ip_hdr->ver_hlen & 0x0f) * 4) + 8); //14 == length of ethrnet header, 8 == length of udp header
        strcpy(srcip, inet_ntoa(ip_hdr->src_addr));
        strcpy(dstip, inet_ntoa(ip_hdr->dest_addr));

        //rip has to be long at least length of hrader
        if(rip_length < HEADER_LEN)
        {
            fprintf(stderr, "Invalid RIP packet length\n");
            return;
        }


        printf("\n\n________________________________________________________\n");
        printf("*********************NEW PACKET*********************\n");
        printf("________________________________________________________\n");

        printf("****************************************************\n");
        printf("Source IP:\t\t%s\nDestination IP:\t\t%s\n", srcip, dstip);
        printf("****************************************************\n");
        printf("Source Port:\t\t%d\nDestination Port:\t%d\n", ntohs(udp_hdr->udp_src), ntohs(udp_hdr->udp_dest));
        printf("****************************************************\n\n");

        rip_header_print(rip_hdr);

        rip_entry_table *entry = (rip_entry_table *) ((u_char *) rip_hdr + HEADER_LEN);

        //reads all rip entry tables
        for(rip_length -= HEADER_LEN; rip_length >= ENTRY_LEN; rip_length -= ENTRY_LEN)
        {
            if(entry->addr_faml == 0xFFFF)
            {
                //if Address Family Identifier contains 0xFFFF, then this entry contains authentication
                rip_authentication_print(entry);
            }
            else
            {
                rip_entry_print(entry, rip_hdr->version);
            }

            entry = (rip_entry_table *) ((u_char *) entry + ENTRY_LEN); //length of rip header == 4
        }
    }
    else
    {
        //ipv6
        struct ipv6_header *ipv6_hdr = (ipv6_header *) (ip_hdr);

        udp_hdr = (udp_header *) (packet + 14 + 40); //14 == length of ethrnet header, 40 == length of ipv6 header
        rip_length = ntohs(udp_hdr->udp_length) - 8; //8 == length of udp header
        rip_hdr = (rip_header *) (packet + 14 + 40 + 8); //14 == length of ethrnet header, 40 == length of ipv6 header, 8 == length of udp header
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_src, srcip, sizeof(srcip));
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_dst, dstip, sizeof(dstip));

        //rip has to be long at least length of hrader
        if(rip_length < HEADER_LEN)
        {
            fprintf(stderr, "Invalid RIP packet length");
            return;
        }

        printf("\n\n________________________________________________________\n");
        printf("*********************NEW PACKET*********************\n");
        printf("________________________________________________________\n");

        printf("****************************************************\n");
        printf("Source IP:\t\t%s\nDestination IP:\t\t%s\n", srcip, dstip);
        printf("****************************************************\n");
        printf("Source Port:\t\t%d\nDestination Port:\t%d\n", ntohs(udp_hdr->udp_src), ntohs(udp_hdr->udp_dest));
        printf("****************************************************\n\n");

        ripng_header_print(rip_hdr);

        ripng_entry_table *entry = (ripng_entry_table *) ((u_char *) rip_hdr + HEADER_LEN);

        //reads all rip entry tables
        for(rip_length -= HEADER_LEN; rip_length >= ENTRY_LEN; rip_length -= ENTRY_LEN)
        {
            if(entry->metric == 0xFF)
            {
                //if metric contains 0xFF, then entry contains nexthop address
                ripng_hop_print(entry);
            }
            else
            {
                ripng_entry_print(entry);
            }

            entry = (ripng_entry_table *) ((u_char *) entry + ENTRY_LEN); //20 == length of entry table
        }
    }

    printf("________________________________________________________\n");
    printf("*********************END OF PACKET*********************\n");
    printf("________________________________________________________\n\n\n");
}


/*
 * Zdroj : prednaska isa-sniffing.pdf
 * Pri praci s knihovnou pcap, nastavovanim filtru a odposlouchavani
 * na rozhrani a souboru jsem se inspiroval v prednaskach z ISA
 *
 * Praci s jednotlivymi funkcemi jsem cerpal na manualovych strankach
 * https://www.tcpdump.org/manpages/
 * http://www.tcpdump.org/pcap.html
 *
 * Nastavovani filtru jsem studoval na strance:
 * https://wiki.wireshark.org/CaptureFilters
 *
 */
void sniffer(char *interface)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    char filter[] = "portrange 520-521 and udp"; //RIP uses UDP. Port 520 for RIP v1,v2 and Port 521 for RIPng
    struct bpf_program fp;
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;

    if(strstr(interface, ".pcap") == NULL && strstr(interface, ".pcapng") == NULL)
    {
        //pcap_lookupnet - find the IPv4 network number and netmask for a device
        if(pcap_lookupnet(interface, &net, &mask, err_buf) != 0)
        {
            fprintf(stderr, "\nERROR Unable to get information for this interface (%s)\n", interface);
            exit(EXIT_FAILURE);
        }

        //pcap_open_live - open a device for capturing
        handle = pcap_open_live(interface, BUFSIZ, 1, 500, err_buf);
        if (handle == NULL)
        {
            fprintf(stderr, "\nERROR: This interface (%s) can't be open\n", interface);
            exit(EXIT_FAILURE);
        }

        //pcap_compile - compile a filter expression
        if (pcap_compile(handle, &fp, filter, 0, net) == -1)
        {
            fprintf(stderr, "\nERROR occurred while compiling filter\n");
            exit(EXIT_FAILURE);
        }

        //pcap_setfilter - set the filter
        if (pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "\nERROR occurred while setting filter\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
		

        handle = pcap_open_offline(interface, err_buf);
		
		pcap_loop(handle, 0, packet_handler, NULL);
		return;
    }

    //pcap_loop, pcap_dispatch - process packets from a live capture or savefile
    pcap_loop(handle, -1, packet_handler, NULL); //-1 means infinity

    //pcap_freecode - free a BPF program
    pcap_freecode(&fp);

    //pcap_close - close a capture device or savefile
    pcap_close(handle);
}
