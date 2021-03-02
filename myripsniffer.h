/**
 * @author Pavel Chlubna, xchlub02
 * @date November, 2018
 */

#ifndef ISA_PACKET_SNIFFER_H
#define ISA_PACKET_SNIFFER_H

#include "packet_structure.h"
#include <pcap.h>


/**
 * @brief Starts with sniffing and filtering the packets
 * @param interface sets the interface to be sniffed on
 */
void sniffer(char *interface);


/**
 * @brief prints informations in header of RIPv1 or RIPv2 packet
 * @param header structure of RIP header
 */
void rip_header_print(rip_header *header);


/**
 * @brief prints informations in header of RIPv1 or RIPv2 packet
 * @param header structure of RIPng header
 */
void ripng_header_print(rip_header *header);


/**
 * @brief Prints authentication part of RIPv2 packet
 * @param entry structure of RIP Entry Table
 */
void rip_authentication_print(rip_entry_table *entry);


/**
 * @brief Prints entry table of RIPng packet
 * @param entry structure of RIPng Entry Table
 */
void ripng_entry_print(ripng_entry_table *entry);


/**
 * @brief Prints next hop RTE of RIPng packet
 * @param entry structure of RIPng Entry Table
 */
void ripng_hop_print(ripng_entry_table *entry);



/**
 * @brief Prints entry table of RIPng packet
 * @param entry structure of RIP Entry Table
 * @param version Version of RIP packet (RIPv1 or RIPv2)
 */
void rip_entry_print(rip_entry_table *entry, uint8_t version);

/**
 * @brief The ctrl + c signal handler, breaks the infinite pcap_loop
 */
void intHandler();

/**
 * @brief function called by pcap_loop. Parse the packet and call functions to print content of the packet
 * @param args
 * @param header
 * @param packet Contains the packet to be parsed
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //ISA_PACKET_SNIFFER_H
