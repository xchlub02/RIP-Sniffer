/**
 * @author Pavel Chlubna, xchlub02
 * @date November, 2018
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>

#include "packet_structure.h"
#include "myripresponse.h"


int main(int argc, char* argv[])
{
	res_arg args;
	int opt;
	bool arg_i, arg_r;

	bzero(args.interface, 256);
	args.address = in6addr_any;
	inet_pton(AF_INET6, "::", &args.nexthop);
	args.nexth = false;
	args.prefix = 0;
	args.metric = 1;
	args.tag = 0;
	arg_i = arg_r = false;

	while((opt = getopt(argc, argv, "i:r:m:n:t:")) != -1)
	{
		switch (opt) {
			case 'i':
				strcpy(args.interface, optarg);
				arg_i = true;
				break;

			case 'r': ;
				char *addr = strtok(optarg, "/");
				char *prefix = strtok(NULL, "/");
				arg_r = true;

				if (!inet_pton(AF_INET6, addr, &args.address)) {
          			fprintf(stderr, "Invalid format of IP address.\n");
          			return -1;
        		}

        		if (prefix == NULL) {
          			fprintf(stderr, "Missing prefix length.\n");
         			return -1;
        		}

				args.prefix = atoi(prefix);
				break;

			case 'm': ;
				int metric = atoi(optarg);
				
				if(metric < 0 || metric > 16)
				{
					fprintf(stderr, "Wrong metric, out of range\n");
					return -1;
				}

				args.metric = metric;
				break;

			case 'n':
				args.nexth = true;

				if (inet_pton(AF_INET6, optarg, &args.nexthop) != 1)
				{
          			fprintf(stderr, "Invalid Next Hop address\n");
          			return -1;
        		}
				break;

			case 't': ;
				int tag = atoi(optarg);

				if(tag < 0 || tag > 65535)
				{
					fprintf(stderr, "Wrong tag, out of range\n");
					return -1;
				}

				args.tag = tag;
				break;
			default:
				break;
		}
	}

	if(!(arg_i && arg_r))
	{
		fprintf(stderr, "Paremetr -i or -r wasnt't set\n");
		exit(EXIT_FAILURE);
	}

	send_packet(&args);
}


/*
 * Jak pracovat se socketem v IPv6 jsem nasel inspiraci v clanku zde:
 * https://blog.apnic.net/2017/10/24/raw-sockets-ipv6/
 *
 * Odesilani na multicast a nastavovani socketu jsem studoval z:
 * https://docs.oracle.com/cd/E19683-01/816-5042/sockets-13/index.html
 * http://www.ciscopress.com/articles/article.asp?p=762938&seqNum=10
 */
void send_packet(res_arg *args)
{
	u_char* ripng;
	size_t size;
	int sockfd;
	struct sockaddr_in6 my_addr, dest_addr;
	int ret;

	ripng = set_packet(args, &size);
	
	sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if(sockfd == -1)
	{
		fprintf(stderr,"ERROR occurred while creating socket\n");
		return;
	}

	int hops = 255;

	setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)); //sets hop count to 255
	setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, args->interface, strlen(args->interface));

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin6_family = AF_INET6;
  	my_addr.sin6_addr = in6addr_any;
  	my_addr.sin6_port = htons(521);

	ret = bind(sockfd, (struct sockaddr*)&my_addr, sizeof(my_addr));

	if (ret == -1) {
    	fprintf(stderr, "ERROR occurred while binding socket\n");
        free(ripng);
		exit(EXIT_FAILURE);
  	}

	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "ff02::9", &dest_addr.sin6_addr); //ff02::9 is multicast for ripng
	dest_addr.sin6_port = htons(521);

	int err = sendto(sockfd, ripng, size, 0, (struct sockaddr *) &dest_addr,
		sizeof(dest_addr));

	if(err == -1)
		fprintf(stderr, "Pacekt wasn't send properly\n");
	else
		printf("Sending complete\n");

	close(sockfd);
	free(ripng);
}


/*
 * Jakymi daty packet naplnit jsem zjistil
 * manualech prilozenych v zadani projektu
 * https://tools.ietf.org/html/rfc2080
 */
u_char *set_packet(const res_arg *args, size_t *size)
{
	u_char* ripng;	
	rip_header header;
	ripng_entry_table entry;

	if(args->nexth)
		*size = HEADER_LEN + 2 * ENTRY_LEN;
	else
		*size = HEADER_LEN + ENTRY_LEN;

	ripng = (u_char *) malloc(*size);

	header.command = 2;		//RESPONSE
	header.version = 1;		//version 1 of ripng
	header.zero_fill = 0;
	
	memcpy(ripng, &header, HEADER_LEN);

	entry.prefix = args->address;
	entry.route_tag = htons(args->tag);
	entry.prefix_length = args->prefix;
	entry.metric = args->metric;

	if(args->nexth)
	{
		//arg for next hop was set, that means we have to alocate additional space for extra entry

		ripng_entry_table entryhop;

		entryhop.prefix = args->nexthop;
		entryhop.route_tag = 0;
		entryhop.prefix_length = 0;
		entryhop.metric = 0xFF;

		memcpy(ripng + HEADER_LEN, &entryhop, ENTRY_LEN);
		memcpy(ripng + HEADER_LEN + ENTRY_LEN, &entry, ENTRY_LEN);
	}
	else
	{
		memcpy(ripng + HEADER_LEN, &entry, ENTRY_LEN);
	}

	return ripng;
}
