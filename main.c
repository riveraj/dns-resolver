/*
Copyright (c) 2013, John Rivera
All rights reserved.

Licensed under the BSD 2-Clause License

Credits:
Structs thanks to Silver Moon:
http://www.binarytides.com/dns-query-code-in-c-with-winsock/

DNS resolver. This program allows the user to enter a domain name and
resolves it into a IPv4 address. The program also displays any canonical
names associated with the domain name.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Struct for the DNS Header */
typedef struct header {
	unsigned short id;
	unsigned char rd : 1;
	unsigned char tc : 1;
	unsigned char aa : 1;
	unsigned char opcode : 4;
	unsigned char qr : 1;
	unsigned char rcode : 4;
	unsigned char z : 3;	
	unsigned char ra : 1;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} HEADER;

/* Struct for the flags for the DNS Question */
typedef struct q_flags {
	unsigned short qtype;
	unsigned short qclass;
} Q_FLAGS;

/* Struct for the flags for the DNS RRs */
typedef struct rr_flags {
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
} RR_FLAGS;

void get_dns_servers(char *str[]);
void change_to_dns_format(char *src, unsigned char *dest);
void change_to_dot_format(unsigned char *str);

int main(int argc, char *argv[]) {

	/* Prints message and exits if user enters less than or more than one
	argument */
	if(argc == 1) {
		printf("Usage: resolver <hostname(s) to check>\n");
		return 1;
	}

	if(argc > 2) {
		printf("Multiple queries are not supported.\n");
		return 1;
	}

	HEADER *header = NULL;
	unsigned char *qname;
	Q_FLAGS *qflags = NULL;
	unsigned char name[10][254];	
	RR_FLAGS *rrflags = NULL;
	unsigned char rdata[10][254];
	unsigned int type[10];
	unsigned char packet[65536];
	unsigned char *temp;	
	int i, j, steps = 0;

	/* Obtaining the DNS servers from the resolv.conf file */
	char **dns_addr = malloc(10 * sizeof(char *));
	for(i = 0; i < 10; ++i)
		dns_addr[i] = malloc(INET_ADDRSTRLEN);
	get_dns_servers(dns_addr);

	/* Building the Header portion of the query packet */
	header = (HEADER *)&packet;
	header->id = (unsigned short)htons(getpid());
	header->qr = 0;
	header->opcode = 0;
	header->aa = 0;
	header->tc = 0;
	header->rd = 1;
	header->ra = 0;
	header->z = 0;
	header->rcode = 0;
	header->qdcount = htons((unsigned short)(argc - 1));
	header->ancount = 0x0000;
	header->nscount = 0x0000;
	header->arcount = 0x0000;

	steps = sizeof(HEADER);	

	/* Adding user-entered hostname into query packet and converting into DNS
	format */
	qname = (unsigned char *)&packet[steps];
	change_to_dns_format(argv[1], qname);

	steps = steps + (strlen((const char *)qname) + 1);

	/* Building the Question flags portion of the query packet */
	qflags = (Q_FLAGS *)&packet[steps];
	qflags->qtype = htons(0x0001);
	qflags->qclass = htons(0x0001);

	steps = steps + sizeof(Q_FLAGS);

	/* Building the socket for connecting to the DNS server */
	long sock_fd;
	struct sockaddr_in servaddr;
	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(53);
	inet_pton(AF_INET, dns_addr[1], &(servaddr.sin_addr));

	/* Connecting to the DNS server */
	connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	/* Sending the query packet to the DNS server */
	write(sock_fd, (unsigned char *)packet, steps);

	/* Receiving the response packet from the DNS server */
	if(read(sock_fd, (unsigned char *)packet, 65536) <= 0)
	close(sock_fd);
	for(i = 0; i < 10; ++i)
		free(dns_addr[i]);
	free(dns_addr);	

	/* Parsing the Header portion of the reply packet */
	header = (HEADER *)&packet;
	steps = sizeof(HEADER);

	/* Parsing the QNAME portion of the reply packet */
	qname = (unsigned char *)&packet[steps];
	change_to_dot_format(qname);
	steps = steps + (strlen((const char *)qname) + 2);

	/* Parsing the Question flags portion of the reply packet */
	qflags = (Q_FLAGS *)&packet[steps];
	steps = steps + sizeof(Q_FLAGS);

	/* Parsing the RRs from the reply packet */
	for(i = 0; i < ntohs(header->ancount); ++i) {

		/* Parsing the NAME portion of the RR */		
		temp = (unsigned char *)&packet[steps];
		j = 0;
		while(*temp != 0) {
			if(*temp == 0xc0) {
				++temp;
				temp = (unsigned char*)&packet[*temp];
			}
			else {
				name[i][j] = *temp;
				++j;
				++temp;
			}
		}
		name[i][j] = '\0';
		change_to_dot_format(name[i]);
		steps = steps + 2;

		/* Parsing the RR flags of the RR */
		rrflags = (RR_FLAGS *)&packet[steps];
		steps = steps + sizeof(RR_FLAGS) - 2;

		/* Parsing the IPv4 address in the RR */
		if(ntohs(rrflags->type) == 1) {
			for(j = 0; j < ntohs(rrflags->rdlength); ++j)
				rdata[i][j] = (unsigned char)packet[steps + j];
			type[i] = ntohs(rrflags->type);
		}

		/* Parsing the canonical name in the RR */
		if(ntohs(rrflags->type) == 5) {
			temp = (unsigned char *)&packet[steps];
			j = 0;
			while(*temp != 0) {
				if(*temp == 0xc0) {
					++temp;
					temp = (unsigned char*)&packet[*temp];
				}
				else {
					rdata[i][j] = *temp;
					++j;
					++temp;
				}
			}
			rdata[i][j] = '\0';
			change_to_dot_format(rdata[i]);
			type[i] = ntohs(rrflags->type);		
		}
		steps = steps + ntohs(rrflags->rdlength);
	}
	
	/* Printing the output */
	printf("QNAME: %s\n", qname);
	printf("ANCOUNT: %d\n", ntohs(header->ancount));	
	printf("\nRDATA:");
	for(i = 0; i < ntohs(header->ancount); ++i) {
		printf("\nNAME: %s\n\t", name[i]);		
		if(type[i] == 5)
			printf("CNAME: %s", rdata[i]);
		else if(type[i] == 1) {
			printf("IPv4: ");
			for(j = 0; j < ntohs(rrflags->rdlength); ++j) 
				printf("%d.", rdata[i][j]);
			printf("\b ");
		}
	}
	putchar('\n');

	return 0;
}

/* The function obtains the DNS servers stored in /etc/resolv.conf */
void get_dns_servers(char *str[]) {

	FILE *resolv_file;
	char line[100];
	int i = 0;

	resolv_file = fopen("/etc/resolv.conf", "rt");
	
	while(fgets(line, 100, resolv_file))
	{
		if(strncmp(line, "nameserver", 10) == 0) {
			strcpy(str[i], strtok(line, " "));
			strcpy(str[i], strtok(NULL, "\n"));
			++i;
		}
	}

	fclose(resolv_file);
}

/* The function converts the dot-based hostname into the DNS format (i.e.
www.apple.com into 3www5apple3com0) */
void change_to_dns_format(char *src, unsigned char *dest) {
	int pos = 0;
	int len = 0;
	int i;
	strcat(src, ".");
	for(i = 0; i < (int)strlen(src); ++i) {
		if(src[i] == '.') {
			dest[pos] = i - len;
			++pos;
			for(; len < i; ++len) {
				dest[pos] = src[len];
				++pos;
			}
			len++;
		}
	}
	dest[pos] = '\0';
}

/* This function converts a DNS-based hostname into dot-based format (i.e.
3www5apple3com0 into www.apple.com) */
void change_to_dot_format(unsigned char *str) {
	int i, j;
	for(i = 0; i < strlen((const char*)str); ++i) {
		unsigned int len = str[i];
		for(j = 0; j < len; ++j) {
			str[i] = str[i + 1];
			++i;
		}
		str[i] = '.';
	}
	str[i - 1] = '\0';
}
