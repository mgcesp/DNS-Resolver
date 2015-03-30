#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
 
// DNS resource records
#define T_A 1   // Ipv4 address
#define T_NS 2  // Nameserver
 
// DNS Header Struct
struct HEADER
{
  unsigned short id; 
 
  //3rd byte
  unsigned char rd :1; 
  unsigned char tc :1; 
  unsigned char aa :1; 
  unsigned char opcode :4;
  unsigned char qr :1; 
 
  //4th byte
  unsigned char rcode :4;
  unsigned char cd :1; 
  unsigned char ad :1; 
  unsigned char z :1; 
  unsigned char ra :1; 
 
  unsigned short q_count;
  unsigned short ans_count;
  unsigned short auth_count;
  unsigned short add_count; 
};
 
struct QUESTION
{
  unsigned short qtype;
  unsigned short qclass;
};
 
//make sure the alighment matches the DNS message format specification
//i.e., there should not be any padding.
//(by default, C struct aligment is based on the "widest" field
#pragma pack(push, 1)
struct R_DATA
{
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)
 
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};
 
typedef struct
{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;

// function prototypes
void dnsquery(unsigned char*);
void getDnsFormat(unsigned char*,unsigned char*);
unsigned char* getName(unsigned char*,unsigned char*,int*);
void setHeader(struct HEADER *dns);
void receivePacket(int sockfd, char* buffer, struct sockaddr_in dest_address);
void sendPacket(int sockfd, char* buffer, unsigned char *query_name, struct sockaddr_in dest_address);
void print_details(struct HEADER *);
void readQueryAnswer(int stop, struct HEADER *dns, unsigned char* buffer, unsigned char *query_index, struct RES_RECORD answ_records[]);

