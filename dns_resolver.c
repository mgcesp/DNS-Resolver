#include "dns_resolver.h"

// to store the next server IPs to query
char next_servers[10][100];

// flag to stop once an answer is found
int answer_found;

int main(int argc, char *argv[])
{
    unsigned char domain_name[100];

    // get root DNS server from argv
    strcpy(next_servers[0] , argv[1]);

    // get the domain_name from argv; memcpy is best way for unsigned char
    memcpy(&domain_name, argv[2], strlen(argv[2]) + 1);

    printf("\n______________________________________________________________\n");
    printf("DOMAIN NAME : %s\n", domain_name);
    printf("DNS ROOT SERVER IP : %s\n", next_servers[0]);
    printf("--------------------------------------------------\n");

    // while no answer record is fetched keep searching
    while(!answer_found)
    {
        // print DNS server that is being queried
        printf("DNS server to query: %s\n", next_servers[0]);
        // run a DNS query on domain name
        dnsquery(domain_name);
    }
 
    return 0;
}

// runs a DNS query on the domain_name using first IP in next_servers[]
void dnsquery(unsigned char *domain_name)
{
    int query_type = T_A; // 1

    unsigned char buffer[70000];
    unsigned char *query_name;
    unsigned char *query_index;

    int i;
    int j;
    int last_position;
    int sockfd;
 
    struct sockaddr_in src_address;
    struct sockaddr_in dest_address;
 
    // the replies from the DNS server
    struct RES_RECORD answ_records[20];
    struct RES_RECORD auth_records[20];
    struct RES_RECORD addi_records[20]; 
 
    struct HEADER *dns = NULL;
    struct QUESTION *query_info = NULL;
 
    // printf("Resolving %s" , domain_name);

    // CREATE UDP SOCKET
    sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); 
 
    dest_address.sin_family = AF_INET;
    dest_address.sin_port = htons(53);
    dest_address.sin_addr.s_addr = inet_addr(next_servers[0]); // next server to query
 
    // prepare buffer for HEADER use
    dns = (struct HEADER *)&buffer;
    
    // set format for DNS message
    setHeader(dns);
 
    // point to the query_name section
    query_name = (unsigned char*)&buffer[sizeof(struct HEADER)];
    
    // call helper to change domain_name to DNS format
    getDnsFormat(query_name , domain_name);

    // allocate query_info for the QUESTION section of message
    query_info = (struct QUESTION*)&buffer[sizeof(struct HEADER) + (strlen((const char*)query_name) + 1)];
    query_info->qtype = htons(query_type); 
    query_info->qclass = htons(1);
 
    // SEND PACKET
    sendPacket(sockfd, (char*)buffer, query_name, dest_address);
     
    // RECEIVE PACKET    
    receivePacket(sockfd, (char*)buffer, dest_address);

    // print details from response
    print_details(dns);

    // point back to beginning
    dns = (struct HEADER*) buffer;
 
    // move ahead of the dns header and the query field
    query_index = &buffer[sizeof(struct HEADER) + (strlen((const char*)query_name)+1) + sizeof(struct QUESTION)];
 
    // READ ANSWER SECTION
    last_position = 0;

    // if the query has an answer
    if (ntohs(dns->ans_count) >= 1)
    {
        answer_found = 1; // set flag
    }
 
    for(i = 0; i < ntohs(dns->ans_count); i++)
    {
        answ_records[i].name = getName(query_index, buffer, &last_position);
        query_index = query_index + last_position;
 
        answ_records[i].resource = (struct R_DATA*)(query_index);
        query_index = query_index + sizeof(struct R_DATA);
 
        if(ntohs(answ_records[i].resource->type) == 1) //if its an ipv4 address
        {
            answ_records[i].rdata = (unsigned char*)malloc(ntohs(answ_records[i].resource->data_len));
 
            for(j = 0; j<ntohs(answ_records[i].resource->data_len); j++)
            {
                answ_records[i].rdata[j] = query_index[j];
            }
 
            answ_records[i].rdata[ntohs(answ_records[i].resource->data_len)] = '\0';
 
            query_index = query_index + ntohs(answ_records[i].resource->data_len);
        }
        else
        {
            answ_records[i].rdata = getName(query_index, buffer, &last_position);
            query_index = query_index + last_position;
        }
    }
 
    // READ AUTHORITATIVE SECTION
    for(i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth_records[i].name = getName(query_index, buffer, &last_position);
        query_index += last_position;
 
        auth_records[i].resource=(struct R_DATA*)(query_index);
        query_index += sizeof(struct R_DATA);
 
        auth_records[i].rdata=getName(query_index, buffer, &last_position);
        query_index += last_position;
    }
 
    // READ ADDITIONAL SECTION
    for(i = 0; i < ntohs(dns->add_count); i++)
    {
        addi_records[i].name = getName(query_index, buffer, &last_position);
        query_index += last_position;
 
        addi_records[i].resource = (struct R_DATA*)(query_index);
        query_index += sizeof(struct R_DATA);
 
        if(ntohs(addi_records[i].resource->type) == 1)
        {
            addi_records[i].rdata = (unsigned char*)malloc(ntohs(addi_records[i].resource->data_len));
            
            for(j = 0; j < ntohs(addi_records[i].resource->data_len); j++)
            {
                addi_records[i].rdata[j] = query_index[j];
            }
 
            addi_records[i].rdata[ntohs(addi_records[i].resource->data_len)] = '\0';
            query_index += ntohs(addi_records[i].resource->data_len);
        }
        else
        {
            addi_records[i].rdata = getName(query_index, buffer, &last_position);
            query_index += last_position;
        }
    }
 
    // print answ_records
    printf("\nAnswers Section:\n");

    for(i = 0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("Name : %s   ",answ_records[i].name);
 
        if( ntohs(answ_records[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answ_records[i].rdata;
            src_address.sin_addr.s_addr = (*p); //working without ntohl
            printf("IP : %s",inet_ntoa(src_address.sin_addr));
        }
 
        printf("\n");
    }
 
    // print authorities
    printf("\nAuthoritive Section:\n");

    for(i = 0; i < ntohs(dns->auth_count); i++)
    {
        printf("Name : %s   ",auth_records[i].name);
        if(ntohs(auth_records[i].resource->type) == T_NS)
        {
            printf("Name Server : %s",auth_records[i].rdata);
        }
        printf("\n");
    }
 
    // print additional resource records
    printf("\nAdditional Information Section:\n");

    for(i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Name : %s   ",addi_records[i].name);
        if(ntohs(addi_records[i].resource->type) == T_A)
        {
            long *p;
            p=(long*)addi_records[i].rdata;
            src_address.sin_addr.s_addr=(*p);
            printf("IP : %s",inet_ntoa(src_address.sin_addr));

            // STORE
            strcpy(next_servers[i], inet_ntoa(src_address.sin_addr));
            
        }
        printf("\n");
    }

    printf("--------------------------------------------------\n");
    return;
}

// converts domain_name to DNS format
// ex: cs.fiu.edu => 2cs.3fiu.3edu
void getDnsFormat(unsigned char* dns,unsigned char* domain_name) 
{
    int lock = 0 , i;
    strcat((char*)domain_name,".");
     
    for(i = 0 ; i < strlen((char*)domain_name) ; i++) 
    {
        if(domain_name[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++= domain_name[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++ = '\0';
}

// read domain name from query_index into buffer
unsigned char* getName(unsigned char* query_index, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p = 0;
    unsigned int jumped = 0;
    unsigned int offset;

    int i , j;

    // mask for leading bits
    int bitMask = 49152; // 49152 = 1100 0000 0000 0000

    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    // read the names in DNS format; 3www6google3com
    while(*query_index!=0)
    {
        if(*query_index>=192)
        {
            offset = (*query_index)*256 + *(query_index+1) - bitMask; 
            query_index = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*query_index;
        }
 
        query_index = query_index+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
    // add null character to create string
    name[p]='\0';

    if(jumped == 1)
    {
        // number of steps we actually moved forward in the packet
        *count = *count + 1; 
    }
 
    // convert to human format: 3www6google3com0 to www.google.com
    for(i = 0; i<(int)strlen((const char*)name); i++) 
    {
        p=name[i];
        for(j = 0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    // remove last dot
    name[i-1]='\0';
    return name;
}

// function to read query; NOT USED
void readQueryAnswer(int position, struct HEADER *dns, unsigned char* buffer, unsigned char *query_index, struct RES_RECORD answ_records[])
{
    int i, j;

    // if the query has an answer
    if (ntohs(dns->ans_count) >= 1)
    {
        answer_found = 1; // set flag
    }
 
    for(i = 0; i < ntohs(dns->ans_count); i++)
    {
        answ_records[i].name = getName(query_index,buffer,&position);
        query_index = query_index + position;
 
        answ_records[i].resource = (struct R_DATA*)(query_index);
        query_index = query_index + sizeof(struct R_DATA);
 
        if(ntohs(answ_records[i].resource->type) == 1) //if its an ipv4 address
        {
            answ_records[i].rdata = (unsigned char*)malloc(ntohs(answ_records[i].resource->data_len));
 
            for(j = 0 ; j<ntohs(answ_records[i].resource->data_len) ; j++)
            {
                answ_records[i].rdata[j] = query_index[j];
            }
 
            answ_records[i].rdata[ntohs(answ_records[i].resource->data_len)] = '\0';
 
            query_index = query_index + ntohs(answ_records[i].resource->data_len);
        }
        else
        {
            answ_records[i].rdata = getName(query_index,buffer,&position);
            query_index = query_index + position;
        }
    }
}

void sendPacket(int sockfd, char* buffer, unsigned char *query_name, struct sockaddr_in dest_address)
{
    if( sendto(sockfd, buffer, sizeof(struct HEADER) + (strlen((const char*)query_name)+1) + sizeof(struct QUESTION), 0, (struct sockaddr*)&dest_address, sizeof(dest_address)) < 0)
    {
        perror("sendto failed");
    }
}

void receivePacket(int sockfd, char* buffer, struct sockaddr_in dest_address)
{
    int i = sizeof(dest_address);
    // printf("\nReceiving answer...");
    if(recvfrom (sockfd, buffer , 70000 , 0 , (struct sockaddr*)&dest_address , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
}

//  helper to print HEADER details
void print_details(struct HEADER *dns)
{
    printf("\nReply received. Content overview: ");
    // printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Intermidiate Name Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional Information Records.\n", ntohs(dns->add_count));
}

// set DNS message format
void setHeader(struct HEADER *dns)
{
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;        // 0=query, 1=response
    dns->opcode = 0;    // 0 = standard, 1 = inverse, 2 = server status request
    dns->aa = 0;        // authoritative answer
    dns->tc = 0;        // truncated
    dns->rd = 0;        // recurision desired
    dns->ra = 0;        // recursion available
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
}