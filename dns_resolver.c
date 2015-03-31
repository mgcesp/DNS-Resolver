#include "dns_resolver.h"

int main(int argc, char *argv[])
{
    unsigned char domain_name[100];

    // get root DNS server from argv
    strcpy(dns_servers[0] , argv[1]);

    // get the domain_name from argv; memcpy is best way for unsigned char
    memcpy(&domain_name, argv[2], strlen(argv[2]) + 1);

    printf("\n______________________________________________________________\n");
    printf("DOMAIN NAME : %s\n", domain_name);
    printf("DNS ROOT SERVER IP : %s\n", dns_servers[0]);
    printf("--------------------------------------------------\n");

    // while no answer record is fetched keep searching
    while(!answer_found)
    {
        // print DNS server that is being queried
        printf("DNS server to query: %s\n", dns_servers[0]);
        // run a DNS query on domain name
        dnsQuery(domain_name);
    }
 
    return 0;
}

// runs a DNS query on the domain_name using first IP in dns_servers[]
void dnsQuery(unsigned char *domain_name)
{
    unsigned char buffer[10000];
    unsigned char *query_name;
    unsigned char *query_index;

    int i;
    int j;
    int last_position;
    int sockfd;
 
    struct sockaddr_in src_address;
    struct sockaddr_in dest_address;
 
    // to store records received from server
    struct RES_RECORD answ_records[20];
    struct RES_RECORD auth_records[20];
    struct RES_RECORD addi_records[20]; 
 
    struct HEADER *dns = NULL;
    struct QUESTION *query_info = NULL;

    /*** CREATE UDP SOCKET  **************************************************/
    sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); 
 
    dest_address.sin_family = AF_INET;
    dest_address.sin_port = htons(53);
    dest_address.sin_addr.s_addr = inet_addr(dns_servers[0]); // next server to query
 
    // prepare buffer for HEADER use
    dns = (struct HEADER *)&buffer;
    
    // set flags for DNS message
    setHeader(dns);
 
    // point to the query_name section
    query_name = (unsigned char*)&buffer[sizeof(struct HEADER)];
    
    // call helper to change domain_name to DNS format
    getDnsFormat(query_name , domain_name);

    // allocate query_info for the QUESTION section of message
    query_info = (struct QUESTION*)&buffer[sizeof(struct HEADER) + (strlen((const char*)query_name) + 1)];
    query_info->qtype = htons(TYPE_A); 
    query_info->qclass = htons(1);
 
    // SEND PACKET
    sendPacket(sockfd, (char*)buffer, query_name, dest_address);
     
    // RECEIVE PACKET    
    receivePacket(sockfd, (char*)buffer, dest_address);

    // print details from response
    printDetails(dns);

    // point back to beginning
    dns = (struct HEADER*) buffer;
 
    // move ahead of the dns header and the query field
    query_index = &buffer[sizeof(struct HEADER) + (strlen((const char*)query_name)+1) + sizeof(struct QUESTION)];
 
    /*** READ ANSWER SECTION  **************************************************/
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
 
        if(ntohs(answ_records[i].resource->type) == TYPE_A) 
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
    
    /*** READ AUTHORITATIVE SECTION  **************************************************/
    for(i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth_records[i].name = getName(query_index, buffer, &last_position);
        query_index += last_position;
 
        auth_records[i].resource=(struct R_DATA*)(query_index);
        query_index += sizeof(struct R_DATA);
 
        auth_records[i].rdata=getName(query_index, buffer, &last_position);
        query_index += last_position;
    }
 
    /*** READ ADDITIONAL SECTION  **************************************************/
    for(i = 0; i < ntohs(dns->add_count); i++)
    {
        addi_records[i].name = getName(query_index, buffer, &last_position);
        query_index += last_position;
 
        addi_records[i].resource = (struct R_DATA*)(query_index);
        query_index += sizeof(struct R_DATA);
 
        if(ntohs(addi_records[i].resource->type) == TYPE_A)
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

    printAnswers(dns, answ_records, src_address);
  
    printAuth(dns, auth_records);

    printAddi(dns, addi_records, src_address);

    saveInterServers(dns, addi_records, src_address);

    printf("--------------------------------------------------\n");
    return;
}

// extracts and saves the IPs of the itermediate servers
void saveInterServers(struct HEADER *dns, struct RES_RECORD addi_records[], struct sockaddr_in src_address)
{
    int i;

    for(i = 0; i < ntohs(dns->add_count); i++)
    {
        if(ntohs(addi_records[i].resource->type) == TYPE_A)
        {
            long *p;
            p=(long*)addi_records[i].rdata;
            src_address.sin_addr.s_addr=(*p);

            // save into dns_servers[]
            strcpy(dns_servers[i], inet_ntoa(src_address.sin_addr));
        }
    }
}

// prints additional records
void printAddi(struct HEADER *dns, struct RES_RECORD addi_records[], struct sockaddr_in src_address)
{
    printf("\nAdditional Information Section:\n");

    int i;

    for(i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Name : %s   ",addi_records[i].name);
        if(ntohs(addi_records[i].resource->type) == TYPE_A)
        {
            long *p;
            p=(long*)addi_records[i].rdata;
            src_address.sin_addr.s_addr=(*p);
            printf("IP : %s",inet_ntoa(src_address.sin_addr));            
        }
        printf("\n");
    }
}

// prints authoritive records
void printAuth(struct HEADER *dns, struct RES_RECORD auth_records[])
{
    printf("\nAuthoritive Section:\n");

    int i;

    for(i = 0; i < ntohs(dns->auth_count); i++)
    {
        printf("Name : %s   ",auth_records[i].name);
        if(ntohs(auth_records[i].resource->type) == TYPE_NS)
        {
            printf("Name Server : %s",auth_records[i].rdata);
        }
        printf("\n");
    }
}

// prints answer records
void printAnswers(struct HEADER *dns, struct RES_RECORD answ_records[], struct sockaddr_in src_address)
{
    printf("\nAnswers Section:\n");

    int i;

    for(i = 0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("Name : %s   ",answ_records[i].name);
 
        if( ntohs(answ_records[i].resource->type) == TYPE_A)
        {
            long *p;
            p=(long*)answ_records[i].rdata;
            src_address.sin_addr.s_addr = (*p);
            printf("IP : %s",inet_ntoa(src_address.sin_addr));
        }
 
        printf("\n");
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

    if(recvfrom (sockfd, buffer, 10000, 0, (struct sockaddr*)&dest_address, (socklen_t*) &i) < 0)
    {
        perror("recvfrom failed");
    }
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
            lock=i+1;
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

    // mask for leading two bits
    int bitMask = 49152; // 1100 0000 0000 0000

    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    // read the names in DNS format
    while(*query_index!=0)
    {
        if(*query_index >= 192)
        {
            offset = (*query_index)*256 + *(query_index+1) - bitMask; 
            query_index = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] =* query_index;
        }
 
        query_index = query_index+1;
 
        if(jumped == 0)
        {
            *count = *count + 1; // incrememt count
        }
    }
    // add null character to create string
    name[p]='\0';

    if(jumped == 1)
    {
        // move one bit forward
        *count = *count + 1; 
    }
 
    // convert to human format
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

//  helper to print HEADER details
void printDetails(struct HEADER *dns)
{
    printf("\nReply received. Content overview: ");
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Intermidiate Name Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional Information Records.\n", ntohs(dns->add_count));
}