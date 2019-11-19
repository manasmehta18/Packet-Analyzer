#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

int count = 0;
float avgsize = 0;
int maxsize = 0;
int minsize = INT_MAX;
unsigned long starttime, endtime, u_starttime, u_endtime;
char tmbuf[64];
time_t nowtime;
struct tm *nowtm;

typedef struct sender_ether{
  char addr[256];
  int num_packets;
  struct sender_ether *next;
} sender_ether;

typedef struct receiver_ether{
  char addr[256];
  int num_packets;
  struct receiver_ether *next;
} receiver_ether;

typedef struct sender_ip{
  char addr[256];
  int num_packets;
  struct sender_ip *next;
} sender_ip;

typedef struct receiver_ip{
  char addr[256];
  int num_packets;
  struct receiver_ip *next;
} receiver_ip;

typedef struct sender_arp{
  char mac[256];
  char ip[256];
  struct sender_arp *next;
} sender_arp;

typedef struct receiver_arp{
  char mac[256];
  char ip[256];
  struct receiver_arp *next;
} receiver_arp;

typedef struct sender_udp{
  char addr[256];
  struct sender_udp *next;
} sender_udp;

typedef struct receiver_udp{
  char addr[256];
  struct receiver_udp *next;
} receiver_udp;

struct sender_ether *head_se = NULL;
struct receiver_ether *head_re = NULL;
struct sender_ip *head_si = NULL;
struct receiver_ip *head_ri = NULL;

struct sender_arp *head_sa = NULL;
struct receiver_arp *head_ra = NULL;

struct sender_udp *head_su = NULL;
struct receiver_udp *head_ru = NULL;

void my_callback(u_char* u, const struct pcap_pkthdr* header, const u_char* packet){
     
      struct ether_header *eh;
      struct ip *myip;
      struct udphdr *myudp;
      struct ether_arp *myarp;
      int pres_se = 0, pres_re = 0, pres_si = 0, pres_ri = 0, pres_sa = 0, pres_ra = 0, pres_su = 0, pres_ru = 0;

      char ether_src[256], ether_dst[256], ip_src[256], ip_dst[256], mac_src[6][256], mac_dst[6][256], p_src[4][256], 
      p_dst[4][256], mac_src1[256], mac_dst1[256], p_src1[256], p_dst1[256], udp_src[256], udp_dst[256];

      eh = (struct ether_header*)packet;

    if(eh->ether_type == 8) {

      myip = (struct ip*) (packet + sizeof(struct ether_header));
      myudp = (struct udphdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip));

      strcpy(ether_src, ether_ntoa((struct ether_addr *) eh->ether_shost));
      strcpy(ether_dst, ether_ntoa((struct ether_addr *) eh->ether_dhost));
      strcpy(ip_src, inet_ntoa(myip->ip_src));
      strcpy(ip_dst, inet_ntoa(myip->ip_dst));

      sprintf(udp_src, "%d", myudp->uh_sport);
      sprintf(udp_dst, "%d", myudp->uh_dport);

      struct sender_ether *curr_se = head_se;
      struct sender_ether *prev_se = head_se;
      struct receiver_ether *curr_re = head_re;
      struct receiver_ether *prev_re = head_re;
      struct sender_ip *curr_si = head_si;
      struct sender_ip *prev_si = head_si;
      struct receiver_ip *curr_ri = head_ri;
      struct receiver_ip *prev_ri = head_ri;

      struct sender_udp *curr_su = head_su;
      struct sender_udp *prev_su = head_su;
      struct receiver_udp *curr_ru = head_ru;
      struct receiver_udp *prev_ru = head_ru;

      while(curr_se != NULL) {
        if(strcmp((char *)ether_src, curr_se->addr) == 0) {
          curr_se->num_packets += 1;
          pres_se = 1;
          break;
        }

        prev_se = curr_se;
        curr_se = curr_se->next;
      }


      if(pres_se == 0) {
        struct sender_ether *new_se = (struct sender_ether*) malloc (sizeof(struct sender_ether));
        strcpy(new_se->addr,ether_src);
        new_se->num_packets = 1;
        new_se->next = NULL;

        if(head_se == NULL)
          head_se = new_se;

        else
          prev_se->next = new_se;
      }

      while(curr_re != NULL) {
        if(strcmp(curr_re->addr,ether_dst) == 0) {
          curr_re->num_packets += 1;
          pres_re = 1;
          break;
        }

        prev_re = curr_re;
        curr_re = curr_re->next;
      }

      if(pres_re == 0) {
        struct receiver_ether *new_re = (struct receiver_ether*) malloc (sizeof(struct receiver_ether));
        strcpy(new_re->addr, ether_dst);
        new_re->num_packets = 1;
        new_re->next= NULL;

        if(head_re == NULL)
          head_re = new_re;
        else
          prev_re->next = new_re;
      }

      while(curr_si != NULL) {
        if(strcmp(curr_si->addr,ip_src) == 0) {
          curr_si->num_packets += 1;
          pres_si = 1;
          break;
        }

        prev_si = curr_si;
        curr_si = curr_si->next;
      }

      if(pres_si == 0) {
        struct sender_ip *new_si = (struct sender_ip*) malloc (sizeof(struct sender_ip));
        strcpy(new_si->addr, ip_src);
        new_si->num_packets = 1;
        new_si->next= NULL;

        if(head_si == NULL) 
          head_si = new_si;
        else
          prev_si->next = new_si;
      }

      while(curr_ri != NULL) {
        if(strcmp(curr_ri->addr,ip_dst) == 0) {
          curr_ri->num_packets += 1;
          pres_ri = 1;
          break;
        }

        prev_ri = curr_ri;
        curr_ri = curr_ri->next;
      }

      if(pres_ri == 0) {
        struct receiver_ip *new_ri = (struct receiver_ip*) malloc (sizeof(struct receiver_ip));
        strcpy(new_ri->addr, ip_dst);
        new_ri->num_packets = 1;
        new_ri->next= NULL;

        if(head_ri == NULL) 
          head_ri = new_ri;
        else
          prev_ri->next = new_ri;
      }


      while(curr_su != NULL) {
        if(strcmp(curr_su->addr,udp_src) == 0) {
          pres_su = 1;
          break;
        }

        prev_su = curr_su;
        curr_su = curr_su->next;
      }

      if(pres_su == 0) {
        struct sender_udp *new_su = (struct sender_udp*) malloc (sizeof(struct sender_udp));
        strcpy(new_su->addr, udp_src);
        new_su->next= NULL;

        if(head_su == NULL) 
          head_su = new_su;
        else
          prev_su->next = new_su;
      }


      while(curr_ru != NULL) {
        if(strcmp(curr_ru->addr,udp_dst) == 0) {
          pres_ru = 1;
          break;
        }

        prev_ru = curr_ru;
        curr_ru = curr_ru->next;
      }

      if(pres_ru == 0) {
        struct receiver_udp *new_ru = (struct receiver_udp*) malloc (sizeof(struct receiver_udp));
        strcpy(new_ru->addr, udp_dst);
        new_ru->next= NULL;

        if(head_ru == NULL) 
          head_ru = new_ru;
        else
          prev_ru->next = new_ru;
      }




      
      printf("\n%s\n", "IP Packet");
      printf("Ether src: %s\n",  ether_src);
      printf("Ether dst: %s\n", ether_dst);

      printf("IP src: %s\n", ip_src);
      printf("IP dst: %s\n", ip_dst);

      printf("UDP src Port: %s\n", udp_src);
      printf("UDP dst Port: %s\n", udp_dst);

    }

    else if(eh->ether_type == 1544) {

      myarp = (struct ether_arp*) (packet + sizeof(struct ether_header));

      sprintf(mac_src[0], "%02x", myarp->arp_sha[0]);
      sprintf(mac_src[1], "%02x", myarp->arp_sha[1]);
      sprintf(mac_src[2], "%02x", myarp->arp_sha[2]);
      sprintf(mac_src[3], "%02x", myarp->arp_sha[3]);
      sprintf(mac_src[4], "%02x", myarp->arp_sha[4]);
      sprintf(mac_src[5], "%02x", myarp->arp_sha[5]);

      strcpy(mac_src1, mac_src[0]);
      strcat(mac_src1, ":");
      strcat(mac_src1, mac_src[1]);
      strcat(mac_src1, ":");
      strcat(mac_src1, mac_src[2]);
      strcat(mac_src1, ":");
      strcat(mac_src1, mac_src[3]);
      strcat(mac_src1, ":");
      strcat(mac_src1, mac_src[4]);
      strcat(mac_src1, ":");
      strcat(mac_src1, mac_src[5]);

      sprintf(p_src[0], "%02x", myarp->arp_spa[0]);
      sprintf(p_src[1], "%02x", myarp->arp_spa[1]);
      sprintf(p_src[2], "%02x", myarp->arp_spa[2]);
      sprintf(p_src[3], "%02x", myarp->arp_spa[3]);

      strcpy(p_src1, p_src[0]);
      strcat(p_src1, ":");
      strcat(p_src1, p_src[1]);
      strcat(p_src1, ":");
      strcat(p_src1, p_src[2]);
      strcat(p_src1, ":");
      strcat(p_src1, p_src[3]);

      sprintf(mac_dst[0], "%02x", myarp->arp_tha[0]);
      sprintf(mac_dst[1], "%02x", myarp->arp_tha[1]);
      sprintf(mac_dst[2], "%02x", myarp->arp_tha[2]);
      sprintf(mac_dst[3], "%02x", myarp->arp_tha[3]);
      sprintf(mac_dst[4], "%02x", myarp->arp_tha[4]);
      sprintf(mac_dst[5], "%02x", myarp->arp_tha[5]);

      strcpy(mac_dst1, mac_dst[0]);
      strcat(mac_dst1, ":");
      strcat(mac_dst1, mac_dst[1]);
      strcat(mac_dst1, ":");
      strcat(mac_dst1, mac_dst[2]);
      strcat(mac_dst1, ":");
      strcat(mac_dst1, mac_dst[3]);
      strcat(mac_dst1, ":");
      strcat(mac_dst1, mac_dst[4]);
      strcat(mac_dst1, ":");
      strcat(mac_dst1, mac_dst[5]);

      sprintf(p_dst[0], "%02x", myarp->arp_tpa[0]);
      sprintf(p_dst[1], "%02x", myarp->arp_tpa[1]);
      sprintf(p_dst[2], "%02x", myarp->arp_tpa[2]);
      sprintf(p_dst[3], "%02x", myarp->arp_tpa[3]);

      strcpy(p_dst1, p_dst[0]);
      strcat(p_dst1, ":");
      strcat(p_dst1, p_dst[1]);
      strcat(p_dst1, ":");
      strcat(p_dst1, p_dst[2]);
      strcat(p_dst1, ":");
      strcat(p_dst1, p_dst[2]);

      printf("\n%s\n", "ARP Packet");
      printf("Source MAC Address: %s\n", mac_src1);
      printf("Source Protocol Address: %s\n", p_src1);

      printf("Desitnation MAC Address: %s\n", mac_dst1);
      printf("Destination Protocol Address: %s\n", p_dst1);

      struct sender_arp *curr_sa = head_sa;
      struct sender_arp *prev_sa = head_sa;
      struct receiver_arp *curr_ra = head_ra;
      struct receiver_arp *prev_ra = head_ra;

      while(curr_sa != NULL) {
        if(strcmp(mac_src1, curr_sa->mac) == 0 && strcmp(p_src1, curr_sa->ip) == 0) {
          pres_sa = 1;
          break;
        }

        prev_sa = curr_sa;
        curr_sa = curr_sa->next;
      }

      if(pres_sa == 0) {
        struct sender_arp *new_sa = (struct sender_arp*) malloc (sizeof(struct sender_arp));
        strcpy(new_sa->mac, mac_src1);
        strcpy(new_sa->ip, p_src1);
        new_sa->next = NULL;

        if(head_sa == NULL)
          head_sa = new_sa;

        else
          prev_sa->next = new_sa;
      }


      while(curr_ra != NULL) {
        if(strcmp(mac_dst1, curr_ra->mac) == 0 && strcmp(p_dst1, curr_ra->ip) == 0) {
          pres_ra = 1;
          break;
        }

        prev_ra = curr_ra;
        curr_ra = curr_ra->next;
      }

      if(pres_ra == 0) {
        struct receiver_arp *new_ra = (struct receiver_arp*) malloc (sizeof(struct receiver_arp));
        strcpy(new_ra->mac, mac_dst1);
        strcpy(new_ra->ip, p_dst1);
        new_ra->next = NULL;

        if(head_ra == NULL)
          head_ra = new_ra;

        else
          prev_ra->next = new_ra;
      }

    }

    if(count == 0) {
      starttime = header->ts.tv_sec;
      u_starttime = header->ts.tv_usec;
    }

    count++;
    endtime = header->ts.tv_sec;
    u_endtime = header->ts.tv_usec;
    
    if(maxsize < header->len)
     maxsize = header->len;
    if(minsize > header->len)
     minsize = header->len;

    nowtime = header->ts.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);

    printf("Time and Day of Capture: %s \n", tmbuf);
    printf("Packet size: %d \n", header->len);
    avgsize+= header->len;
}

int main(int argc, char **argv) 
{ 

  if(argc != 2) {
    printf("%s\n", "Enter a pcap filename!");
    exit(1);
  }

  struct pcap_pkthdr header; 
  const u_char *packet;
  char stmbuf[64];
  struct tm *sttm;
  long time_elapsed = 0;


  pcap_t *handle; 
  char errbuf[PCAP_ERRBUF_SIZE];  
  handle = pcap_open_offline(argv[1], errbuf); 

  if (handle == NULL) { 
    printf("error: can't open file");
    return(2); 
  } 

  pcap_loop(handle, -1, my_callback, NULL);

  struct sender_ether *curr_se1 = head_se;
  struct receiver_ether *curr_re1 = head_re;
  struct sender_ip *curr_si1 = head_si;
  struct receiver_ip *curr_ri1 = head_ri;
  struct sender_arp *curr_sa1 = head_sa;
  struct receiver_arp *curr_ra1 = head_ra;
  struct sender_udp *curr_su1 = head_su;
  struct receiver_udp *curr_ru1 = head_ru;

  printf("\n\n%s\n\n", "**************************************** STATISTICS ****************************************");

  printf("\n%s\n", "******************************** IP/TCP/DNS/SSH/.. Packets Statistics ********************************");

  printf("\n%s\n", "List of Unique Ethernet Senders");

  while(curr_se1 != NULL) {
    printf("Sender Address: %s\n", curr_se1->addr);
    printf("Number of Packets: %d\n", curr_se1->num_packets);

    curr_se1 = curr_se1->next;
  }

  printf("\n%s\n", "List of Unique Ethernet Receivers");

  while(curr_re1 != NULL) {
    printf("Receiver Address: %s\n", curr_re1->addr);
    printf("Number of Packets: %d\n", curr_re1->num_packets);

    curr_re1 = curr_re1->next;
  }

  printf("\n%s\n", "List of Unique IP Senders");

  while(curr_si1 != NULL) {
    printf("Sender Address: %s\n", curr_si1->addr);
    printf("Number of Packets: %d\n", curr_si1->num_packets);

    curr_si1 = curr_si1->next;
  }

  printf("\n%s\n", "List of Unique IP Receivers");

  while(curr_ri1 != NULL) {
    printf("Receiver Address: %s\n", curr_ri1->addr);
    printf("Number of Packets: %d\n", curr_ri1->num_packets);

    curr_ri1 = curr_ri1->next;
  }

  printf("\n%s\n", "List of Unique UDP Sender Ports");

  while(curr_su1 != NULL) {
    printf("Sender Port Address: %s\n", curr_su1->addr);

    curr_su1 = curr_su1->next;
  }

  printf("\n%s\n", "List of Unique UDP Receiver Ports");

  while(curr_ru1 != NULL) {
    printf("Receiver Port Address: %s\n", curr_ru1->addr);

    curr_ru1 = curr_ru1->next;
  }

  printf("\n%s\n", "******************************** ARP Packets Statistics ********************************");

  printf("\n%s\n", "List of Unique Senders");

  while(curr_sa1 != NULL) {
    printf("Sender MAC Address: %s\n", curr_sa1->mac);
    printf("Sender IP Address: %s\n", curr_sa1->ip);

    curr_sa1 = curr_sa1->next;
  }

  printf("\n%s\n", "List of Unique Receivers");

  while(curr_ra1 != NULL) {
    printf("Receiver MAC Address: %s\n", curr_ra1->mac);
    printf("Receiver IP Address: %s\n", curr_ra1->ip);

    curr_ra1 = curr_ra1->next;
  }

  printf("\n%s\n", "******************************** Time Statistics ********************************");

  avgsize/=count;
  sttm = localtime((time_t *) &starttime);
  strftime(stmbuf, sizeof stmbuf, "%Y-%m-%d %H:%M:%S", sttm);
  printf("\nStart Time and Day of Capture: %s \n", stmbuf);

  time_elapsed = (endtime*1000000 + u_endtime) - (starttime*1000000 + u_starttime);

  printf("Time of capture: %d seconds %ld microseconds\n", (int) (time_elapsed/1000000), time_elapsed%1000000);

  printf("\n%s\n", "******************************** Packets Statistics ********************************");

  printf("\nTotal number of Packets: %d\n", count);
  printf("Average Packet Size: %f\n", avgsize);
  printf("Maximum Packet Size: %d\n", maxsize);
  printf("Minimum Packet Size: %d\n", minsize);

  pcap_close(handle);
  
  return 0;
}