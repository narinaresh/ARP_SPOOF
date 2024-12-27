#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h> 
#include <pcap.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

#define RESET_COLOR   "\033[0m"     //normal color 
#define RED_COLOR     "\033[1;31m"    //red color
#define GREEN_COLOR   "\033[32m"    //green color
#define YELLOW_COLOR  "\033[33m"    //yellow color
#define BLUE_COLOR    "\033[34m"    //blue color
#define MAGENTA_COLOR "\033[35m"    //magenta color
#define CYAN_COLOR "\033[1;36m"   //cyan color


#define ARP_REQUEST 1	//ARP Request
#define ARP_RESPONSE 2	//ARP Response

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;		//Hardware type
  uint16_t ptype;		//Protocol type
  uint8_t hlen;			//Hardware address lenght (MAC)
  uint8_t plen;			//Protocol address length
  uint16_t opcode;		//Operation code (request or response)
  uint8_t sender_mac[6];	//Sender hardware address	
  uint8_t sender_ip[4];		//Sender IP address
  uint8_t target_mac[6];	//Target MAC address
  uint8_t target_ip[4];		//Target IP address
};


void print_name(); //to print the name and author name
void show_help(char *bin);
int interface();
char alerter(char *ip,char *mac);
int sniffer(char *devices);
char* get_mac();
char* get_ip();


int main(int argc,char *argv[]){

    if(argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0){
		print_name();
		show_help(argv[0]);
	} else if(strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0){
		print_name();
		exit(1);
	} else if(strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0){
        interface();
	} else if(strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0){
		if(argc < 3){
			printf("Error: Please provide an interface to sniff on. Select from the following.\n");
			printf("--------------------------------------------------------------------------\n");
            interface();
			printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", argv[0]);
		} else {
			sniffer(argv[2]);
		}
	} else {
		printf("Invalid argument.\n");
		show_help(argv[0]);
	}
	return 0;

}

int sniffer(char *devices){

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* packet_storage;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eth_header; 
    arp_hdr *arp_header = NULL;
    u_char hard_ptr;
    char *t_mac,*t_ip,*s_mac,*s_ip;
    int counter = 0;
    long int diff = 0;
    time_t ct,lt;

    packet_storage = pcap_open_live(devices, BUFSIZ, 0, 1, error);
    if(packet ==  NULL){
        printf("error - can't able to listen the interface try again\n");
        interface();
        return -1;
    }else{
        printf(GREEN_COLOR"Listening at %s...\n"RESET_COLOR,devices);
    }
    while(1){
        packet = pcap_next(packet_storage,&header);
        if (packet == NULL){
            fprintf(stderr,"can't able to open the next packets!\n");
            return -1;
        }else{
            eth_header = (struct ether_header*) packet;
            if(ntohs(eth_header->ether_type)== ETHERTYPE_ARP){
                ct = time(NULL);
				diff = ct - lt;
				// printf(MAGENTA_COLOR"ct:"YELLOW_COLOR" %ld;"MAGENTA_COLOR" Diff:"YELLOW_COLOR" %ld;"MAGENTA_COLOR" Counter:"YELLOW_COLOR" %d\n"RESET_COLOR,ct, diff, counter);
				if(diff > 20){
				    counter = 0;
				}
                arp_header = (arp_hdr*)(packet+14);
                printf(CYAN_COLOR"RECEIVED PACKET LENGTH = "RESET_COLOR"%d\n",header.len);
                printf(CYAN_COLOR"RECEIVED AT :"RESET_COLOR"%s",ctime((const time_t *)&header.ts.tv_sec));
                printf(CYAN_COLOR"LENGTH OF ETHERNET HEADER = "RESET_COLOR"%d\n",ETHER_HDR_LEN);
                printf(CYAN_COLOR"Operation Type:"RESET_COLOR"%s\n",(ntohs(arp_header->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");
                printf(CYAN_COLOR"Sender MAC:"RESET_COLOR" %s\n", get_mac(arp_header->sender_mac));
				printf(CYAN_COLOR"Sender IP: "RESET_COLOR"%s\n", get_ip(arp_header->sender_ip));
				printf(CYAN_COLOR"Target MAC:"RESET_COLOR" %s\n", get_mac(arp_header->target_mac));
				printf(CYAN_COLOR"Target IP: "RESET_COLOR"%s\n",get_ip(arp_header->target_ip));
                printf("\n\n");
                counter++;
                lt = time(NULL);
                if(counter > 10){
				    alerter(get_ip(arp_header->sender_ip),get_mac(arp_header->sender_mac));
				}
            }
        }
    }
    return 0;
}

char* get_mac(uint8_t mac[6]){
    
    char *m=(char*)malloc(20*sizeof(char));
    sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return m;
}

char* get_ip(uint8_t ip[4]){

    char *m =(char*)malloc(20*sizeof(char));
    sprintf(m,"%d.%d.%d.%d",0[ip],ip[1],2[ip],3[ip]);
    return m;
}


char alerter(char *ip,char *mac){
    char command[256];
    sprintf(command,"zenity --warning --text='Possible ARP Spoofing Detected. IP: %s and MAC: %s'", ip, mac);
	system(command);
    printf(RED_COLOR"\nAlert: Possible ARP Spoofing Detected. IP: %s and MAC: %s\n"RESET_COLOR, ip, mac);
}

void show_help(char *bin){

    printf(BLUE_COLOR"\nAvailable arguments: \n"RESET_COLOR);
	printf("----------------------------------------------------------\n");
	printf("-h or --help:\t\t\tPrint this help text.\n");
	printf("-l or --lookup:\t\t\tPrint the available interfaces.\n");
	printf("-i or --interface:\t\tProvide the interface to sniff on.\n");
	printf("-v or --version:\t\tPrint the version information.\n");
	printf("----------------------------------------------------------\n");
	printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", bin);
	exit(1);
}

//TO list out the interfaces
int interface(){
    char error[PCAP_BUF_SIZE];
    pcap_if_t *devs, *temp;
    int i=0;

    if(pcap_findalldevs(&devs,error) == -1){
        fprintf(stderr,"%s\n",error);
        return -1;
    }

    printf(GREEN_COLOR"Listing Available Interface:\n"RESET_COLOR);
    for(temp = devs; temp; temp=temp->next){
        printf("#%d. %s\n",++i,temp->name);
    }
    return 0;
}

// To print the title and the version
void print_name(){
    printf(YELLOW_COLOR"\t    _    ____  ____      ____  ____   ___   ___  _____ \n");
    printf("\t   / \\  |  _ \\|  _ \\    / ___||  _ \\ / _ \\ / _ \\|  ___|\n");
    printf("\t  / _ \\ | |_) | |_) |   \\___ \\| |_) | | | | | | | |_   \n");
    printf("\t / ___ \\|  _ <|  __/      __) |  __/| |_| | |_| |  _|  \n");
    printf("\t/_/   \\_\\_| \\_\\_|       |____/|_|    \\___/ \\___/|_|    \n");
    printf("\t ____  _____ ____ _____ _____ ____ _____ ___  ____     \n");
    printf("\t|  _ \\| ____/ ___|_   _| ____/ ___|_   _/ _ \\|  _ \\    \n");
    printf("\t| | | |  _|| |     | | |  _|| |     | || | | | |_) |   \n");
    printf("\t| |_| | |__| |___  | | | |__| |___  | || |_| |  _ <    \n");
    printf("\t|____/|_____\\____| |_| |_____\\____| |_| \\___/|_| \\_\\   \n");
    printf("\t                                                       \n"RESET_COLOR);
    printf(BLUE_COLOR"\t\t\t\t\t\t\t - version 1.O\n\n"RESET_COLOR);

}