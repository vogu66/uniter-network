#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define IP_LENGTH 20


/*
Program structure:

DONE: Get list of running network interfaces
DONE: Scan network interfaces for open hosts
TODO: Authentify open hosts
TODO: Remove duplicate hosts (from different interfaces,
                              priority lists of interfaces)
TODO: Ask all hosts to provide a list of all the hosts they have access to,
        and piggy-back their connection to access all
TODO: Sync possible host list, re-check all available hosts to see
        if new ones are actually authentified
TODO: create public keys and hijack connections from other connected
        computers to pair the new additions to all hosts on the network
TODO: see connection types ? (direct ethernet connections can be let unsecure
        for faster transfer speeds)
TODO: Sync the file locations and correct mis-matches
DONE: test ssh connection to each host (through ssh-keyscan)
TODO: Get list of data to synchronize from each host
TODO: Basic sync network (basic double pass on star shape
                            from base machine)
TODO: Better sync network (at least identify the best machine to use
                            for each set of data to sync)
TODO: Optimized sync network
        (which computer needs to sync what, parrallel sync
         when possible, launch unison on multiple computers for
         faster processing, and make sure all of them have the last
         version of everything by having probably a first pass in star
         shape then propagating the process through binary division)
TODO: Cleanup string list and stuff
*/


struct string_list {
   struct string_list *previous;
   char *ip;
   struct string_list *next;
};
struct string_list* insert(struct string_list *end, char *ip)
// insert a new string at the end of the list or start the list
{
    //create a link
    struct string_list *link = (struct string_list*) malloc(sizeof(struct string_list));

    link->ip= (char *) malloc(IP_LENGTH);
    strcpy(link->ip,ip);
    link->previous=end;
    link->next = NULL;

    if (end!=NULL)
    {
        end->next=link;
    }
    return link;
}
void print_backwards(struct string_list *s)
{
    if (s!=NULL)
    {
        printf("%s\n",s->ip);
        if (s->previous!=NULL)
        {
            print_backwards(s->previous);
        }
    }
}





int main ()
{
    // PORT NUMBER to be used
    const char PORT[] = "46";
    const char *SPACE=" ";
    const char *SLASH="/";

    struct ifaddrs *ifap, *ifa;
    // structure ref:
    // https://www.man7.org/linux/man-pages/man3/getifaddrs.3.html
    // == linked list of internet interfaces
    struct sockaddr_in *sa;
    struct sockaddr_in *sa_mask;
    // sockaddr_in:
    // https://linuxhint.com/sockaddr-in-structure-usage-c/
    // sin_family: This component refers to an address family which in most of
    //             the cases is set to “AF_INET”.
    // sin_addr: It represents a 32-bit IP address.
    // sin_port: It refers to a 16-bit port number on which the server will
    //           listen to the connection requests by the clients.

    // used variables
    char addr[30]; // current ip address
    int mask; // subnet mask (for nmap)
    struct string_list *addresses=NULL; //list of addresses found by nmap

    // temp variables
    int mask_maker;
    char command[50];
    FILE *pipe_fp;
    char line[152]="\0";
    char *ptr;
    char ip[IP_LENGTH];

// DONE: Get list of running network interfaces
    getifaddrs (&ifap);
// DONE: Scan network interfaces for open hosts
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET)
        {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            // sa = (struct sockaddr_in *) ifa->ifa_netmask;
            if ( sa->sin_addr.s_addr != (int) 0x100007f) // ignore loopback interface
            {
                /*
                Will loop here over all relevant IP addresses of this computer
                Relevant address in addr (as a string):
                */
                // printf("%x\n",sa->sin_addr.s_addr)
                strcpy(addr, inet_ntoa(sa->sin_addr));

                // get net mask
                // https://www.freecodecamp.org/news/subnet-cheat-sheet-24-subnet-mask-30-26-27-29-and-other-ip-address-cidr-network-references/
                sa_mask = (struct sockaddr_in *) ifa->ifa_netmask;
                mask=0;
                for(mask_maker=sa_mask->sin_addr.s_addr;mask_maker%2;mask_maker>>=1)
                {
                    mask++;
                }

                /* Gimmick */
                printf("Scanning interface: %s\n",ifa->ifa_name);
                printf("IP address: %s\n\n",addr);

                /*
                find relevant ip addresses on local network with nmap and
                keep the ones with not closed PORT
                */
                sprintf(command, "nmap -oG - -p %s %s/%d",PORT,addr,mask); // needs subnet mask
                // printf("%s",command);

                /* Create one way pipe line with call to popen() */
                if (( pipe_fp = popen(command, "r")) == NULL)
                {
                        perror("failed to use nmap");
                        exit(1);
                }
                // parse output
                for(char *check= fgets( line, 150, pipe_fp ); check!=NULL; check= fgets( line, 150, pipe_fp ))
                {
                    // line and check are the same string
                    if (line[0]=='H')
                    {
                        printf(line);
                        // split line in words
                        strtok(line, SPACE); // useless word in output
                        strcpy(ip, strtok(NULL, SPACE));
                        // printf("%s\n",ip);
                        strtok(NULL, SPACE); //useless word in output
                        ptr=strtok(NULL, SPACE); // last part of the string says if interface is up
                        // printf("%s",ptr);
                        strtok(ptr, SLASH);
                        ptr=strtok(NULL, SLASH);
                        // printf("slash: %s\n",ptr);
                        if (ptr!=NULL)
                        {
                            if (strcmp("closed",ptr))
                            {
                                /* This means ip holds an open ip address */
                                /* add it to the list */
                                if (strcmp(ip,addr))
                                {
                                    addresses=insert(addresses,ip);
                                }
                            }
                        }
                    }
                }
                /* Close the pipe */
                pclose(pipe_fp);
            }
        }
    }

    freeifaddrs(ifap);

    /*
    addresses now contains the ip addresses to check
    for authenticity and synchronize
    (the last link is stored)
    (all interfaces except loopback are included)
    */
    if (addresses!=NULL)
    {
        printf("\n\nDiscovered open pairs:\n");
        print_backwards(addresses);
    }
    else
    {
        perror("No discovered open port on the network");
        return 0;
    }


// TODO: Authentify open hosts



// TODO: Remove duplicate hosts (from different interfaces,
//                               priority lists of interfaces)
// TODO: Ask all hosts to provide a list of all the hosts they have access to,
//         and piggy-back their connection to access all
// TODO: Sync possible host list, re-check all available hosts to see
//         if new ones are actually authentified
// TODO: create public keys and hijack connections from other connected
//         computers to pair the new additions to all hosts on the network
// TODO: see connection types ? (direct ethernet connections can be let unsecure
//         for faster transfer speeds)
// TODO: test ssh connection to each host
// TODO: Get list of data to synchronize from each host
// TODO: Basic sync network (basic double pass on star shape
//                             from base machine)
// TODO: Better sync network (at least identify the best machine to use
//                             for each set of data to sync)
// TODO: Optimized sync network
//         (which computer needs to sync what, parrallel sync
//          when possible, launch unison on multiple computers for
//          faster processing, and make sure all of them have the last
//          version of everything by having probably a first pass in star
//          shape then propagating the process through binary division)
// TODO: Cleanup string list and stuff

    return 0;
}
