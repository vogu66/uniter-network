#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define IP_LENGTH 20
#define NAME_LENGTH 32
#define ALGO_LENGTH 16
#define KEY_LENGTH 100
#define PATH_LENGTH 512
#define MAX_LINE_LENGTH 2048


/*
Program structure:

DONE: Get list of running network interfaces
DONE: Scan network interfaces for open hosts
DONE: Authentify open hosts
TODO: this makes an unreachable object, memory leak -- solve it
TODO: Remove duplicate hosts (from different interfaces,
                              priority lists of interfaces)
TODO: Ask all hosts to provide a list of all the hosts they have access to,
        and piggy-back their connection to access all
TODO: Sync possible host list, re-check all available hosts to see
        if new ones are actually authentified
TODO: Manage list of files to synchronize from each host, with the host list (correctly, cross-link and invert paths as needed or save things in a coherent way using name → path for each host and assemble them later on)
TODO: create public keys and hijack connections from other connected
        computers to pair the new additions to all hosts on the network
TODO: see connection types ? (direct ethernet connections can be let unsecure
        for faster transfer speeds)
TODO: Sync the file locations and correct mis-matches
TODO: test ssh connection to each host (dummy connection attempt to check public key)
DONE: Basic sync network (basic double pass on star shape
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
TODO: add a way to add options (e.g. use shasum instead of date)
*/


struct string_list {
   struct string_list *previous;
   char *ip;
   struct string_list *next;
};
struct string_list* insert_string(struct string_list *end, char *ip, int length)
// insert a new string at the end of the list or start the list
{
    //create a link
    struct string_list *link = (struct string_list*) malloc(sizeof(struct string_list));

    link->ip= (char *) malloc(length);
    strcpy(link->ip,ip);
    link->previous=end;
    link->next = NULL;

    if (end!=NULL)
    {
        end->next=link;
    }
    return link;
}
struct string_list* insert_ip(struct string_list *end, char *ip)
{
    return (struct string_list *) insert_string(end, ip, IP_LENGTH);
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



struct host_list {
   struct host_list *previous;
   char *name;
   char *algo;
   char *key;
   char *username;
   char *ip;
   struct string_list *origin;
   struct string_list *destination;
   struct host_list *next;
};
struct host_list* insert_host(struct host_list *end,
                                char *name,
                                char *algo,
                                char *key,
                                char *username,
                                struct string_list *origin,
                                struct string_list *destination)
// insert a new string at the end of the list or start the list
{
    //create a link
    struct host_list *link = (struct host_list*) malloc(sizeof(struct host_list));

    link->name= (char *) malloc(NAME_LENGTH);
    strcpy(link->name,name);
    link->algo= (char *) malloc(ALGO_LENGTH);
    strcpy(link->algo,algo);
    link->key= (char *) malloc(KEY_LENGTH);
    strcpy(link->key,key);
    link->username= (char *) malloc(NAME_LENGTH);
    strcpy(link->username,username);
    link->origin=origin;
    link->destination=destination;
    link->previous=end;
    link->next = NULL;
    link->ip=NULL;

    if (end!=NULL)
    {
        end->next=link;
    }
    return link;
}
void print_hosts(struct host_list *s)
{
    if (s!=NULL)
    {
        // printf("%s\n",s->ip);
        if (s->previous!=NULL)
        {
            print_hosts(s->previous);
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
    struct host_list *hostList=NULL;

    // temp variables
    int temp;
    char command[MAX_LINE_LENGTH];
    FILE *pipe_fp;
    char line[MAX_LINE_LENGTH]="\0";
    char *ptr;
    char ip[IP_LENGTH];
    char path[PATH_LENGTH];
    char word1[PATH_LENGTH];
    char word2[PATH_LENGTH];
    char word3[PATH_LENGTH];
    char word4[PATH_LENGTH];
    struct string_list *temp_list;
    struct string_list *temp_list2;
    struct host_list *temp_host_list;

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
                for(temp=sa_mask->sin_addr.s_addr;temp%2;temp>>=1)
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
                                    addresses=insert_ip(addresses,ip);
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

// DONE: Authentify open hosts
    // first read host file
    sprintf(path, "%s/.bin/backup_hosts/hostlist",getenv("HOME"));
    if ((pipe_fp = fopen(path, "r")) == NULL)
    {
            perror("failed to open host list file");
            exit(1);
    }

    for(char *check= fgets( line, MAX_LINE_LENGTH, pipe_fp ); check!=NULL; check= fgets( line, MAX_LINE_LENGTH, pipe_fp ))
    {
        temp=sscanf( line, "%s %s %s %s", word1,  word2,  word3,  word4);
        if (temp>=2)
        {
            if (temp==3)
                strcpy(word4,word3);
            if (word1[0]!='*')
            {
                // new host
                // word1 = algo
                // word2 = key
                // word3 = name
                hostList=insert_host(hostList, word3, word1, word2,word4,NULL,NULL);
            }
            else
            {
                if (hostList==NULL)
                {
                    perror("first line of host list file cannot be a location");
                    return -1;
                }
                // word2 = name
                // word3 = origin
                // word4 = destination
                hostList->origin=insert_string(hostList->origin, word3, PATH_LENGTH);
                hostList->destination=insert_string(hostList->destination, word4, PATH_LENGTH);
            }
        }
    }


    // then scan ip signatures
    // finally compare hosts and ip signatures
    for(temp_list=addresses;temp_list!=NULL;temp_list=temp_list->previous)
    {
        // get signature
        sprintf(command, "ssh-keygen -lf <(ssh-keyscan -p %s %s 2>/dev/null)",PORT,temp_list->ip);
        /* Create one way pipe line with call to popen() */
        if (( pipe_fp = popen(command, "r")) != NULL)
        {
            // parse output
            for(char *check= fgets( line, MAX_LINE_LENGTH, pipe_fp ); check!=NULL; check= fgets( line,  MAX_LINE_LENGTH, pipe_fp ))
            {
                sscanf( line, "%s %s %s (%s)", word1,  word2,  word3,  word4);
                // check the formatting worjed as expected
                // otherwise the error message doesn't have '('
                if (strlen(word4)>0)
                {
                    // remove the last character since it keeps a parenthesis for some reason
                    word4[strlen(word4)-1]='\0';
                    // printf(word4);
                    // find related host and add to it
                    for(temp_host_list=hostList;temp_host_list!=NULL;temp_host_list=temp_host_list->previous)
                    {
                        // word4 is the algorithm
                        // word2 is the key
                        if (!strcmp(temp_host_list->algo,word4) && !strcmp(temp_host_list->key,word2))
                        {
                            // TODO: Remove duplicate hosts (from different interfaces,
                            //                               priority lists of interfaces)
                            temp_host_list->ip=temp_list->ip;
                        }
                    }
                }
            }
        }
    }

    while(1)
    {
        if (hostList->ip == NULL)
        {
            if (hostList->previous!=NULL)
            {
                hostList->previous->next=hostList->next;
            }
            if (hostList->next!=NULL)
            {
                hostList->next->previous=hostList->previous;
                hostList=hostList->next;
            }
            else if (hostList->previous==NULL)
                hostList=NULL;
        }
        if (hostList != NULL && hostList->previous!=NULL)
        {
            hostList=hostList->previous;
        }
        else
        {break;}
// TODO: this makes an unreachable object, memory leak -- solve it
    }

// TODO: Ask all hosts to provide a list of all the hosts they have access to,
//         and piggy-back their connection to access all
// TODO: Sync possible host list, re-check all available hosts to see
//         if new ones are actually authentified
// TODO: Manage list of files to synchronize from each host, with the host list (correctly, cross-link and invert paths as needed or save things in a coherent way using name → path for each host and assemble them later on)
// TODO: create public keys and hijack connections from other connected
//         computers to pair the new additions to all hosts on the network
// TODO: see connection types ? (direct ethernet connections can be let unsecure
//         for faster transfer speeds)
// TODO: Sync the file locations and correct mis-matches
// TODO: test ssh connection to each host (dummy connection attempt to check public key)
// TODO: Get list of data to synchronize from each host
// DONE: Basic sync network (basic double pass on star shape
//                             from base machine)

    if (hostList!=NULL)
    {
        // hostList is stored from first for now -> advance forward
        // probably should make a function to loop over the list in either
        // direction somehow, this is dirty and won't scale
        while(1)
        {
            printf("\nSynching: %s (%s)\n",hostList->name, hostList->ip);
            // system("unison -sshargs='-p 46 -i ~/.ssh/Salem' /tmp/testing ssh://valerium@192.168.0.12//tmp/testing");
            // advance backwards in the list
            while(1)
            {
                sprintf(command,
                    "unison -perms 0 -auto -sshargs='-p %s -i ~/.ssh/%s' %s ssh://%s@%s/%s",
                    PORT,
                    hostList->name,
                    hostList->origin->ip,
                    hostList->username,
                    hostList->ip,
                    hostList->destination->ip);
                printf("\n\n====================\n%s\n====================\n",command);
                system(command);
                if (hostList->origin->previous!=NULL)
                {
                    hostList->origin=hostList->origin->previous;
                    hostList->destination=hostList->destination->previous;
                }
                else
                {
                    break;
                }
            }
            if (hostList->next!=NULL)
            {
                hostList=hostList->next;
            }
            else
            {break;}
        }


        while(hostList->previous != NULL)
        {
            // advance back backwards in the host list to propagate
            // all changes from last hosts to first hosts
            // we can ignore the first host since it was just synched
            hostList=hostList->previous;
            while(1)
            {
                sprintf(command,
                    "unison -perms 0 -auto -sshargs='-p %s -i ~/.ssh/%s' %s ssh://%s@%s/%s",
                    PORT,
                    hostList->name,
                    hostList->origin->ip,
                    hostList->username,
                    hostList->ip,
                    hostList->destination->ip);
                printf("\n\n====================\n%s\n====================\n",command);
                system(command);

                if (hostList->origin->next!=NULL)
                {
                    hostList->origin=hostList->origin->next;
                    hostList->destination=hostList->destination->next;
                }
                else
                {
                    break;
                }
            }
        }
    }
    else
    {
        perror("No authentified host found");
        return 0;
    }
// TODO: Better sync network (at least identify the best machine to use
//                             for each set of data to sync)
// TODO: Optimized sync network
//         (which computer needs to sync what, parrallel sync
//          when possible, launch unison on multiple computers for
//          faster processing, and make sure all of them have the last
//          version of everything by having probably a first pass in star
//          shape then propagating the process through binary division)
// TODO: Cleanup string list and stuff
// TODO: add a way to add options (e.g. use shasum instead of date)

    return 0;
}
