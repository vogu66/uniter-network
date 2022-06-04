#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* readNmap(file)
{
    
}

int main ()
{
    // PORT NUMBER to be used
    const char PORT[] = "46";

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

    char addr[30];
    int mask;
    int mask_maker;
    getifaddrs (&ifap);
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
                mask_maker=sa_mask->sin_addr.s_addr;
                mask=0;
                for(mask_maker=sa_mask->sin_addr.s_addr;mask_maker%2;mask_maker>>=1)
                {
                    mask++;
                }

                char command[50];
                sprintf(command, "nmap -oG - -p %s %s/%d",PORT,addr,mask); // needs subnet mask
                // printf("%s",command);

                FILE *pipe_fp;
                /* Create one way pipe line with call to popen() */
                if (( pipe_fp = popen(command, "r")) == NULL)
                {
                        perror("failed to use nmap");
                        exit(1);
                }
                // parse output
                char ch;
                while((ch = fgetc(pipe_fp)) != EOF )
                    printf("%c", ch);
                /* Close the pipe */
                pclose(pipe_fp);

            }
        }
    }

    freeifaddrs(ifap);
    return 0;
}
