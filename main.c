#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>

int main ()
{
    struct ifaddrs *ifap, *ifa;
    // structure ref:
    // https://www.man7.org/linux/man-pages/man3/getifaddrs.3.html
    // == linked list of internet interfaces
    struct sockaddr_in *sa;
    // sockaddr_in:
    // https://linuxhint.com/sockaddr-in-structure-usage-c/
    // sin_family: This component refers to an address family which in most of
    //             the cases is set to “AF_INET”.
    // sin_addr: It represents a 32-bit IP address.
    // sin_port: It refers to a 16-bit port number on which the server will
    //           listen to the connection requests by the clients.

    char *addr;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
        }
    }

    freeifaddrs(ifap);
    return 0;
}
