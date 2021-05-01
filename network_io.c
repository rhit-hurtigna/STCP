/* network_io.c:  routines shared amongst all network layer instantiations */

#include <assert.h>
#include <netinet/in.h>
#include "mysock_impl.h"
#include "network_io.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* return local IP address associated with the given mysocket.
 *
 * this requires that the peer address be known; on the active side,
 * this implies that this function must not be called until myconnect()
 * has been called, while on the passive side, it must not be called
 * until the first packet arrives from the peer.  (this is not too
 * onerous a restriction, as this interface is used only in the TCP
 * checksum calculation, which satisfies the aforementioned
 * requirements).
 */

uint32_t _network_get_local_addr(network_context_t *ctx)
{


    struct ifaddrs *ifaddr, *ifa;
    uint32_t addr = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {  
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_RUNNING && !(ifa->ifa_flags & IFF_LOOPBACK)) {
        	if(addr != 0) {
        		printf("\nHEY! This code is only configured to work while only 1 non-loopback interface is connected (I think you might be plugged into Ethernet or something). I'm going to try my best to return something that's correct, but no guarantees! If you'd like to shut me up or write some better code that what this is, check me out in line 51 of network_io.c.\n");
        	}
        	addr = ((struct sockaddr_in *) ifa->ifa_addr)->sin_addr.s_addr;
        }
    }

    freeifaddrs(ifaddr);
	return addr;


	/*
    assert(ctx);

    assert(ctx->peer_addr_valid);
    assert(ctx->peer_addr_len > 0);
    assert(ctx->peer_addr.sa_family == AF_INET);
    printf("%u is ret\n", _network_get_interface_ip(
        ((struct sockaddr_in *) &ctx->peer_addr)->sin_addr.s_addr));
    return _network_get_interface_ip(
        ((struct sockaddr_in *) &ctx->peer_addr)->sin_addr.s_addr);
    */
}

