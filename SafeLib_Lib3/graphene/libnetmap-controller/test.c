#include <stdio.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int createServer_untrusted(void* lib_netmap_desc_ptr, char* ifname) {
    printf("RIDER REPORT: createServer_untrusted function\n"); fflush(stdout);
    struct nm_desc* lib_netmap_desc = (struct nm_desc*) lib_netmap_desc_ptr;
    
    struct nmreq base_req;
    memset(&base_req, 0, sizeof(base_req));
    base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
    lib_netmap_desc = nm_open(ifname, &base_req, 0, 0);

    return 0;
}

int main() {
    return createServer_untrusted(NULL, NULL);
}