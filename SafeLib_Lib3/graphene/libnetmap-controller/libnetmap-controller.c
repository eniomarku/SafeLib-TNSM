#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <sys/poll.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


struct pollfd fds;
pthread_t polling_thread;

void* do_polling() {
    while (1) {
        poll(&fds, 1, -1);
    }
    return NULL;
}


int createServer_untrusted(void* lib_netmap_desc_ptr, char* ifname) {
    
    struct nmreq base_req;
    memset(&base_req, 0, sizeof(base_req));
    base_req.nr_flags |= NR_ACCEPT_VNET_HDR;
    struct nm_desc* lib_netmap_desc = nm_open(ifname, &base_req, 0, 0);
    memcpy(lib_netmap_desc_ptr, lib_netmap_desc, sizeof(struct nm_desc));

    struct netmap_ring *receive_ring = NETMAP_RXRING(lib_netmap_desc->nifp, 0);
    struct netmap_ring *send_ring = NETMAP_TXRING(lib_netmap_desc->nifp, 0);

    fds.fd = NETMAP_FD(lib_netmap_desc);
    fds.events = POLLIN;

    int err;
    err = pthread_create(&polling_thread, NULL, &do_polling, NULL);
    if (err != 0)
        printf("\ncan't create thread :[%s]", strerror(err));
    else
        printf("\n Thread created successfully\n");

    return 0;
}