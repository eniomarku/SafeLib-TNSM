#include <stdio.h>

int ocall_l3vnf_create_server(void *lib_netmap_desc, int len_lib_netmap_desc, char *ifname);

int main() {
    return ocall_l3vnf_create_server(NULL, 0, NULL);
}