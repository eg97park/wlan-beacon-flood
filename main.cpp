#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include <unistd.h>

#include <string>

#include "wlanhdr.h"
#include "tools.h"
#include "BeaconFlood.h"


int main(int argc, char* argv[]) {
    Param param = {
        .dev_ = NULL
    };

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    BeaconFlood flood_pkt_generator = BeaconFlood();
    const char* SLASH_LINE = "------------------------------------------------";

    while (true)
    {
        sleep(0);
        beacon_flood_pkt* flood_pkt = flood_pkt_generator.get_flood_pkt();
        int res = pcap_sendpacket(handle, flood_pkt->packet, flood_pkt->size);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        free(flood_pkt->packet);
        free(flood_pkt);
    }
    
    pcap_close(handle);
	return 0;
}
