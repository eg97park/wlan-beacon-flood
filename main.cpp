#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include <unistd.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>

#include "wlanhdr.h"
#include "tools.h"
#include "BeaconFlood.h"


const auto cpu_count = std::thread::hardware_concurrency();
std::mutex g_pcap_handler_mutex;

void thread_function(pcap_t* handle, BeaconFlood* beacon_flooder)
{
    while (true)
    {
        sleep(0);
        beacon_flood_pkt* flood_pkt = (*beacon_flooder).get_flood_pkt();
g_pcap_handler_mutex.lock();
        std::cout << std::this_thread::get_id() << ": " << flood_pkt->ssid << "\n";
        int res = pcap_sendpacket(handle, flood_pkt->packet, flood_pkt->size);
g_pcap_handler_mutex.unlock();
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        free(flood_pkt->packet);
        free(flood_pkt);
    }
    return;
}

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
    
    std::vector<std::thread> thread_pool;
    for (size_t i = 0; i < cpu_count; i++)
    {
        BeaconFlood* flood_pkt_generator = new BeaconFlood();
        thread_pool.push_back(std::thread(thread_function, std::ref(handle), flood_pkt_generator));
    }
    
    for (std::vector<std::thread>::iterator it = thread_pool.begin(); it != thread_pool.end(); it++)
    {
        (*it).join();
    }

    
    pcap_close(handle);
	return 0;
}
