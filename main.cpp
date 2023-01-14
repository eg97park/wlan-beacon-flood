#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>

#include <unistd.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>

#include "wlanhdr.h"
#include "tools.h"
#include "BeaconFlood.h"


volatile sig_atomic_t REQ_THREAD_EXIT = 0;
const auto cpu_count = std::thread::hardware_concurrency();
std::mutex g_pcap_handler_mutex;

void signal_handler(int signal);

void thread_function(pcap_t* handle);

int main(int argc, char* argv[]) {

    /**
     * @ref https://stackoverflow.com/questions/1641182/how-can-i-catch-a-ctrl-c-event
    */
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);
    
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
        thread_pool.push_back(std::thread(thread_function, std::ref(handle)));
    }
    
    for (std::vector<std::thread>::iterator it = thread_pool.begin(); it != thread_pool.end(); it++)
    {
        (*it).join();
    }
    printf("All threads were joined.\n");

    pcap_close(handle);
	return 0;
}

void signal_handler(int signal)
{
    printf("SIGINT was detected. Start cleaning...\n");
    REQ_THREAD_EXIT = 1;
    return;
}

void thread_function(pcap_t* handle)
{
    BeaconFlood* flood_pkt_generator = new BeaconFlood();
    while (!REQ_THREAD_EXIT)
    {
        sleep(0);
        beacon_flood_pkt* flood_pkt = (*flood_pkt_generator).get_flood_pkt();
        // beacon_flood_pkt* flood_pkt = (*flood_pkt_generator).get_flood_pkt("TTTEESSSTT");
g_pcap_handler_mutex.lock();
        printf("Thread [0x%x] generated SSID: %s\n", std::this_thread::get_id(), flood_pkt->ssid.c_str());
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
    delete flood_pkt_generator;
    return;
}