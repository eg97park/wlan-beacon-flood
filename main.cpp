#include "pch.h"

#include "tools.h"
#include "BeaconFlood.h"


/**
 * @brief thread 종료용 플래그.
*/
volatile sig_atomic_t g_req_thread_exit = 0;

/**
 * @brief 생성할 thread 개수.
*/
const auto CPU_COUNT = std::thread::hardware_concurrency();

/**
 * @brief thread mutex.
*/
std::mutex g_pcap_handler_mutex;

/**
 * @brief ssid list 파일을 읽어, 목록을 반환하는 함수.
 * 
 * @param file_path ssid list 파일 경로
*/
std::vector<std::string> read_ssid_list(char* file_path);

/**
 * @brief 사용법을 출력하는 함수.
 * 
 * @param signal 처리할 signal 번호
 */
void signal_handler(int signal);

/**
 * @brief thread 돌릴 함수.
 * 
 * @param handle pcap 핸들러
 */
void thread_function(std::vector<std::string>& ssid_list, pcap_t* handle);

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
        .dev_ = NULL,
        .file_ = NULL
    };

    if (!parse(&param, argc, argv))
        return -1;

    std::vector<std::string> ssid_list = read_ssid_list(param.file_);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    std::vector<std::thread> thread_pool;
    for (size_t i = 0; i < CPU_COUNT; i++)
    {
        thread_pool.push_back(std::thread(thread_function, std::ref(ssid_list), std::ref(handle)));
    }
    
    // thread 종료.
    for (std::vector<std::thread>::iterator it = thread_pool.begin(); it != thread_pool.end(); ++it)
    {
        (*it).join();
    }
    printf("All threads were joined.\n");

    pcap_close(handle);
	return 0;
}

std::vector<std::string> read_ssid_list(char* file_path)
{
    std::vector<std::string> ssid_list;
    std::ifstream ifs(file_path);

    std::string ssid;
    while (std::getline(ifs, ssid))
    {
        std::istringstream iss(ssid);
        if (!(iss >> ssid))
        {
            break;
        }
        ssid_list.push_back(ssid);
    }
    return ssid_list;
}

void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        printf("SIGINT was detected. Start cleaning...\n");
        g_req_thread_exit = 1;
    }
    return;
}

void thread_function(std::vector<std::string>& ssid_list, pcap_t* handle)
{
    BeaconFlood* flood_pkt_generator = new BeaconFlood();
    while (!g_req_thread_exit)
    {
        sleep(0);
        for (std::vector<std::string>::iterator it = ssid_list.begin(); it != ssid_list.end(); ++it)
        {
            beacon_flood_pkt* flood_pkt = (*flood_pkt_generator).get_flood_pkt(*it);

    g_pcap_handler_mutex.lock();
            printf("generated SSID: %s\n", flood_pkt->ssid.c_str());
            int res = pcap_sendpacket(handle, flood_pkt->packet, flood_pkt->size);
    g_pcap_handler_mutex.unlock();

            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
                pcap_close(handle);
                return;
            }
            
            free(flood_pkt->packet);
            flood_pkt->packet = nullptr;
            free(flood_pkt);
            flood_pkt = nullptr;
        }
    }
    delete flood_pkt_generator;
    return;
}