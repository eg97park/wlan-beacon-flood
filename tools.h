#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <map>


/**
 * @brief 사용법을 출력하는 함수.
 * 
 * @param argv 
 */
void usage(char* argv[]);


/**
 * @brief 디버깅 플래그용?
 * 
 */
typedef struct {
    char* dev_;
} __attribute__((__packed__)) Param;


/**
 * @brief 주어진 인자를 파싱하여 처리하는 함수.
 * 
 * @param param ?
 * @param argc 인자 개수
 * @param argv 인자 배열
 * @return true 
 * @return false 
 */
bool parse(Param* param, int argc, char* argv[]);


/**
 * @brief 주어진 주소로부터 메모리 값을 주어진 만큼 읽어 출력하는 함수.
 * 
 * @param p 읽을 주소
 * @param n 읽을 크기
 * 
 * @ref https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
 */
void dump(void* p, size_t n);
