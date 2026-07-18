#include <iostream>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <net/ethernet.h>
#include "packet.h"

int main(){
    //创建原始套接字
    //AF_PACKET：直接访问链路层（以太网帧）
    //SOCK_RAW：原始套接字，读取完整数据包
    //ETH_P_ALL：接收所有类型的以太网帧
    int sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (sock == -1){
        std::cerr<<"socket()失败"<<std::endl;
        close(sock);
        return 1;
    }
    //开启混杂模式
    struct ifreq ifr;
    std::strcpy(ifr.ifr_name,"enp2s0");//设置要操作的网卡名
    //获取网卡当前标志
    if (ioctl(sock,SIOCGIFFLAGS,&ifr) == -1){
        std::cerr<<"获取网卡标志失败"<<std::endl;
        close(sock);
        return 1;
    }
    //用或运算加上混杂模式
    ifr.ifr_flags |= IFF_PROMISC;
    //将修改后的标志写回网卡
    if (ioctl(sock,SIOCSIFFLAGS,&ifr) == -1){
        std::cerr<<"开启混杂模式失败"<<std::endl;
        close(sock);
        return 1;
    }
    //创建缓冲区
    uint8_t buffer[65536];
    std::cout<<"开始抓包，按Ctrl + C退出"<<std::endl;
    while (true){
        ssize_t len = recvfrom(sock,buffer,sizeof(buffer),0,nullptr,nullptr);
        if (len > 0){
            EthFrame* eth = (EthFrame*)buffer;//创建以太网帧头，将缓冲区设置为以太网帧头，忽略14字节后的IPv4
            //检查以太网类型是否为IPv4(0x0800)
            if(ntoh16(eth -> ether_type) == 0x800){
                IPv4* ip = (IPv4*)(buffer + 14);//以太网帧头占14位，从14位后为IPv4帧头
                //读取源IP和目的IP并转换为小端模式（CPU从内存读取后字节逆序，需要转换成大端）
                uint32_t src = ntoh32(ip -> src_ip);//(读取后格式是小端，所以需要用这个函数再逆序，实际上是转换成大端拆字节打印了)
                uint32_t dst = ntoh32(ip -> dst_ip);
                //将32位整数拆分为4个字节，并按照大端模式打印
                printf("[ 源IP:%d.%d.%d.%d -> 目的IP:%d.%d.%d.%d ]",
                    (src >> 24) & 0xFF,
                    (src >> 16) & 0xFF,
                    (src >> 8) & 0xFF,
                    src & 0xFF,
                    (dst >> 24) & 0xFF,
                    (dst >> 16) & 0xFF,
                    (dst >> 8) & 0xFF,
                    dst & 0xFF);
                if((int)ip->protocol == 6){
                    printf(" \t通信协议类型：TCP");
                    TCP* tcp = (TCP*)(buffer + 34);
                    if((int)tcp->flags & 0x1){
                        printf(" SYN");
                    }
                    if((int)tcp->flags & 0x10){
                        printf(" ACK");
                    }
                    if((int)tcp->flags & 0x2){
                        printf(" FIN");
                    }
                    if((int)tcp->flags & 0x4){
                        printf(" RST");
                    }
                    if((int)tcp->flags & 0x8){
                        printf(" PSH");
                    }
                    if((int)tcp->flags == 0x20){
                        printf(" URG");
                    }
                    printf("\n");
                }else if((int)ip->protocol == 17){
                    printf(" \t通信协议类型：UDP\n");
                }
            }
        }
    }
    close(sock);
    return 0;
}
