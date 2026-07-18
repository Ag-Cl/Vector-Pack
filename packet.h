#ifndef PACKET_H
#define PACKET_H


#include <stdint.h>
//#include <arpa\inet.h>

#pragma pack(push,1)//强制按照一字节对齐，防止编译器优化为2字节对齐破坏struct偏移

struct EthFrame {
    uint8_t dest_mac[6];//目的IP
    uint8_t src_mac[6];//源IP
    uint16_t ether_type;//以太网类型（0x0800 = IPv4,0x0806 = ARP)
};

struct IPv4 {
    uint8_t ver_ihl;//版本+头长度各四字节
    uint8_t tos;//服务类型（TOS）
    uint16_t total_len;//总长度（包含IP头+数据）
    uint16_t id;//标识符
    uint16_t flags_off;//标志位+分片位移
    uint8_t ttl;//生存时间
    uint8_t protocol;//协议（6 = TCP,17 = UDP,1 = ICMP）
    uint16_t checksum;//校验和
    uint32_t src_ip;//源IP
    uint32_t dst_ip;//目的IP
};

struct TCP {
    uint16_t src_port;//源端口
    uint16_t dst_port;//目的端口
    uint32_t seq;//序列号
    uint32_t ack;//确认号
    uint8_t data_off;//数据偏移（单位4字节）
    uint8_t flags;//标志位
    uint16_t window;//窗口大小
    uint16_t checksum;//校验和
    uint16_t urg_ptr;//紧急指针
};

struct UDP {
    uint16_t src_port;//源端口
    uint16_t dst_port;//目的端口
    uint16_t len;//长度
    uint16_t checksum;//校验和
};

#pragma pack(pop)

uint32_t ntoh32 (uint32_t data){
    uint8_t byte0 = (data >> 24) & 0xFF;
    //只截取最高位，0xff表示只读取第八位，不加也可以，uint自动截断
    uint8_t byte1 = (data >> 16) & 0xFF;//只截取次高位
    uint8_t byte2 = (data >> 8) & 0xFF;//只截取次低位
    uint8_t byte3 = data & 0xFF;//只截取最低位
    uint32_t finally_data = (byte3<<24)|(byte2<<16)|(byte1<<8)|byte0;
    //合并为32位数据
    //<<先将byte3提升为4字节，其他以此类推，再或运算合并
    return finally_data;
}

uint16_t ntoh16 (uint16_t data){
    uint8_t byte0 = (data >> 8) & 0xFF;
    uint8_t byte1 = data & 0xFF;//只截取第二位
    uint16_t finally_data = (byte1 << 8) | byte0;
    //此处注释同32位
    return finally_data;
}



#endif
