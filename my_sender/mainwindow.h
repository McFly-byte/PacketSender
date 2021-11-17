#pragma once
#include <QtWidgets/QMainWindow>
#include <QDebug>
#include "qstring.h"
#define HAVE_REMOTE //一定要先define HAVA_REMOTE 再include "wpcap.h" 否则还是报错
#include "pcap.h"   //Qt引入winpcap
#include <remote-ext.h>
/*
    这是wincap的一个失误,忘记把该函数(pcap_findalldevs_ex()等)的声明文件包含进去了。
    现在的Winpcap做了更新，因为winpcap现在增加了远程捕获的功能，
    在pcap_findalldevs_ex和pcap_open函数中增加了远程主机身份验证的参数
    struct pcap_rmtauth * auth，所以将两个函数的定义转移到remote-ext.h中去了。
*/
#include <winsock2.h>   //为了使用htons(),htonl(),ntohs(),ntohl()
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"ws2_32.lib")
/*
 * MSVC预处理命令 将MFC的程序移植到Qt上
 * 还需要在pro文件内 加入 LIBS += -lws2_32
*/

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1       //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1       //ARP请求
#define ARP_RESPONSE    2       //ARP应答
#define PROTO_TCP 6     //TCP协议号
#define PROTO_UDP 17    //UDP协议号
#define MAX_BUFF_LEN 65500
using namespace std;

namespace Ui {
    class MainWindow;
}

//14字节以太网帧头部
struct EthernetHeader
{
    u_char dstMAC[6];    //目的MAC地址 6字节
    u_char srcMAC[6];    //源MAC地址 6字节
    u_short EthType;      //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP数据包
struct ArpHeader
{
    unsigned short hdType;    //硬件类型 2字节
    unsigned short proType;   //协议类型 2字节
    unsigned char hdSize;     //硬件地址长度 1字节
    unsigned char proSize;    //协议地址长度 1字节
    unsigned short op;        //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4） 2字节
    u_char smac[6];           //发送方以太网地址（源MAC地址）    6
    unsigned char sip[4];     //发送方IP地址 4
    u_char dmac[6];           //接收方以太网地址（目的MAC地址）   6
    unsigned char dip[4];     //接收方IP地址 4
};

//定义整个arp报文，总长度42字节
struct ArpPacket {
    EthernetHeader ed;  //14字节
    ArpHeader ah;       //28字节
};

//定义ip头
struct IpHeader
{
    unsigned char       version;       //版本号：IP协议的版本。对于IPv4来说值是4
    unsigned char       tos;            //服务类型(Type Of Service，TOS)：3位优先权字段(现已被忽略) + 4位TOS字段 + 1位保留字段(须为0)。4位TOS字段分别表示最小延时、最大吞吐量、最高可靠性、最小费用，其中最多有一个能置为1。应用程序根据实际需要来设置TOS值，如ssh和telnet这样的登录程序需要的是最小延时的服务，文件传输ftp需要的是最大吞吐量的服务
    unsigned short      total_len;      //总长度: 指整个IP数据报的长度，单位为字节，即IP数据报的最大长度为65535字节(2的16次方)
    unsigned short      ident;          //标识：唯一地标识主机发送的每一个数据报，其初始值是随机的，每发送一个数据报其值就加1。同一个数据报的所有分片都具有相同的标识值
    unsigned short      frag_and_flags; //3位标志位
    unsigned char       ttl;            //8位生存时间
    unsigned char       proto;          //8位协议
    unsigned short      checksum;       //16位ip头部检验和
    unsigned int        srcIP;          //32位源ip地址
    unsigned int        dstIP;          //32位目的ip地址
};

//定义tcp头
struct TcpHeader
{
    unsigned short    th_srcport;   //16位源端口
    unsigned short    th_dstport;   //16位目的端口
    unsigned int      th_seq;       //32位序列号
    unsigned int      th_ack;       //32位确认号
    unsigned char     th_lenres;    //4位头部长度/6位保留字
    unsigned char     th_flag;      //6位标志位
    unsigned short    th_win;       //16位窗口大小
    unsigned short    th_sum;       //16位校验和
    unsigned short    th_urp;       //16位紧急指针
};

//定义伪头部
struct PseudoHeader {
    unsigned long    src_add;   //源IP地址 32
    unsigned long    dst_add;   //目的IP地址 32
    char             placeholder;       //填充0 8
    char             protocol;      //协议号 8
    unsigned short   plen;      //TCP/UDP头长度 8
};

//定义UDP头
struct UdpHeader
{
    u_short src_port;		//源端口  16位
    u_short dst_port;		//目的端口 16位
    u_short len;			//数据报长度 16位
    u_short check;          //校验和 16位
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
public slots:
    void send_clicked();
public:
    MainWindow(QWidget *parent = Q_NULLPTR);
    pcap_if_t *alldevs;              //所有网络适配器
    pcap_if_t *d;                    //选中的网络适配器
    int inum;                        //选择网络适配器
    pcap_t *adhandle;                //打开网络适配器，捕捉实例,是pcap_open返回的对象
    char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
    ~MainWindow();
private:
    Ui::MainWindow *ui;
};

/*
    struct pcap_if
    {
        struct pcap_if *next;//指向下一个网卡

        char *name;//网卡的标识符，唯一识别一个网卡

        char *description;//用来描述网卡

        struct pcap_addr*address;//网卡的地址，包括IP地址，网络掩码，广播地址等，类型中的成员变量在后面会写到

        bpf_u_int32 flags;//接口标志
    }
*/
