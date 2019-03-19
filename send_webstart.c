#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/udp.h>
#include <poll.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>

#define ETH0_NAME "enp0s31f6" //replace with real net name by ifconfig

#define ETH_NAME_LEN 30
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN 20

#define BUFFER_SIZE  1024 * 1024 * 16
#define BLOCK_SIZE  4096
#define PER_PACKET_SIZE 2048

#define MAX_MAC_PKT_LEN 1500
#define ETH_P_ST_WEB   0xf1f1

struct EthInfo 
{
    char name[ETH_NAME_LEN];
    int sock_fd;
    char *buf_rx;
    char *buf_tx;
    struct tpacket_req req_rx;
    struct tpacket_req req_tx;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
};
struct start_web_ip_packet 
{
    unsigned char dest_mac[ETH_ALEN];
    unsigned char src_mac[ETH_ALEN]; 
    unsigned short type;
};
struct EthInfo eth0;
struct start_web_ip_packet start_web_packet;
struct ifreq ifr0;

/* 物理网卡混杂模式属性操作 */
static int eth_set_promisc(const char *pcIfName, int fd, int iFlags) 
{
    int iRet = -1;
    struct ifreq stIfr;

    /* 获取接口属性标志位 */
    strcpy(stIfr.ifr_name, pcIfName);
    iRet = ioctl(fd, SIOCGIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        printf("[Error]Get Interface Flags\n");    
        return -1;
    }
    
    if (0 == iFlags) /* 取消混杂模式 */
        stIfr.ifr_flags &= ~IFF_PROMISC;
    else/* 设置为混杂模式 */
        stIfr.ifr_flags |= IFF_PROMISC;

    iRet = ioctl(fd, SIOCSIFFLAGS, &stIfr);
    if (0 > iRet)
    {
        printf("[Error]Set Interface Flags\n");
        return -1;
    }
    
    return 0;
}

void set_rx_buffer(struct EthInfo *eth) 
{
    int ret = -1;

    eth->req_rx.tp_block_size = BLOCK_SIZE;
    eth->req_rx.tp_block_nr = BUFFER_SIZE / BLOCK_SIZE;
    eth->req_rx.tp_frame_size = PER_PACKET_SIZE;
    eth->req_rx.tp_frame_nr = BUFFER_SIZE / PER_PACKET_SIZE;

    ret = setsockopt(eth->sock_fd, SOL_PACKET, PACKET_RX_RING, (void *)&eth->req_rx, sizeof(eth->req_rx));
    if (ret < 0) 
    {
        perror("set rx ring error");
        close(eth->sock_fd);
        return;
    }
    eth->buf_rx = (char *)mmap(0, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, eth->sock_fd, 0);
    if (eth->buf_rx == MAP_FAILED) 
    {
        perror("mmap error");
        close(eth->sock_fd);
        return;
    }
}

void eth0_open() 
{
    struct sockaddr_ll ether0;
    int bind0 = -1;
	
    strcpy(eth0.name, ETH0_NAME);
    eth0.sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(eth0.sock_fd < 0)
        printf("Creat eth0 receive socket error\n");
    else
        printf("eth0 receive socket created\n");
	
    /*bind sock*/
    bzero(&ether0,sizeof(ether0));
	strcpy(ifr0.ifr_name,eth0.name);
	ether0.sll_family = PF_PACKET;
	ioctl(eth0.sock_fd,SIOCGIFINDEX,&ifr0);
	ether0.sll_ifindex = ifr0.ifr_ifindex;
	ether0.sll_protocol = htons(ETH_P_ALL);
	bind0 = bind(eth0.sock_fd,(struct sockaddr_ll*)&ether0,sizeof(struct sockaddr_ll));
	if(bind0 < 0)
	{
	    printf("Bind recv socket failed\n");
		printf("%d\n",bind0);
	}
	else
	{
	    printf("Bind recv sock to eth0 success\n");
	}
	ioctl(eth0.sock_fd,SIOCGIFHWADDR,&ifr0);

	eth_set_promisc(eth0.name, eth0.sock_fd, 1);
	set_rx_buffer(&eth0);
	int val = IP_PMTUDISC_DO;
	setsockopt(eth0.sock_fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
}

static void dump_packet(char *buf, int len) 
{
	int i = 0;
	int index = 0;
	for (i=0; i<len; i++) 
	{
		if (i == 1514) 
			printf("\n--------------------\n");
		
		index = i % 16;
		printf("0x%02X ", (unsigned char)buf[i]);
		if (index == 15) 
			printf("\n");
	}
	printf("\n=======================================\n");
}

int main(int argc, char **argv)
{
	int ret;
	unsigned char buf[MAX_MAC_PKT_LEN+12] = {0};
	int fd;
	struct stat st;
	int send_len;
	int i=0;
	
	eth0_open();	

	memcpy((unsigned char *)(&start_web_packet.src_mac[0]),(unsigned char *)(&ifr0.ifr_hwaddr.sa_data[0]),ETH_ALEN);

	start_web_packet.dest_mac[0] = 0x00;
	start_web_packet.dest_mac[1] = 0x00;
	start_web_packet.dest_mac[2] = 0x01;
	start_web_packet.dest_mac[3] = 0x02;
	start_web_packet.dest_mac[4] = 0x03;
	start_web_packet.dest_mac[5] = 0x04;

	start_web_packet.type = ETH_P_ST_WEB;

	while(1)
	{
	    ret = send(eth0.sock_fd, (unsigned char *)&start_web_packet, sizeof(start_web_packet), 0);
		if (-1 == ret) 
		    printf("send error");

        sleep(2);
    }
	return 0;
}
