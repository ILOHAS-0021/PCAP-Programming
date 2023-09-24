# [WHS][PCAP-Programming] 6반 박진석(3871)

## C, C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램 작성
Ethernet Header : src mac / dst mac <br />
IP Header : src ip / dst ip <br />
TCP Header : src port / dst port <br />
Message도 출력하면 좋음. (적당한 길이로) <br />

## TCP protocol 만을 대상으로 진행 (UDP는 무시), sniff_improved.c, myheader.h 코드 참고
sniff_improved.c <br />
```C
...

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) 
	{
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
```
 myheader.h <br />
 ```C
...

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

...
```
## Docker 
Docker Compose
```bash
docker-compose up
```
Check Server IP
```bash
ifconfig
```
## Start TCP
Server
```bash
./sniff_server
```
Client
```bash
nc <server_ip> <server_port>
```

