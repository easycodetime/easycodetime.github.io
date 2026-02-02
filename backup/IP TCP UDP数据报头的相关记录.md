# IP TCP UDP数据报头的相关记录


## IP数据报头
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20230226214359608_2250.png?raw=true)
```c
typedef struct _IP_HEADER_V4_
{
	union
	{
		UINT8 versionAndHeaderLength;
		struct
		{
			UINT8 headerLength : 4;
			UINT8 version : 4;
		};
	};
	union
	{
		UINT8  typeOfService;
		UINT8  differentiatedServicesCodePoint;
		struct
		{
			UINT8 explicitCongestionNotification : 2;
			UINT8 typeOfService6bit : 6;
		};
	};
	UINT16 totalLength;
	UINT16 identification;
	union
	{
		UINT16 flagsAndFragmentOffset;
		struct
		{
			UINT16 fragmentOffset : 13;
			UINT16 flags : 3;
		};
	};
	UINT8  timeToLive;
	UINT8  protocol;
	UINT16 checksum;
	BYTE   pSourceAddress[sizeof(UINT32)];
	BYTE   pDestinationAddress[sizeof(UINT32)];
}IP_HEADER_V4, *PIP_HEADER_V4;
```
```c
IP报头的长度
    IP_HEADER_V4 pHeader;
    int nLength = pHeader.headerLength * 4;
```

## TCP数据报头
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20230226215501000_20824.png?raw=true)
```c
typedef struct _TCP_HEADER_
{
	UINT16 sourcePort;
	UINT16 destinationPort;
	UINT32 sequenceNumber;
	UINT32 acknowledgementNumber;
	union
	{
		UINT8 dataOffsetReservedAndNS;
		struct
		{
			UINT8 nonceSum : 1;
			UINT8 reserved : 3;
			UINT8 dataOffset : 4;
		}dORNS;
	};
	union
	{
		UINT8 controlBits;
		struct
		{
			UINT8 FIN : 1;
			UINT8 SYN : 1;
			UINT8 RST : 1;
			UINT8 PSH : 1;
			UINT8 ACK : 1;
			UINT8 URG : 1;
			UINT8 ECE : 1;
			UINT8 CWR : 1;
		};
	};
	UINT16 window;
	UINT16 checksum;
	UINT16 urgentPointer;
}TCP_HEADER, *PTCP_HEADER;
```
```
TCP报头的长度
    TCP_HEADER pHeader;
    int nLength = pHeader.dORNS.dataOffset * 4;
```

## UDP数据报头
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20230226215856227_2865.png?raw=true)
```c
typedef struct _UDP_HEADER_
{
	UINT16 sourcePort;
	UINT16 destinationPort;
	UINT16 length;
	UINT16 checksum;
}UDP_HEADER, *PUDP_HEADER;
```
```
UDP报头的长度 = 固定长度
```

## 网络字节序的相互转换

## checksum值的计算
```c
/定义一个结构体来存储伪ip头部
struct pseudo_header
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

//定义一个函数来计算16位二进制字符串之和
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

//定义一个函数来计算tcp的checksum
unsigned short tcp_checksum(struct tcphdr *tcph , int len_tcp , struct sockaddr_in *src_addr , struct sockaddr_in *dest_addr)
{
  //创建一个伪ip头部对象，并填充相关信息
  struct pseudo_header psh; 
  psh.source_address = src_addr->sin_addr.s_addr; //源地址
  psh.dest_address = dest_addr->sin_addr.s_addr; //目标地址
  psh.placeholder = 0; //占位符，固定为0
  psh.protocol = IPPROTO_TCP; //协议类型，固定为TCP
  psh.tcp_length = htons(len_tcp); //TCP长度

  //创建一个缓冲区，用于存储伪ip头部和tcp头部
  int total_len = sizeof(struct pseudo_header) + len_tcp; 
  char *buf = malloc(total_len);

  //将伪ip头部和tcp头部复制到缓冲区中
  memcpy(buf , (char*) &psh , sizeof (struct pseudo_header));
  memcpy(buf + sizeof(struct pseudo_header) , tcph , len_tcp);

  //调用csum函数计算缓冲区中所有二进制字符串之和的反码，即为tcp的checksum值
  unsigned short check_sum = csum( (unsigned short*) buf , total_len);

  free(buf);

  return check_sum;

}
```