# WFP初探
参考资料
        https://www.cnblogs.com/XYDsoft/articles/16857933.html
        https://learn.microsoft.com/zh-cn/windows/win32/fwp/tcp-packet-flows
        https://bot-man-jl.github.io/articles/?post=2018/Learn-TCP-IP-from-WFP-2

## WFP简述
```
WFP（Windows Filtering Platform）驱动框架，WFP是在WIN7以上系统中TDI 的替代框架，提供了更加强大的内核网络数据包的过滤，拦截，修改等诸多功能
```


## TCP三次握手在WFP的流动情况
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20230226174725553_15945.png?raw=true)
```
首先连接建立过程：
    server端调用 socket， bind， listen， accept 等函数接收客户端连接
    client端调用 socket， connect 建立连接，

server
    bind： FWPM_LAYER_ALE_BIND_REDIRECT_V4        这个支持win7以上系统
    bind： FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4
    listen: FWPM_LAYER_ALE_AUTH_LISTEN_V4         listen函数认证

    接下来就是accept开始接收客户端的请求，首先接收到的是SYN数据包

    SYN: FWPM_LAYER_INBOUND_IPPACKET_V4           SYN包首先进入IP层
    SYN: FWPM_LAYER_INBOUND_TRANSPORT_V4          SYN包进入传输层
    SYN: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4       SYN进入ALE层，确认建立连接，同时给客户端回复SYN-ACK数据包。
    SYN-ACK: FWPM_LAYER_OUTBOUND_TRANSPORT_V4     回复的SYN-ACK数据包进入传输层
    SYN-ACK: FWPM_LAYER_OUTBOUND_IPPACKET_V4      回复的SYN-ACK数据包进入IP层

    然后就开始接收客户端发来的最后一个ACK数据包

    ACK: FWPM_LAYER_INBOUND_IPPACKET_V4           ACK包首先进入IP层
    ACK: FWPM_LAYER_INBOUND_TRANSPORT_V4          ACK进入传输层
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4            ACK进入ALE层，这个时候就已经建立起了连接

client
    bind： FWPM_LAYER_ALE_BIND_REDIRECT_V4 这个支持win7以上系统，（不管有没有显式调用bind函数，绑定操作都会发生）
    bind： FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4
    connect: FWPM_LAYER_ALE_CONNECT_REDIRECT_V4   win7以上系统
    connect: FWPM_LAYER_ALE_AUTH_CONNECT_V4

    接着发送SYN数据包

    SYN: FWPM_LAYER_OUTBOUND_TRANSPORT_V4        SYN进入到传输层
    SYN: FWPM_LAYER_OUTBOUND_IPPACKET_V4         SYN进入到IP层

    接收到 SYN_ACK数据包

    SYN-ACK: FWPM_LAYER_INBOUND_IPPACKET_V4     首先进入IP层
    SYN-ACK: FWPM_LAYER_INBOUND_TRANSPORT_V4    进入到传输层
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4          到达ALE层，内核建立起连接，同时回复ACK包给服务端。
    ACK: FWPM_LAYER_OUTBOUND_TRANSPORT_V4       回复的ACK包进入传输层
    ACK: FWPM_LAYER_OUTBOUND_IPPACKET_V4        回复的包进入IP层
```

## 上述流程的简述和实际应用
```
WFP可以在
    1. 应用层(数据流层),捕获修改网络数据
    2. 传输层,捕获修改TCP,UDP数据包
    3. 网际层,捕获修改IP数据包
    4. 链路层,捕获修改以太网卡MAC地址的链路层数据包(注意:WIN8.1以上系统才包含这层)

层级简要记录
    FWPM_LAYER_INBOUND_IPPACKET_V4
    FWPM_LAYER_OUTBOUND_IPPACKET_V4

    INBOUND/OUTBOUND     输入和输出
    IPPACKET             代表网络层
    TRANSPORT            代表传输层
    V4/V6                IPV4/IPV6

1. 想做流量拦截,例如阻止本机所有的出网流量      挂载在 FWPM_LAYER_OUTBOUND_IPPACKET_V4 这层拦截所有的包即可
2. 做驱动层的端口转发       挂载在 FWPM_LAYER_INBOUND_IPPACKET_V4 这层找到ip包头的来去地址修改即可
3. tcp流量数据修改         挂载在 FWPM_LAYER_INBOUND_TRANSPORT_V4 这层即可获取到tcp传输的数据
```


## 创建过滤点(也就是代码到底怎么写)
```c
1. 添加一个子层  FwpmSubLayerAdd  排除干扰
2. 注册呼出函数  FwpsCalloutRegister
3. 添加呼出接口函数 FwpmCalloutAdd
4. 添加过滤器    FwpmFilterAdd


以上4步都完成后会把以下函数添加到WFP的callback中
static void NTAPI callifyFn0(
IN const FWPS_INCOMING_VALUES0* inFixedValues,
IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
IN OUT void* layerData, //如果是在传输层，IP层，数据层，指向 NET_BUFFER_LIST类型的参数
IN const FWPS_FILTER0* filter,
IN UINT64 flowContext,
OUT FWPS_CLASSIFY_OUT0* classifyOut)
{
    //这层的数据包怎么处理就是你说的算了,你把这个包丢了,后面的层也就收不到了
    //这层修改了包,后面的层就会收到修改后的包
}

代码示例
    1. https://github.com/minglinchen/WinKernelDev/tree/master/WfpSample/WfpSample  <Windows内核编程> 中的示例,一个简单的阻止流量的例子
    2. https://github.com/microsoft/Windows-driver-samples/tree/main/network/trans/ddproxy  微软出示的示例  很原始的例子
    3. https://github.com/BOT-Man-JL/WFP-Traffic-Redirection-Driver  一个匿名通信项目,代码进行了一定程度的封装
```