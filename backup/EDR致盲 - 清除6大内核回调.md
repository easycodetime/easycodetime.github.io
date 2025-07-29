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