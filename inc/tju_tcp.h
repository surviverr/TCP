#ifndef _TJU_TCP_H_
#define _TJU_TCP_H_

#include "global.h"
#include "tju_packet.h"
#include "kernel.h"

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket();

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr);

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
*/
int tju_listen(tju_tcp_t* sock);

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* sock);


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr);


int tju_send (tju_tcp_t* sock, const void *buffer, int len);
int tju_recv (tju_tcp_t* sock, void *buffer, int len);

/*
关闭一个TCP连接
这里涉及到四次挥手
*/
int tju_close (tju_tcp_t* sock);


int tju_handle_packet(tju_tcp_t* sock, char* pkt);

//new function
int syn_send(tju_tcp_t* sock, int seqnum);
int synack_send(tju_tcp_t* sock, int seqnum, int acknum);
int ack_send(tju_tcp_t* sock, int seq, int acknum);
int fin_send(tju_tcp_t* sock);
int finack_send(tju_tcp_t* sock);

//新建一个队列
tju_queue* makequeue();

//从队列now中删除目标连接
void queue_del(tju_queue* now, int tarhash);

//在队列now中增加目标连接
void queue_add(tju_queue* now, int tarhash);

//从当前开始一秒的系统时间
struct timespec* some_sec(int now_time);

//从当前开始x毫秒的系统时间
struct timespec* some_msec(int now_time);

//向发送缓冲区添加数据
void add_send_buf(tju_tcp_t* sock, char* buf, int len);

//负责发送缓冲区
void* tju_send_thread();

//向发送链表中添加元素
void add_sendlist(tju_list* now, char* toadd, int _seq, int _len);

//在发送链表中删除元素
void delete_sendlist(tju_list* now, int new_ack);

//在接收链表中增加元素并作出反应
void add_recvlist(tju_tcp_t* sock, tju_list* now, char* toadd, int _seq, int _len);

//现在时间的ns形式
uint64_t nowtime_ns();

//更新时间间隔
void update_timeout(tju_tcp_t* sock);

//绝对值函数
uint64_t absuint64(uint64_t x, uint64_t y);

//开启时钟
void start_timer(tju_tcp_t* sock);

//关闭时钟
void stop_timer(tju_tcp_t* sock);

//定时器线程
void* tju_timer(void* arg);

//取3个数中的最小值
int min(int x, int y, int z);

//取2个数中的最小值
int min2(int x, int y);

//取2个数中的最大值
int max(int x, int y);

//获取当前的时间
long getCurrentTime();

//获得初始随机序列号
int getmyrandseq(int now);

//写SEND
void maketrace_send(int seq, int ack, int flg, int len);

//写RECV
void maketrace_recv(int seq, int ack, int flg, int len);

//写RWND
void maketrace_rwnd(int size);

//写SWND
void maketrace_swnd(int size);

//写RTT
void maketrace_rtt(tju_tcp_t* sock);

//写CWND
void maketrace_cwnd(tju_tcp_t* sock, int type, int size);

//写DELV
void maketrace_delv(tju_tcp_t* sock, int seq, int size);

//写所有window
void maketrace_allwindow(tju_tcp_t* sock, int type);

#endif

