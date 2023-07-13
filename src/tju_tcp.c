#include "tju_tcp.h"
#include "semaphore.h"

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;
    
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    //初始化sendlist
    sock->sendlist = (tju_list*)malloc(sizeof(tju_list));
    pthread_mutex_init(&(sock->sendlist->list_lock), NULL);
    sock->sendlist->first = sock->sendlist->tail = NULL;
    sock->sendlist->list_len = 0;

    //初始化recvlist
    sock->recvlist = (tju_list*)malloc(sizeof(tju_list));
    pthread_mutex_init(&(sock->recvlist->list_lock), NULL);
    sock->recvlist->first = sock->recvlist->tail = NULL;
    sock->recvlist->list_len = 0;
    sock->recvlist->tot_size = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = (sender_window_t*)malloc(sizeof(sender_window_t));
    sock->window.wnd_recv = (receiver_window_t*)malloc(sizeof(receiver_window_t));

    sem_init(&sock->readytostart, 0, 0);

    if(pthread_cond_init(&sock->readytostop, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }
2 * 
    pthread_mutex_init(&(sock->stopmutex), NULL);

    pthread_mutex_init(&(sock->window.wnd_send->ack_cnt_lock), NULL);
    sock->window.wnd_send->ack_cnt = 0;

    sock->window.wnd_send->rwnd = TCP_RECVWN_SIZE;
    sock->window.wnd_send->swnd = MAX_DLEN;

    sock->window.wnd_send->timeout_interval = 1000000000;
    sock->window.wnd_send->estimated_rtt = sock->window.wnd_send->deviation_rtt = 0;
    sock->window.wnd_send->sample_rtt = sock->window.wnd_send->send_timepoint = 0;

    //拥塞控制
    sock->window.wnd_send->cwnd = MAX_DLEN;
    sock->window.wnd_send->ssthresh = 32 * MAX_DLEN;
    sock->cstate = SLOW_START;
    sock->window.wnd_send->flg_ssthresh = 1;
    sock->window.wnd_send->retransmit = 0; //没被重传
    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    int hashval = cal_hash(bind_addr.ip, bind_addr.port, 0, 0);
    if(bind_socks[hashval] == NULL) {   //绑定成功
        bind_socks[hashval] = sock;
        sock->bind_addr = bind_addr;
    } else return -1;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    if(listen_socks[hashval] == NULL) {
        sock->state = LISTEN;
        listen_socks[hashval] = sock;
        //建立半连接和全连接队列
        listen_queue[hashval][0] = makequeue();
        listen_queue[hashval][1] = makequeue();
    } else return -1;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    int ls_hash_val = cal_hash(listen_sock->bind_addr.ip, listen_sock->bind_addr.port, 0, 0);
    while(!(listen_queue[ls_hash_val][0]->size));
    tju_tcp_t* accept_socket = established_socks[listen_queue[ls_hash_val][0]->array[0]];
    int synack_try = 0, synack_time = 1;
    accept_socket->window.wnd_send->base = accept_socket->window.wnd_send->nextseq = getmyrandseq(0);
    accept_socket->window.wnd_send->nextseq += 1;
    while(accept_socket->state != SYN_RECV);
    while(accept_socket->state == SYN_RECV) {
        if(synack_try == tjutcp_syn_retries) return NULL;
        synack_send(accept_socket, accept_socket->window.wnd_send->base, accept_socket->window.wnd_recv->expect_seq);
        //printf("synack_try = %d次, synack_time = %ds\n", synack_try, synack_time);
        pthread_mutex_lock(&time_mutex);
        pthread_cond_timedwait(&timeout, &time_mutex, some_sec(synack_time));
        pthread_mutex_unlock(&time_mutex);
        synack_time *= 2;
        synack_try += 1;
    }
    listen_queue[ls_hash_val][1]->size -= 1;

    //开启发送线程
    pthread_t thread_id = 1002;
    int rst = pthread_create(&thread_id, NULL, tju_send_thread, (void*)accept_socket);
    if(rst < 0) {
        printf("ERROR open thread");
        exit(-1);
    }

    //开启定时器线程
    rst = pthread_create(&thread_id, NULL, tju_timer, (void*)accept_socket);
    if(rst < 0) {
        printf("ERROR open thread");
        exit(-1);
    }

    return established_socks[listen_queue[ls_hash_val][1]->array[0]];
}


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;

    sock->state = SYN_SENT;
    int syn_try = 0, syn_time = 1;
    sock->window.wnd_send->base = sock->window.wnd_send->nextseq = getmyrandseq(1);
    sock->window.wnd_send->nextseq += 1;
    sock->window.wnd_recv->expect_seq = 0;
    while(sock->state != ESTABLISHED) {
        if(syn_try == tjutcp_syn_retries) {
            printf("CLOSED\n");
            return -1;
        }
        syn_send(sock, sock->window.wnd_send->base);
        pthread_mutex_lock(&time_mutex);
        pthread_cond_timedwait(&timeout, &time_mutex, some_sec(syn_time));
        pthread_mutex_unlock(&time_mutex);
        syn_time *= 2;
        syn_try += 1;
    }    
    //开启发送线程
    pthread_t thread_id = 1002;
    int rst = pthread_create(&thread_id, NULL, tju_send_thread, (void*)sock);
    if(rst < 0) {
        printf("ERROR open thread");
        exit(-1);
    }

    rst = pthread_create(&thread_id, NULL, tju_timer, (void*)sock);
    if(rst < 0) {
        printf("ERROR open thread");
        exit(-1);
    }

    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    char* data = malloc(len);
    memcpy(data, buffer, len); 
    add_send_buf(sock, data, len);
    free(data);
    return 0;
}


int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len < len);

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return read_len;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    maketrace_recv(get_seq(pkt), get_ack(pkt), get_flags(pkt), get_plen(pkt) - DEFAULT_HEADER_LEN);
    if(sock->state == LISTEN && syn_packet(pkt)) {
        tju_tcp_t* res_socket = tju_socket();
        res_socket->established_local_addr.ip = inet_network("172.17.0.3");
        res_socket->established_remote_addr.ip = inet_network("172.17.0.2");
        res_socket->established_local_addr.port = get_dst(pkt);
        res_socket->established_remote_addr.port = get_src(pkt);
        int ls_hash_val = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
        int res_hash_val = cal_hash(res_socket->established_local_addr.ip, res_socket->established_local_addr.port,
                         res_socket->established_remote_addr.ip, res_socket->established_remote_addr.port);
        res_socket->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
        established_socks[res_hash_val] = res_socket;
        queue_add(listen_queue[ls_hash_val][0], res_hash_val);
        res_socket->state = SYN_RECV;
        //synack_send(res_socket, get_seq(pkt) + 1);
    } else if(sock->state == SYN_SENT && synack_packet(pkt)) {
        if(get_seq(pkt) + 1 > sock->window.wnd_recv->expect_seq) sock->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
        if(get_ack(pkt) > sock->window.wnd_send->base) sock->window.wnd_send->base = get_ack(pkt);
        ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
        sock->state = ESTABLISHED;
        pthread_cond_signal(&timeout);
    } else if(sock->state == SYN_RECV) {
        if(syn_packet(pkt)) synack_send(sock, sock->window.wnd_send->base, sock->window.wnd_recv->expect_seq);
        else if(ack_packet(pkt)) {
            if(get_ack(pkt) > sock->window.wnd_send->base) sock->window.wnd_send->base = get_ack(pkt);
            int ls_hash_val = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port, 0, 0);
            int res_hash_val = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                                        sock->established_remote_addr.ip, sock->established_remote_addr.port);
            queue_del(listen_queue[ls_hash_val][0], res_hash_val), queue_add(listen_queue[ls_hash_val][1], res_hash_val);
            sock->state = ESTABLISHED;
            pthread_cond_signal(&timeout);
        }
    } else if(sock->state == ESTABLISHED) {
        if(fin_packet(pkt)) {
            sock->state = CLOSE_WAIT;
            if(get_seq(pkt) + 1 > sock->window.wnd_recv->expect_seq) sock->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
            ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
            while(sock->window.wnd_send->base != sock->window.wnd_send->nextseq);
            finack_send(sock);
            sock->state = LAST_ACK;  
            printf("i am ESTABLISHED\n");
        } else if(ack_packet(pkt)) {
            sock->window.wnd_send->rwnd = get_advertised_window(pkt);
            if(sock->window.wnd_send->rwnd != 0) pthread_cond_signal(&timeout);
            if(get_ack(pkt) > sock->window.wnd_send->base) {
                sock->window.wnd_send->flg_ssthresh = 1;
                if(sock->cstate == FAST_RECOVERY) {
                    sock->window.wnd_send->cwnd = sock->window.wnd_send->ssthresh;
                    sock->window.wnd_send->swnd = (sock->window.wnd_send->cwnd < sock->window.wnd_send->rwnd) ? sock->window.wnd_send->cwnd : sock->window.wnd_send->rwnd;
                    maketrace_allwindow(sock, FAST_RECOVERY);
                    sock->cstate = CONGESTION_AVOIDANCE;
                } else if(sock->cstate == SLOW_START) {
                    sock->window.wnd_send->cwnd += min2(get_ack(pkt) - sock->window.wnd_send->base, MAX_DLEN);
                    if(sock->window.wnd_send->cwnd > sock->window.wnd_send->ssthresh) sock->cstate = CONGESTION_AVOIDANCE;
                    sock->window.wnd_send->swnd = (sock->window.wnd_send->cwnd < sock->window.wnd_send->rwnd) ? sock->window.wnd_send->cwnd : sock->window.wnd_send->rwnd;
                    maketrace_allwindow(sock, SLOW_START);
                } else if(sock->cstate == CONGESTION_AVOIDANCE) {
                    int add = MAX_DLEN * MAX_DLEN / (int)sock->window.wnd_send->cwnd;
                    if(add == 0) add = 1;
                    sock->window.wnd_send->cwnd += add;
                    sock->window.wnd_send->swnd = (sock->window.wnd_send->cwnd < sock->window.wnd_send->rwnd) ? sock->window.wnd_send->cwnd : sock->window.wnd_send->rwnd;
                    maketrace_allwindow(sock, CONGESTION_AVOIDANCE);
                }
                stop_timer(sock);
                sock->window.wnd_send->retransmit = 0;
                if(sock->window.wnd_send->base != sock->window.wnd_send->nextseq) {
                    start_timer(sock);
                }
                pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock));
                sock->window.wnd_send->ack_cnt = 0;
                pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
                delete_sendlist(sock->sendlist, get_ack(pkt));
                sock->window.wnd_send->base = get_ack(pkt);
            } else {
                pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock));
                sock->window.wnd_send->ack_cnt++;
                if(sock->window.wnd_send->ack_cnt == 3) {
                    if(sock->sendlist->first) {
                        sock->window.wnd_send->retransmit = 1;
                        sendToLayer3(sock->sendlist->first->nodebuf, sock->sendlist->first->plen);
                        maketrace_send(get_seq(sock->sendlist->first->nodebuf), get_ack(sock->sendlist->first->nodebuf), get_flags(sock->sendlist->first->nodebuf), sock->sendlist->first->plen - DEFAULT_HEADER_LEN);
                        sock->window.wnd_send->ssthresh = max(2 * MAX_DLEN, sock->window.wnd_send->cwnd / 2);
                        sock->window.wnd_send->cwnd = sock->window.wnd_send->ssthresh + 3 * MAX_DLEN;
                        sock->cstate = FAST_RECOVERY;
                        sock->window.wnd_send->swnd = (sock->window.wnd_send->cwnd < sock->window.wnd_send->rwnd) ? sock->window.wnd_send->cwnd : sock->window.wnd_send->rwnd;
                        maketrace_rwnd(sock->window.wnd_send->rwnd);
                        maketrace_swnd(sock->window.wnd_send->swnd);
                        maketrace_cwnd(sock, FAST_RECOVERY, sock->window.wnd_send->cwnd);
                    }
                } else if(sock->window.wnd_send->ack_cnt > 3) {
                    sock->window.wnd_send->cwnd += MAX_DLEN;
                    sock->window.wnd_send->swnd = (sock->window.wnd_send->cwnd < sock->window.wnd_send->rwnd) ? sock->window.wnd_send->cwnd : sock->window.wnd_send->rwnd;
                    maketrace_rwnd(sock->window.wnd_send->rwnd);
                    maketrace_swnd(sock->window.wnd_send->swnd);
                    maketrace_cwnd(sock, FAST_RECOVERY, sock->window.wnd_send->cwnd);
                }
                pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
            }
        } else {
            add_recvlist(sock, sock->recvlist, pkt + DEFAULT_HEADER_LEN, get_seq(pkt), get_plen(pkt) - DEFAULT_HEADER_LEN);
        }
    } else if(sock->state == LAST_ACK) {
        if(ack_packet(pkt)) {
            sock->window.wnd_send->base = get_ack(pkt);
            sock->state = CLOSED;
            printf("i am LAST_ACK\n");
        }
    } else if(sock->state == FIN_WAIT_1) {
        if(finack_packet(pkt)) {
            if(get_seq(pkt) + 1 > sock->window.wnd_recv->expect_seq) sock->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
            ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
            sock->state = TIME_WAIT;
        } else if(ack_packet(pkt)) {
            sock->window.wnd_send->base = get_ack(pkt);
            sock->state = FIN_WAIT_2;
        } else if(fin_packet(pkt)) {
            if(get_seq(pkt) + 1 > sock->window.wnd_recv->expect_seq) sock->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
            ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
            sock->state = CLOSING;
        }
        printf("i am FIN_WAIT_1\n");
    } else if(sock->state == FIN_WAIT_2 || sock->state == TIME_WAIT) {
        if(finack_packet(pkt)) {
            if(get_seq(pkt) + 1 > sock->window.wnd_recv->expect_seq) sock->window.wnd_recv->expect_seq = get_seq(pkt) + 1;
            ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
            sock->state = TIME_WAIT;
            printf("i am FIN_WAIT_2\n");
        } else if(fin_packet(pkt) && sock->state == TIME_WAIT) {
            ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
        }
    } else if(sock->state == CLOSING) {
        if(ack_packet(pkt)) {
            sock->window.wnd_send->base = get_ack(pkt);
            sock->state = TIME_WAIT;
            printf("i am CLOSING\n");
        }
    }
    return 0;
}

int tju_close (tju_tcp_t* sock){
    //sleep(90);
    if(sock->state == ESTABLISHED) {
        fin_send(sock);
        sock->state = FIN_WAIT_1;
    }
    while(sock->state != CLOSED && sock->state != TIME_WAIT);
    if(sock->state == TIME_WAIT) {
        sleep(1);
        sock->state = CLOSED;
    }
    return 0;
}

int syn_send(tju_tcp_t* sock, int seqnum) {
    char* msg;
    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seqnum, sock->window.wnd_recv->expect_seq, 
                                                                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN, 1, 0, NULL, 0);
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    maketrace_send(seqnum, 0, SYN, 0);
    return 0;
}

int ack_send(tju_tcp_t* sock, int seq, int acknum) {
    char* msg;
    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, acknum, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK, TCP_RECVWN_SIZE - sock->received_len - sock->recvlist->tot_size, 0, NULL, 0);
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    maketrace_send(seq, acknum, ACK, 0);
    return 0;
}

int synack_send(tju_tcp_t* sock, int seqnum, int acknum) {
    char* msg;
    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seqnum, acknum, 
                                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYNACK, 1, 0, NULL, 0);
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    maketrace_send(seqnum, acknum, SYNACK, 0);
    return 0;
}

int fin_send(tju_tcp_t* sock) {
    char* msg;
    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, sock->window.wnd_send->base, 
                            sock->window.wnd_recv->expect_seq, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN, 1, 0, NULL, 0);
    sock->window.wnd_send->nextseq += 1;
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    maketrace_send(sock->window.wnd_send->base, sock->window.wnd_recv->expect_seq, FIN, 0);
    add_sendlist(sock->sendlist, msg, sock->window.wnd_send->base, DEFAULT_HEADER_LEN);
}

int finack_send(tju_tcp_t* sock) {
    char* msg;
    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, sock->window.wnd_send->base, 
                            sock->window.wnd_recv->expect_seq, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FINACK, 1, 0, NULL, 0);
    sock->window.wnd_send->nextseq += 1;
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    maketrace_send(sock->window.wnd_send->base, sock->window.wnd_recv->expect_seq, FINACK, 0);
    add_sendlist(sock->sendlist, msg, sock->window.wnd_send->base, DEFAULT_HEADER_LEN);
}

//新建一个队列
tju_queue* makequeue() {
    tju_queue* newqueue = (tju_queue*)malloc(sizeof(tju_queue));
    newqueue->size = 0;
    return newqueue;
}

//从队列now中删除目标连接
void queue_del(tju_queue* now, int tarhash) {
  for(int i = 0; i < now->size; i++) {
    if(now->array[i] == tarhash) {
      now->array[i] = now->array[now->size - 1];
      now->size -= 1;
      break;
    }
  }
}

//在队列now中增加目标连接
void queue_add(tju_queue* now, int tarhash) {
  now->array[now->size] = tarhash;
  now->size += 1;
}

//从当前开始x秒的系统时间
struct timespec* some_sec(int now_time) {
    struct timeval now;
    struct timespec* ret = (struct timespec*)malloc(sizeof(struct timespec));
    gettimeofday(&now, NULL);
    ret->tv_sec = now.tv_sec + now_time;
    ret->tv_nsec = now.tv_usec * 1000;
    return ret;
}

//从当前开始x毫秒的系统时间
struct timespec* some_msec(int now_time) {
    struct timeval now;
    struct timespec* ret = (struct timespec*)malloc(sizeof(struct timespec));
    gettimeofday(&now, NULL);
    ret->tv_sec = now.tv_sec + ((long long)now.tv_usec * 1000 + now_time * 1000000) / 1000000000;
    ret->tv_nsec = ((long long)now.tv_usec * 1000 + now_time * 1000000) % 1000000000;
    return ret;
}

//向发送缓冲区添加数据
void add_send_buf(tju_tcp_t* sock, char* buf, int len) {
    pthread_mutex_lock(&sock->send_lock);
    if(sock->sending_buf == NULL) {
        sock->sending_buf = (char*)malloc(len);
        sock->sending_len = len;
        memcpy(sock->sending_buf, buf, len);
    } else {
        sock->sending_buf = realloc(sock->sending_buf, sock->sending_len + len);
        memcpy(sock->sending_buf + sock->sending_len, buf, len);
        sock->sending_len += len;
    }
    pthread_mutex_unlock(&sock->send_lock);
}

//负责发送缓冲区
void* tju_send_thread(void* arg) {
    tju_tcp_t* send_sock = (tju_tcp_t*)arg;
    while(1) {
        if(send_sock->sending_len != 0 && send_sock->window.wnd_send->nextseq - send_sock->window.wnd_send->base < send_sock->window.wnd_send->swnd) {
            pthread_mutex_lock(&send_sock->send_lock);
            int already_send = 0;
            char* msg;
            if(send_sock->window.wnd_send->base == send_sock->window.wnd_send->nextseq) {
                start_timer(send_sock);
            }
            while(send_sock->sending_len > already_send && send_sock->window.wnd_send->nextseq - send_sock->window.wnd_send->base < send_sock->window.wnd_send->swnd) {
                uint32_t seq = send_sock->window.wnd_send->nextseq;
                int tosendlen = min(MAX_DLEN, send_sock->sending_len - already_send, send_sock->window.wnd_send->swnd - (send_sock->window.wnd_send->nextseq - send_sock->window.wnd_send->base));

                msg = create_packet_buf(send_sock->established_local_addr.port, send_sock->established_remote_addr.port, seq, send_sock->window.wnd_recv->expect_seq, 
                                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + tosendlen, NO_FLAG, 1, 0, send_sock->sending_buf + already_send, tosendlen);
                send_sock->window.wnd_send->nextseq += tosendlen;
                already_send += tosendlen;
                sendToLayer3(msg, DEFAULT_HEADER_LEN + tosendlen);
                maketrace_send(seq, send_sock->window.wnd_recv->expect_seq, NO_FLAG, tosendlen);
                add_sendlist(send_sock->sendlist, msg, seq, DEFAULT_HEADER_LEN + tosendlen);
            }
            
            if(send_sock->sending_len == already_send) {
                free(send_sock->sending_buf);
                send_sock->sending_buf = NULL;
                send_sock->sending_len = 0;
            } else {
                char* new_sending_buf = (char*)malloc(send_sock->sending_len - already_send);
                memcpy(new_sending_buf, send_sock->sending_buf + already_send, send_sock->sending_len - already_send);
                free(send_sock->sending_buf);
                send_sock->sending_buf = new_sending_buf;
                send_sock->sending_len -= already_send;
            }
            pthread_mutex_unlock(&send_sock->send_lock);
        } else if(send_sock->window.wnd_send->swnd == 0 && send_sock->sending_len > 0) { //0窗口
            //printf("i am here\n");
            char* msg;
            uint32_t seq = send_sock->window.wnd_send->nextseq;
            msg = create_packet_buf(send_sock->established_local_addr.port, send_sock->established_remote_addr.port, seq, send_sock->window.wnd_recv->expect_seq, 
                                                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + 1, NO_FLAG, 1, 0, send_sock->sending_buf, 1);
            send_sock->window.wnd_send->nextseq += 1;
            if(send_sock->sending_len == 1) {                free(send_sock->sending_buf);
                send_sock->sending_buf = NULL;
                send_sock->sending_len = 0;
            } else {
                char* new_sending_buf = (char*)malloc(send_sock->sending_len - 1);
                memcpy(new_sending_buf, send_sock->sending_buf + 1, send_sock->sending_len - 1);
                free(send_sock->sending_buf);
                send_sock->sending_buf = new_sending_buf;
                send_sock->sending_len -= 1;
            }
            sendToLayer3(msg, DEFAULT_HEADER_LEN + 1);
            maketrace_send(seq, send_sock->window.wnd_recv->expect_seq, NO_FLAG, 1);
            add_sendlist(send_sock->sendlist, msg, seq, DEFAULT_HEADER_LEN + 1);
            pthread_mutex_lock(&time_mutex);
            pthread_cond_timedwait(&timeout, &time_mutex, some_msec(200));
            pthread_mutex_unlock(&time_mutex);
        }
    }
}

//向发送链表中添加元素
void add_sendlist(tju_list* now, char* toadd, int _seq, int _len) {
    pthread_mutex_lock(&(now->list_lock));
    tju_node* newnode = (tju_node*)malloc(sizeof(tju_node));
    newnode->nodebuf = (char*)malloc(_len);
    memcpy(newnode->nodebuf, toadd, _len);
    newnode->seqnum = _seq;
    newnode->plen = _len;
    newnode->nxt = NULL;
    if(now->list_len == 0) {
        now->first = now->tail = newnode;
        now->list_len = 1;
    } else {
        now->tail->nxt = newnode;
        now->tail = newnode;
        now->list_len += 1;
    }
    pthread_mutex_unlock(&(now->list_lock));
    return;
}

//在发送链表中删除元素
void delete_sendlist(tju_list* now, int new_ack) {
    pthread_mutex_lock(&(now->list_lock));
    while(now->list_len > 0 && now->first->seqnum < new_ack) {
        if(now->list_len == 1) {
            free(now->first->nodebuf);
            free(now->first);
            now->first = now->tail = NULL;
            now->list_len = 0;
        } else {
            tju_node* todel = now->first;
            now->first = now->first->nxt;
            free(todel->nodebuf);
            free(todel);
            now->list_len -= 1;
        }
    }
    pthread_mutex_unlock(&(now->list_lock));
    return;
}

//在接收链表中增加元素并作出反应
void add_recvlist(tju_tcp_t* sock, tju_list* now, char* toadd, int _seq, int _len) {
    if(_seq < sock->window.wnd_recv->expect_seq) {
        ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
        return;
    }
    pthread_mutex_lock(&(sock->recvlist->list_lock));
    //首先观察序列中是否有该seq
    if(now->list_len) {
        for(tju_node* i = now->first;i != NULL;i = i->nxt) {
            if(i->seqnum == _seq) {
                ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
                pthread_mutex_unlock(&(sock->recvlist->list_lock));
                return;
            }
        }
    }
    //没有那么进行链表的插入
    tju_node* newnode = (tju_node*)malloc(sizeof(tju_node));
    newnode->nodebuf = (char*)malloc(_len);
    memcpy(newnode->nodebuf, toadd, _len);
    newnode->seqnum = _seq;
    newnode->plen = _len;
    newnode->nxt = NULL;
    if(now->list_len) {
        if(now->first->seqnum > _seq) {
            now->list_len += 1;
            newnode->nxt = now->first;
            now->first = newnode;
        } else {
            for(tju_node* i = now->first;i != NULL;i = i->nxt) {
                if(_seq > i->seqnum && (i->nxt == NULL || _seq < i->nxt->seqnum)) {
                    newnode->nxt = i->nxt;
                    i->nxt = newnode;
                    now->list_len += 1;
                    break;
                }
            }
        }
    } else {
        now->first = now->tail = newnode;
        now->list_len += 1;
    }
    now->tot_size += _len;
    //完成插入后判断是否可以移动至recvbuf
    if(now->first->seqnum == sock->window.wnd_recv->expect_seq) {
        while(now->list_len && now->first->seqnum == sock->window.wnd_recv->expect_seq) {
            if(sock->received_len + sock->recvlist->list_len + now->first->plen <= TCP_RECVWN_SIZE) {
                pthread_mutex_lock(&(sock->recv_lock));
                if(sock->received_buf == NULL) {
                    sock->received_buf = malloc(now->first->plen);
                } else {
                    sock->received_buf = realloc(sock->received_buf, sock->received_len + now->first->plen);
                }
                memcpy(sock->received_buf + sock->received_len, now->first->nodebuf, now->first->plen);
                sock->received_len += now->first->plen;
                sock->window.wnd_recv->expect_seq += now->first->plen;
                pthread_mutex_unlock(&(sock->recv_lock)); // 解锁*/
                maketrace_delv(sock, now->first->seqnum, now->first->plen);
            }
            tju_node* todel = now->first;
            now->tot_size -= todel->plen;
            now->first = now->first->nxt;
            free(todel->nodebuf);
            free(todel);
            now->list_len -= 1;
        }
    }
    ack_send(sock, sock->window.wnd_send->nextseq, sock->window.wnd_recv->expect_seq);
    pthread_mutex_unlock(&(sock->recvlist->list_lock));
}

//现在时间的ns形式
uint64_t nowtime_ns() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
}

//绝对值函数
uint64_t absuint64(uint64_t x, uint64_t y) {
    return x > y ? x - y : y - x;
}

//更新时间间隔
void update_timeout(tju_tcp_t* sock) {
    sock->window.wnd_send->sample_rtt = nowtime_ns() - sock->window.wnd_send->send_timepoint;
    sock->window.wnd_send->deviation_rtt = sock->window.wnd_send->deviation_rtt * 0.75 + absuint64(sock->window.wnd_send->sample_rtt, sock->window.wnd_send->estimated_rtt) * 0.25;
    sock->window.wnd_send->estimated_rtt = sock->window.wnd_send->estimated_rtt * 0.875 + sock->window.wnd_send->sample_rtt * 0.125;
    sock->window.wnd_send->timeout_interval = sock->window.wnd_send->estimated_rtt + max(sock->window.wnd_send->deviation_rtt * 4, TIME_G);
    maketrace_rtt(sock);
}

//开启时钟
void start_timer(tju_tcp_t* sock) {
    //printf("i am starting\n");
    sock->window.wnd_send->send_timepoint = nowtime_ns();
    sem_post(&sock->readytostart);
    return;
}

//关闭时钟
void stop_timer(tju_tcp_t* sock) {
    //printf("i am stopping\n");
    if(sock->window.wnd_send->retransmit == 0) update_timeout(sock); //没重传过
    pthread_cond_signal(&(sock->readytostop));
    return;
}

//定时器线程
void* tju_timer(void* arg) {
    tju_tcp_t* sock = (tju_tcp_t*)arg;
    while(1) {
        sem_wait(&sock->readytostart);
        while(1) {
            pthread_mutex_lock(&(sock->stopmutex));
            int ret = (pthread_cond_timedwait(&(sock->readytostop), &(sock->stopmutex), some_msec(sock->window.wnd_send->timeout_interval / 1000000)));
            pthread_mutex_unlock(&(sock->stopmutex));
            if(ret == 0) break;
            pthread_mutex_lock(&(sock->sendlist->list_lock));
            if(sock->sendlist->first) {
                if(sock->window.wnd_send->flg_ssthresh) {
                    sock->window.wnd_send->flg_ssthresh = 0;
                    sock->window.wnd_send->ssthresh = max(2 * MAX_DLEN, sock->window.wnd_send->cwnd / 2);
                }
                sock->window.wnd_send->cwnd = MAX_DLEN;
                sock->window.wnd_send->ack_cnt = 0;
                sock->cstate = SLOW_START;
                if(sock->window.wnd_send->swnd > sock->window.wnd_send->cwnd) sock->window.wnd_send->swnd = sock->window.wnd_send->cwnd;
                maketrace_cwnd(sock, 3, sock->window.wnd_send->cwnd);
                maketrace_swnd(sock->window.wnd_send->swnd);
                sock->window.wnd_send->retransmit = 1;
                sock->window.wnd_send->timeout_interval *= 2;
                maketrace_rtt(sock);
                sendToLayer3(sock->sendlist->first->nodebuf, sock->sendlist->first->plen);
                maketrace_send(get_seq(sock->sendlist->first->nodebuf), get_ack(sock->sendlist->first->nodebuf), get_flags(sock->sendlist->first->nodebuf), sock->sendlist->first->plen - DEFAULT_HEADER_LEN);
            } else break;
            pthread_mutex_unlock(&(sock->sendlist->list_lock));
        }
    }
}

//取3个数中的最小值
int min(int x, int y, int z) {
    if(y < x) x = y;
    if(z < x) x = z;
    return x;
}

//取2个数中的最小值
int min2(int x, int y) {
    if(x > y) return y;
    else return x;
}

//取2个数中的最大值
int max(int x, int y) {
    if(x > y) return x;
    else return y;
}

//获取当前的时间
long getCurrentTime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

//获得初始随机序列号
int getmyrandseq(int now) {
    srand(time(NULL));
    if(now == 1) return rand() % 1000 + 10000;
    else return rand() % 1500 + 5000;
}

//写SEND
void maketrace_send(int seq, int ack, int flg, int len) {
    fprintf(tracefile, "[%ld] [SEND] [seq:%d ack:%d flag:%d length:%d]\n", getCurrentTime(), seq, ack, flg, len);
    fflush(tracefile);
}

//写RECV
void maketrace_recv(int seq, int ack, int flg, int len) {
    fprintf(tracefile, "[%ld] [RECV] [seq:%d ack:%d flag:%d length:%d]\n", getCurrentTime(), seq, ack, flg, len);
    fflush(tracefile);
}

//写RWND
void maketrace_rwnd(int size) {
    fprintf(tracefile, "[%ld] [RWND] [size:%d]\n", getCurrentTime(), size);
    fflush(tracefile);
}

//写SWND
void maketrace_swnd(int size) {
    fprintf(tracefile, "[%ld] [SWND] [size:%d]\n", getCurrentTime(), size);
    fflush(tracefile);
}

//写RTT
void maketrace_rtt(tju_tcp_t* sock) {
    fprintf(tracefile, "[%ld] [RTTS] [SampleRTT:%f EstimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f]\n", getCurrentTime(),
                            sock->window.wnd_send->sample_rtt / 1000000.0, sock->window.wnd_send->estimated_rtt / 1000000.0, 
                    sock->window.wnd_send->deviation_rtt / 1000000.0, sock->window.wnd_send->timeout_interval / 1000000.0);
    fflush(tracefile);
}

//写CWND
void maketrace_cwnd(tju_tcp_t* sock, int type, int size) {
    fprintf(tracefile, "[%ld] [CWND] [type:%d size:%d]\n", getCurrentTime(), type, size);
    fflush(tracefile);
}

//写DELV
void maketrace_delv(tju_tcp_t* sock, int seq, int size) {
    fprintf(tracefile, "[%ld] [DELV] [seq:%d size:%d]\n", getCurrentTime(), seq, size);
    fflush(tracefile);
}

//写所有window
void maketrace_allwindow(tju_tcp_t* sock, int type) {
    maketrace_rwnd(sock->window.wnd_send->rwnd);
    maketrace_swnd(sock->window.wnd_send->swnd);
    maketrace_cwnd(sock, type, sock->window.wnd_send->cwnd);
}