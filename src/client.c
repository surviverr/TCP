// #include "tju_tcp.h"
// #include <string.h>


// int main(int argc, char **argv) {
//     // 开启仿真环境 
//     startSimulation();

//     tju_tcp_t* my_socket = tju_socket();
//     //printf("my_tcp state %d\n", my_socket->state);
    
//     tju_sock_addr target_addr;
//     target_addr.ip = inet_network("172.17.0.3");
//     target_addr.port = 1234;

//     while(tju_connect(my_socket, target_addr) == -1) my_socket->state = CLOSED;
//     //printf("my_socket state %d\n", my_socket->state);      

//     // uint32_t conn_ip;
//     // uint16_t conn_port;

//     // conn_ip = my_socket->established_local_addr.ip;
//     // conn_port = my_socket->established_local_addr.port;
//     // printf("my_socket established_local_addr ip %d port %d\n", conn_ip, conn_port);

//     // conn_ip = my_socket->established_remote_addr.ip;
//     // conn_port = my_socket->established_remote_addr.port;
//     // printf("my_socket established_remote_addr ip %d port %d\n", conn_ip, conn_port);

//     //sleep(3);

//     /*tju_send(my_socket, "hello world", 12);
//     tju_send(my_socket, "hello tju", 10);

//     char buf[2021];
//     tju_recv(my_socket, (void*)buf, 12);
//     printf("client recv %s\n", buf);

//     tju_recv(my_socket, (void*)buf, 10);
//     printf("client recv %s\n", buf);*/

//     // char buf[2021];
//     // for(int i = 10;i < 100;i++) {
//     //     //printf("i am %d\n", i);
//     //     tju_recv(my_socket, (void*)buf, 21);
//     //     printf("%d: client recv %s\n", i - 10, buf);
//     // }

//     // sleep(5);
//     // for(int i = 10;i < 100;i++) {
//     //     char test_msg[50];
//     //     sprintf(test_msg, "pass the autolab! %d ", i);
//     //     //printf("i am %d\n", i);
//     //     tju_send(my_socket, (void*)test_msg, 21);
//     // }

//     //sleep(5);
//     sleep(1);
//     tju_close(my_socket);
//     sleep(5);
//     return EXIT_SUCCESS;
// }

#include "tju_tcp.h"
#include <string.h>
#include <fcntl.h>

#define MIN_LEN 1000
#define EACHSIZE 10*MIN_LEN
#define MAXSIZE 50*MIN_LEN*MIN_LEN

// 全局变量
int t_times = 5000;

void sleep_no_wake(int sec){  
    do{          
        sec =sleep(sec);
    }while(sec > 0);             
}

int main(int argc, char **argv) {
    // 开启仿真环境 
    startSimulation();

    tju_tcp_t* my_socket = tju_socket();
    
    tju_sock_addr target_addr;
    target_addr.ip = inet_network("172.17.0.3");
    target_addr.port = 1234;

    tju_connect(my_socket, target_addr);

    //sleep_no_wake(1);

    int fd =  open("./test/rdt_send_file.txt",O_RDWR);
    if(-1 == fd) {
        return 1;
    }
    struct stat st;
    fstat(fd, &st);
    char* file_buf  = (char *)malloc(sizeof(char)*st.st_size);
    read(fd, (void *)file_buf, st.st_size );
    close(fd);

    for(int i=0; i<t_times; i++){
        char *buf = malloc(EACHSIZE);
        memset(buf, 0, EACHSIZE);
        if(i<10){
            sprintf(buf , "START####%d#", i);
        }
        else if(i<100){
            sprintf(buf , "START###%d#", i);
        }
        else if(i<1000){
            sprintf(buf , "START##%d#", i);
        }
        else if(i<10000){
            sprintf(buf , "START#%d#", i);
        }

        strcat(buf, file_buf);
        tju_send(my_socket, buf, EACHSIZE);
        free(buf);
    }

    free(file_buf);
        
    sleep_no_wake(100);
    

    return EXIT_SUCCESS;
}
