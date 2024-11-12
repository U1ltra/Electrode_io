// compile using gcc -o recv_multishot recv_multishot.c -luring
// after having installed liburing-dev using sudo apt-get install liburing-dev
// alternatively, is installation failed, try installing from .deb file using sudo dpkg -i <download from ubuntu website>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <liburing.h>
#include <unistd.h>
#include <netinet/in.h>

#define PORT 12345
#define BUFFER_SIZE 1024

int main() {
    struct io_uring ring;
    struct sockaddr_in server_addr;
    int server_fd;
    int ret;

    // Initialize io_uring
    ret = io_uring_queue_init(8, &ring, 0);
    if (ret < 0) {
        perror("io_uring_queue_init");
        return 1;
    }

    // Create a socket
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        perror("socket");
        io_uring_queue_exit(&ring);
        return 1;
    }

    // Bind the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    ret = bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        perror("bind");
        close(server_fd);
        io_uring_queue_exit(&ring);
        return 1;
    }

    // Prepare recvmsg with multishot
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Could not get SQE\n");
        close(server_fd);
        io_uring_queue_exit(&ring);
        return 1;
    }

    struct msghdr msg;
    struct iovec iov;
    char buffer[BUFFER_SIZE];

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buffer;
    iov.iov_len = BUFFER_SIZE;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    io_uring_prep_recvmsg_multishot(sqe, server_fd, &msg, 0);

    // Submit and wait for completion
    ret = io_uring_submit(&ring);
    if (ret < 0) {
        perror("io_uring_submit");
        close(server_fd);
        io_uring_queue_exit(&ring);
        return 1;
    }

    struct io_uring_cqe *cqe;
    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
        perror("io_uring_wait_cqe");
    } else {
        printf("Received message of length %d\n", cqe->res);
        io_uring_cqe_seen(&ring, cqe);
    }

    // Clean up
    close(server_fd);
    io_uring_queue_exit(&ring);
    return 0;
}