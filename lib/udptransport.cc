// -*- mode: c++; c-file-style: "k&r"; c-basic-offset: 4 -*-
/***********************************************************************
 *
 * udptransport.cc:
 *   message-passing network interface that uses UDP message delivery
 *   and libasync
 *
 * Copyright 2013-2016 Dan R. K. Ports  <drkp@cs.washington.edu>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 **********************************************************************/

#include "lib/assert.h"
#include "lib/configuration.h"
#include "lib/message.h"
#include "lib/udptransport.h"

#include <google/protobuf/message.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <sys/eventfd.h>
#include <sys/mman.h>

#include <random>
#include <cinttypes>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

const size_t MAX_UDP_MESSAGE_SIZE = 9000; // XXX
const int SOCKET_BUF_SIZE = 10485760;

const uint64_t NONFRAG_MAGIC = 0x20050318;
const uint64_t FRAG_MAGIC = 0x20101010;

// higher 48 bits for fd index
const uint64_t FDIDX_MASK = 0x0000FFFF;

#define FAST_PAXOS_DATA_LEN 12

#define QD 128
#define BUF_SHIFT 12 // 4KB
#define CQES (QD * 16)
#define BUFFERS CQES
#define CONTROLLEN 0

using std::pair;

static size_t buffer_size(struct iouring_ctx *ring_ctx_ptr)
{
	return 1U << ring_ctx_ptr->buf_shift;
}

static unsigned char *get_buffer(struct iouring_ctx *ring_ctx_ptr, int idx)
{
	return ring_ctx_ptr->buffer_base + (idx << ring_ctx_ptr->buf_shift);
}

UDPTransportAddress::UDPTransportAddress(const sockaddr_in &addr)
    : addr(addr)
{
    memset((void *)addr.sin_zero, 0, sizeof(addr.sin_zero));
}

UDPTransportAddress *
UDPTransportAddress::clone() const
{
    UDPTransportAddress *c = new UDPTransportAddress(*this);
    return c;    
}

bool operator==(const UDPTransportAddress &a, const UDPTransportAddress &b)
{
    return (memcmp(&a.addr, &b.addr, sizeof(a.addr)) == 0);
}

bool operator!=(const UDPTransportAddress &a, const UDPTransportAddress &b)
{
    return !(a == b);
}

bool operator<(const UDPTransportAddress &a, const UDPTransportAddress &b)
{
    return (memcmp(&a.addr, &b.addr, sizeof(a.addr)) < 0);
}

UDPTransportAddress
UDPTransport::LookupAddress(const specpaxos::ReplicaAddress &addr)
{
    int res;
    struct addrinfo hints;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags    = 0;
    struct addrinfo *ai;
    if ((res = getaddrinfo(addr.host.c_str(), addr.port.c_str(), &hints, &ai))) {
        Panic("Failed to resolve %s:%s: %s",
              addr.host.c_str(), addr.port.c_str(), gai_strerror(res));
    }
    if (ai->ai_addr->sa_family != AF_INET) {
        Panic("getaddrinfo returned a non IPv4 address");
    }
    UDPTransportAddress out =
              UDPTransportAddress(*((sockaddr_in *)ai->ai_addr));
    freeaddrinfo(ai);
    return out;
}

UDPTransportAddress
UDPTransport::LookupAddress(const specpaxos::Configuration &config,
                            int idx)
{
    const specpaxos::ReplicaAddress &addr = config.replica(idx);
    return LookupAddress(addr);
}

const UDPTransportAddress *
UDPTransport::LookupMulticastAddress(const specpaxos::Configuration
                                     *config)
{
    if (!config->multicast()) {
        // Configuration has no multicast address
        return NULL;
    }

    if (multicastFds.find(config) != multicastFds.end()) {
        // We are listening on this multicast address. Some
        // implementations of MOM aren't OK with us both sending to
        // and receiving from the same address, so don't look up the
        // address.
        return NULL;
    }

    UDPTransportAddress *addr =
        new UDPTransportAddress(LookupAddress(*(config->multicast())));
    return addr;
}

static void
BindToPort(int fd, const string &host, const string &port)
{
    struct sockaddr_in sin;

    if ((host == "") && (port == "any")) {
        // Set up the sockaddr so we're OK with any UDP socket
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = 0;        
    } else {
        // Otherwise, look up its hostname and port number (which
        // might be a service name)
        struct addrinfo hints;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;
        hints.ai_flags    = AI_PASSIVE;
        struct addrinfo *ai;
        int res;
        if ((res = getaddrinfo(host.c_str(), port.c_str(),
                               &hints, &ai))) {
            Panic("Failed to resolve host/port %s:%s: %s",
                  host.c_str(), port.c_str(), gai_strerror(res));
        }
        ASSERT(ai->ai_family == AF_INET);
        ASSERT(ai->ai_socktype == SOCK_DGRAM);
        if (ai->ai_addr->sa_family != AF_INET) {
            Panic("getaddrinfo returned a non IPv4 address");        
        }
        sin = *(sockaddr_in *)ai->ai_addr;
        
        freeaddrinfo(ai);
    }

    Notice("Binding to %s:%d", inet_ntoa(sin.sin_addr), htons(sin.sin_port));

    if (bind(fd, (sockaddr *)&sin, sizeof(sin)) < 0) {
        PPanic("Failed to bind to socket");
    }
}

UDPTransport::UDPTransport(double dropRate, double reorderRate,
                           int dscp, event_base *evbase)
    : dropRate(dropRate), reorderRate(reorderRate),
      dscp(dscp)
{

    lastTimerId = 0;
    lastFragMsgId = 0;

    uniformDist = std::uniform_real_distribution<double>(0.0,1.0);
    randomEngine.seed(time(NULL));
    reorderBuffer.valid = false;
    if (dropRate > 0) {
        Warning("Dropping packets with probability %g", dropRate);
    }
    if (reorderRate > 0) {
        Warning("Reordering packets with probability %g", reorderRate);
    }
    
    // Set up libevent
    event_set_log_callback(LogCallback);
    event_set_fatal_callback(FatalCallback);
    // XXX Hack for Naveen: allow the user to specify an existing
    // libevent base. This will probably not work exactly correctly
    // for error messages or signals, but that doesn't much matter...
    if (evbase) {
        libeventBase = evbase;
    } else {
        evthread_use_pthreads();
        libeventBase = event_base_new();
        evthread_make_base_notifiable(libeventBase);
    }

    // Set up signal handler
    signalEvents.push_back(evsignal_new(libeventBase, SIGTERM,
                                        SignalCallback, this));
    signalEvents.push_back(evsignal_new(libeventBase, SIGINT,
                                        SignalCallback, this));
    for (event *x : signalEvents) {
        event_add(x, NULL);
    }

    if (setup_iouring(&ring_ctx, AF_INET, false, BUF_SHIFT)) {
        PPanic("Failed to setup io_uring");
    }

}

UDPTransport::~UDPTransport()
{
    // XXX Shut down libevent?

    // for (auto kv : timers) {
    //     delete kv.second;
    // }

    // free io_uring
    struct io_uring *ring = &(ring_ctx.ring);
    io_uring_unregister_eventfd(ring);
    io_uring_queue_exit(ring);

}

void
UDPTransport::ListenOnMulticastPort(const specpaxos::Configuration
                                    *canonicalConfig)
{
    if (!canonicalConfig->multicast()) {
        // No multicast address specified
        return;
    }

    if (multicastFds.find(canonicalConfig) != multicastFds.end()) {
        // We're already listening
        return;    
    }

    int fd;
    
    // Create socket
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PPanic("Failed to create socket to listen for multicast");
    }
    
    // Put it in non-blocking mode
    if (fcntl(fd, F_SETFL, O_NONBLOCK, 1)) {
        PWarning("Failed to set O_NONBLOCK on multicast socket");
    }
    
    int n = 1;
    if (setsockopt(fd, SOL_SOCKET,
                   SO_REUSEADDR, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_REUSEADDR on multicast socket");
    }

    // Increase buffer size
    n = SOCKET_BUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET,
                   SO_RCVBUF, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_RCVBUF on socket");
    }
    if (setsockopt(fd, SOL_SOCKET,
                   SO_SNDBUF, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_SNDBUF on socket");
    }

    
    // Bind to the specified address
    BindToPort(fd,
               canonicalConfig->multicast()->host,
               canonicalConfig->multicast()->port);
    
    // Set up a libevent callback
    event *ev = event_new(libeventBase, fd,
                          EV_READ | EV_PERSIST,
                          SocketCallback, (void *)this);
    event_add(ev, NULL);
    listenerEvents.push_back(ev);

    // Record the fd
    multicastFds[canonicalConfig] = fd;
    multicastConfigs[fd] = canonicalConfig;

    Notice("Listening for multicast requests on %s:%s",
           canonicalConfig->multicast()->host.c_str(),
           canonicalConfig->multicast()->port.c_str());
}

void
UDPTransport::Register(TransportReceiver *receiver,
                       const specpaxos::Configuration &config,
                       int replicaIdx)
{
    ASSERT(replicaIdx < config.n);
    struct sockaddr_in sin;

    const specpaxos::Configuration *canonicalConfig =
        RegisterConfiguration(receiver, config, replicaIdx);

    // Create socket
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        PPanic("Failed to create socket to listen");
    }

    // Put it in non-blocking mode
    if (fcntl(fd, F_SETFL, O_NONBLOCK, 1)) {
        PWarning("Failed to set O_NONBLOCK");
    }

    // Enable outgoing broadcast traffic
    int n = 1;
    if (setsockopt(fd, SOL_SOCKET,
                   SO_BROADCAST, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_BROADCAST on socket");
    }

    if (dscp != 0) {
        n = dscp << 2;
        if (setsockopt(fd, IPPROTO_IP,
                       IP_TOS, (char *)&n, sizeof(n)) < 0) {
            PWarning("Failed to set DSCP on socket");
        }
    }
    
    // Increase buffer size
    n = SOCKET_BUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET,
                   SO_RCVBUF, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_RCVBUF on socket");
    }
    if (setsockopt(fd, SOL_SOCKET,
                   SO_SNDBUF, (char *)&n, sizeof(n)) < 0) {
        PWarning("Failed to set SO_SNDBUF on socket");
    }
    
    if (replicaIdx != -1) {
        // Registering a replica. Bind socket to the designated
        // host/port
        const string &host = config.replica(replicaIdx).host;
        const string &port = config.replica(replicaIdx).port;
        BindToPort(fd, host, port);
    } else {
        // Registering a client. Bind to any available host/port
        BindToPort(fd, "", "any");        
    }

    // Set up a libevent callback
    // event *ev = event_new(libeventBase, fd, EV_READ | EV_PERSIST,
    //                       SocketCallback, (void *)this);
    // event_add(ev, NULL);
    // listenerEvents.push_back(ev);

    // Set up a libevent callback for io_uring
    // create a eventfd
    int event_fd = eventfd(0, EFD_NONBLOCK);
    if (event_fd < 0) {
        PPanic("Failed to create eventfd");
    }
    // register the eventfd to io_uring
    if (io_uring_register_eventfd(&(ring_ctx.ring), event_fd) < 0) {
        PPanic("Failed to register eventfd");
    }
    // set up a libevent callback for the eventfd
    event *ev_eventfd = event_new(libeventBase, event_fd, EV_READ | EV_PERSIST,
                                  RingCallback, (void *)this);
    event_add(ev_eventfd, NULL);
    listenerEvents.push_back(ev_eventfd);

    int ret;
    int *fd_ptr = (int *)malloc(sizeof(int) * (idxfd_map.size() + 1));
    for (size_t i = 0; i < idxfd_map.size(); i++) {
        fd_ptr[i] = idxfd_map[i];
    }

    fd_ptr[idxfd_map.size()] = fd;
    fdidx_map[fd] = idxfd_map.size();
    idxfd_map[idxfd_map.size()] = fd;
    
    // add the new fd to the io_uring
    ret = io_uring_register_files(&ring_ctx.ring, fd_ptr, idxfd_map.size());
    if (ret < 0) {
        PPanic("Failed to register files");
    }

    ret = add_recv(&ring_ctx, fdidx_map[fd]);
    if (ret < 0) {
        PPanic("Failed to add recv");
    }

    // submit the prepared io_uring recv multishot request
    // rely on the eventfd to trigger the callback
    io_uring_submit(&ring_ctx.ring);

    // Tell the receiver its address
    socklen_t sinsize = sizeof(sin);
    if (getsockname(fd, (sockaddr *) &sin, &sinsize) < 0) {
        PPanic("Failed to get socket name");
    }
    UDPTransportAddress *addr = new UDPTransportAddress(sin);
    receiver->SetAddress(addr);

    // Update mappings
    receivers[fd] = receiver;
    fds[receiver] = fd;

    Notice("Listening on UDP port %hu", ntohs(sin.sin_port));

    // If we are registering a replica, check whether we need to set
    // up a socket to listen on the multicast port.
    //
    // Don't do this if we're registering a client.
    if (replicaIdx != -1) {
        ListenOnMulticastPort(canonicalConfig);
    }
}

static size_t SerializeMessage(const ::google::protobuf::Message &m, char **out, const void *my_buf) {
    string data = m.SerializeAsString();
    string type = m.GetTypeName();
    size_t typeLen = type.length();
    size_t dataLen = data.length();
    ssize_t totalLen = (sizeof(uint32_t) +
                       typeLen + sizeof(typeLen) +
                       dataLen + sizeof(dataLen) + FAST_PAXOS_DATA_LEN);

    char *buf = new char[totalLen];

    
    char *ptr = buf;
    *(uint32_t *)ptr = NONFRAG_MAGIC;
    ptr += sizeof(uint32_t);
    *((size_t *) ptr) = typeLen;
    ptr += sizeof(size_t);
    ASSERT(ptr-buf < totalLen);
    ASSERT(ptr+typeLen-buf < totalLen);
    memcpy(ptr, type.c_str(), typeLen);
    ptr += typeLen;

    // asd123www: my data copy.
    if (my_buf != NULL) {
        memcpy(ptr, my_buf, FAST_PAXOS_DATA_LEN);
    } else {
        memset(ptr, 0, FAST_PAXOS_DATA_LEN);
    }
    ptr += FAST_PAXOS_DATA_LEN;
    

    *((size_t *) ptr) = dataLen;
    ptr += sizeof(size_t);
    ASSERT(ptr-buf < totalLen);
    ASSERT(ptr+dataLen-buf == totalLen);
    memcpy(ptr, data.c_str(), dataLen);
    ptr += dataLen;
    
    *out = buf;
    return totalLen;
}

bool
UDPTransport::SendMessageInternal(TransportReceiver *src,
                                  const UDPTransportAddress &dst,
                                  const Message &m,
                                  bool multicast,
                                  const void *my_buf) {
    
    return sendmsg_iouring(src, dst, m, my_buf);

    sockaddr_in sin = dynamic_cast<const UDPTransportAddress &>(dst).addr;

    // Serialize message
    char *buf;
    size_t msgLen = SerializeMessage(m, &buf, my_buf);

    int fd = fds[src];
    
    // XXX All of this assumes that the socket is going to be
    // available for writing, which since it's a UDP socket it ought
    // to be.
    if (msgLen <= MAX_UDP_MESSAGE_SIZE) {
        if (sendto(fd, buf, msgLen, 0,
                   (sockaddr *)&sin, sizeof(sin)) < 0) {
            PWarning("Failed to send message");
            goto fail;
        }
    } else {
        msgLen -= sizeof(uint32_t);
        char *bodyStart = buf + sizeof(uint32_t);
        int numFrags = ((msgLen-1) / MAX_UDP_MESSAGE_SIZE) + 1;
        Notice("Sending large %s message in %d fragments",
               m.GetTypeName().c_str(), numFrags);
        uint64_t msgId = ++lastFragMsgId;
        for (size_t fragStart = 0; fragStart < msgLen;
             fragStart += MAX_UDP_MESSAGE_SIZE) {
            size_t fragLen = std::min(msgLen - fragStart,
                                      MAX_UDP_MESSAGE_SIZE);
            size_t fragHeaderLen = 2*sizeof(size_t) + sizeof(uint64_t) + sizeof(uint32_t);
            char fragBuf[fragLen + fragHeaderLen];
            char *ptr = fragBuf;
            *((uint32_t *)ptr) = FRAG_MAGIC;
            ptr += sizeof(uint32_t);
            *((uint64_t *)ptr) = msgId;
            ptr += sizeof(uint64_t);
            *((size_t *)ptr) = fragStart;
            ptr += sizeof(size_t);
            *((size_t *)ptr) = msgLen;
            ptr += sizeof(size_t);
            memcpy(ptr, &bodyStart[fragStart], fragLen);
            
            if (sendto(fd, fragBuf, fragLen + fragHeaderLen, 0,
                       (sockaddr *)&sin, sizeof(sin)) < 0) {
                PWarning("Failed to send message fragment %ld",
                         fragStart);
                goto fail;
            }
        }
    }    

    delete [] buf;
    return true;

fail:
    delete [] buf;
    return false;
}

void
UDPTransport::Run()
{
    event_base_dispatch(libeventBase);
}

static void DecodePacket(const char *buf, size_t sz, string &type, string &msg) {
    ssize_t ssz = sz;
    const char *ptr = buf;
    size_t typeLen = *((size_t *)ptr);
    ptr += sizeof(size_t);
    ASSERT(ptr-buf < ssz);
    ASSERT(ptr+typeLen-buf < ssz);
    type = string(ptr, typeLen);
    ptr += typeLen;

    // asd123www: In user-space, we can just omit these info, cause it's provided for XDP.
    ptr += FAST_PAXOS_DATA_LEN;

    size_t msgLen = *((size_t *)ptr);
    ptr += sizeof(size_t);
    ASSERT(ptr-buf < ssz);
    ASSERT(ptr+msgLen-buf <= ssz);
    msg = string(ptr, msgLen);
    ptr += msgLen;
}

void
UDPTransport::OnReadable(int fd)
{
    const int BUFSIZE = 65536;
    
    do {
        ssize_t sz;
        char buf[BUFSIZE];
        sockaddr_in sender;
        socklen_t senderSize = sizeof(sender);
        
        sz = recvfrom(fd, buf, BUFSIZE, 0,
                      (struct sockaddr *) &sender, &senderSize); // blocking
        if (sz == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                PWarning("Failed to receive message from socket");
            }
        }
        
        UDPTransportAddress senderAddr(sender);
        string msgType, msg;

        // Take a peek at the first field. If it's all zeros, this is
        // a fragment. Otherwise, we can decode it directly.
        ASSERT(sizeof(uint32_t) - sz > 0);
        uint32_t magic = *(uint32_t*)buf;
        if (magic == NONFRAG_MAGIC) {
            // Not a fragment. Decode the packet
            DecodePacket(buf+sizeof(uint32_t), sz-sizeof(uint32_t), msgType, msg);
        } else if (magic == FRAG_MAGIC) {
            // This is a fragment. Decode the header
            // asd123www: maybe this in XDP in the future.
            const char *ptr = buf;
            ptr += sizeof(uint32_t);
            ASSERT(ptr-buf < sz);
            uint64_t msgId = *((uint64_t *)ptr);
            ptr += sizeof(uint64_t);
            ASSERT(ptr-buf < sz);
            size_t fragStart = *((size_t *)ptr);
            ptr += sizeof(size_t);
            ASSERT(ptr-buf < sz);
            size_t msgLen = *((size_t *)ptr);
            ptr += sizeof(size_t);
            ASSERT(ptr-buf < sz);
            ASSERT(buf+sz-ptr == (ssize_t) std::min(msgLen-fragStart,
                                                    MAX_UDP_MESSAGE_SIZE));
            Notice("Received fragment of %zd byte packet %" PRIx64 " starting at %zd",
                   msgLen, msgId, fragStart);
            UDPTransportFragInfo &info = fragInfo[senderAddr];
            if (info.msgId == 0) {
                info.msgId = msgId;
                info.data.clear();
            }
            if (info.msgId != msgId) {
                ASSERT(msgId > info.msgId);
                Warning("Failed to reconstruct packet %" PRIx64 "", info.msgId);
                info.msgId = msgId;
                info.data.clear();
            }
            
            if (fragStart != info.data.size()) {
                Warning("Fragments out of order for packet %" PRIx64 "; "
                        "expected start %zd, got %zd",
                        msgId, info.data.size(), fragStart);
                continue; 
            }
            
            info.data.append(string(ptr, buf+sz-ptr));
            if (info.data.size() == msgLen) {
                Debug("Completed packet reconstruction");
                DecodePacket(info.data.c_str(), info.data.size(), msgType, msg); // asd123www: we havn't implement reassembly.
                info.msgId = 0;
                info.data.clear();
            } else {
                continue; // continue to receive the next fragment and deliver until full packet is reassembled.
            }
        } else {
            Warning("Received packet with bad magic number");
        }
        
        // Dispatch
        if (dropRate > 0.0) {
            double roll = uniformDist(randomEngine);
            if (roll < dropRate) {
                Debug("Simulating packet drop of message type %s",
                      msgType.c_str());
                continue;
            }
        }

        if (!reorderBuffer.valid && (reorderRate > 0.0)) {
            double roll = uniformDist(randomEngine);
            if (roll < reorderRate) {
                Debug("Simulating reorder of message type %s",
                      msgType.c_str());
                ASSERT(!reorderBuffer.valid);
                reorderBuffer.valid = true;
                reorderBuffer.addr = new UDPTransportAddress(senderAddr);
                reorderBuffer.message = msg;
                reorderBuffer.msgType = msgType;
                reorderBuffer.fd = fd;
                continue;
            }
        }

    deliver:
        // Was this received on a multicast fd?
        auto it = multicastConfigs.find(fd);
        if (it != multicastConfigs.end()) {
            // If so, deliver the message to all replicas for that
            // config, *except* if that replica was the sender of the
            // message.
            const specpaxos::Configuration *cfg = it->second;
            for (auto &kv : replicaReceivers[cfg]) {
                TransportReceiver *receiver = kv.second;
                const UDPTransportAddress &raddr = 
                    replicaAddresses[cfg].find(kv.first)->second;
                // Don't deliver a message to the sending replica
                if (raddr != senderAddr) {
                    receiver->ReceiveMessage(senderAddr, msgType, msg);
                }
            }
        } else {
            TransportReceiver *receiver = receivers[fd];
            receiver->ReceiveMessage(senderAddr, msgType, msg);
        }

        if (reorderBuffer.valid) {
            reorderBuffer.valid = false;
            msg = reorderBuffer.message;
            msgType = reorderBuffer.msgType;
            fd = reorderBuffer.fd;
            senderAddr = *(reorderBuffer.addr);
            delete reorderBuffer.addr;
            Debug("Delivering reordered packet of type %s",
                  msgType.c_str());
            goto deliver;       // XXX I am a bad person for this.
        }
    } while (0);
}

int
UDPTransport::Timer(uint64_t ms, timer_callback_t cb)
{
    UDPTransportTimerInfo *info = new UDPTransportTimerInfo();

    struct timeval tv;
    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms % 1000) * 1000;
    
    ++lastTimerId;
    
    info->transport = this;
    info->id = lastTimerId;
    info->cb = cb;
    info->ev = event_new(libeventBase, -1, 0,
                         TimerCallback, info);

    timers[info->id] = info;
    
    event_add(info->ev, &tv);
    
    return info->id;
}

bool
UDPTransport::CancelTimer(int id)
{
    UDPTransportTimerInfo *info = timers[id];

    if (info == NULL) {
        return false;
    }

    timers.erase(info->id);
    event_del(info->ev);
    event_free(info->ev);
    delete info;
    
    return true;
}

void
UDPTransport::CancelAllTimers()
{
    while (!timers.empty()) {
        auto kv = timers.begin();
        CancelTimer(kv->first);
    }
}

void
UDPTransport::OnTimer(UDPTransportTimerInfo *info)
{
    timers.erase(info->id);
    event_del(info->ev);
    event_free(info->ev);
    
    info->cb();

    delete info;
}

void
UDPTransport::SocketCallback(evutil_socket_t fd, short what, void *arg)
{
    UDPTransport *transport = (UDPTransport *)arg;
    if (what & EV_READ) {
        transport->OnReadable(fd);
    }
}

void
UDPTransport::TimerCallback(evutil_socket_t fd, short what, void *arg)
{
    UDPTransport::UDPTransportTimerInfo *info =
        (UDPTransport::UDPTransportTimerInfo *)arg;

    ASSERT(what & EV_TIMEOUT);

    info->transport->OnTimer(info);
}

void
UDPTransport::LogCallback(int severity, const char *msg)
{
    Message_Type msgType;
    switch (severity) {
    case _EVENT_LOG_DEBUG:
        msgType = MSG_DEBUG;
        break;
    case _EVENT_LOG_MSG:
        msgType = MSG_NOTICE;
        break;
    case _EVENT_LOG_WARN:
        msgType = MSG_WARNING;
        break;
    case _EVENT_LOG_ERR:
        msgType = MSG_WARNING;
        break;
    default:
        NOT_REACHABLE();
    }

    _Message(msgType, "libevent", 0, NULL, "%s", msg);
}

void
UDPTransport::FatalCallback(int err)
{
    Panic("Fatal libevent error: %d", err);
}

void
UDPTransport::SignalCallback(evutil_socket_t fd, short what, void *arg)
{
    Notice("Terminating on SIGTERM/SIGINT");
    UDPTransport *transport = (UDPTransport *)arg;
    event_base_loopbreak(transport->libeventBase);
}

void
UDPTransport::OnCompletion(struct iouring_ctx *ring_ctx_ptr, struct io_uring_cqe **cqe_ptrs, int count) 
{
    //TODO
    for (int i = 0; i < count; i++) {
        if ((cqe_ptrs[i]->user_data & FDIDX_MASK) < BUFFERS) {
            if (process_cqe_send(ring_ctx_ptr, cqe_ptrs[i])) {
                PPanic("Failed to process send cqe");
            }
        }
        else{
        // user_data << 16 is the fdidx for the socket
            if (process_cqe_recv(
                ring_ctx_ptr, cqe_ptrs[i], cqe_ptrs[i]->user_data >> 16
                )) { 
                PPanic("Failed to process recv cqe");
            }
        }
    }
}

void
UDPTransport::RingCallback(evutil_socket_t fd, short what, void *arg)
{
    UDPTransport *transport = (UDPTransport *)arg;
    struct iouring_ctx *ring_ctx_ptr = &(transport->ring_ctx);
    struct io_uring_cqe *cqes[CQES];
    int ret;
    unsigned int count;
    struct io_uring *ring = &(ring_ctx_ptr->ring);

    count = io_uring_peek_batch_cqe(ring, &cqes[0], CQES);
    if (count == 0) {
        return;
    }
    transport->OnCompletion(ring_ctx_ptr, cqes, count);
    io_uring_cq_advance(ring, count);
}

int
UDPTransport::setup_iouring(struct iouring_ctx *ring_ctx_ptr, int af, bool verbose, int buf_shift)
{
    memset(ring_ctx_ptr, 0, sizeof(*ring_ctx_ptr));
    ring_ctx_ptr->verbose = verbose;
    ring_ctx_ptr->af = af;
    ring_ctx_ptr->buf_shift = buf_shift;
    ring_ctx_ptr->send_size = BUFFERS;
    ring_ctx_ptr->send = (struct sendmsg_ctx *)malloc(sizeof(struct sendmsg_ctx) * ring_ctx_ptr->send_size);

    struct io_uring_params params;
    int ret;
    
    memset(&params, 0, sizeof(params));
    params.cq_entries = QD * 8; // make the completion queue larger than the request queue
    params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE; // IOURING_SETUP_CQSIZE in /liburing/src/include/liburing/io_uring.h
    
    ret = io_uring_queue_init_params(QD, &(ring_ctx_ptr->ring), &params);
    if (ret < 0) {
        PPanic("Failed to initialize io_uring\nNB: This requires a kernel version >= 6.0\n");
        return ret;
    }

    // TODO
    ret = setup_buffer_pool(ring_ctx_ptr);
    if (ret < 0) {
        PPanic("Failed to setup buffer pool");
        io_uring_queue_exit(&(ring_ctx_ptr->ring));
        return ret;
    }
    
    memset(&(ring_ctx_ptr->msg), 0, sizeof(struct msghdr));
    ring_ctx_ptr->msg.msg_namelen = sizeof(struct sockaddr_storage);
    ring_ctx_ptr->msg.msg_controllen = CONTROLLEN;

    return ret;
}

int 
UDPTransport::setup_buffer_pool(struct iouring_ctx *ring_ctx_ptr) {
    int ret, i;
    void *mapped;
    struct io_uring_buf_reg reg = {
        .ring_addr = 0,
        .ring_entries = BUFFERS,
        .bgid = 0
    };

    ring_ctx_ptr->buf_ring_size = (buffer_size(ring_ctx_ptr) + sizeof(struct io_uring_buf)) * BUFFERS;
    mapped = mmap(NULL, ring_ctx_ptr->buf_ring_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (mapped == MAP_FAILED) {
        PPanic("Failed to mmap buffer ring");
        return -1;
    }
    ring_ctx_ptr->buf_ring = (struct io_uring_buf_ring *)mapped;
    io_uring_buf_ring_init(ring_ctx_ptr->buf_ring);

    reg = (struct io_uring_buf_reg){
        .ring_addr = (unsigned long)ring_ctx_ptr->buf_ring,
        .ring_entries = BUFFERS,
        .bgid = 0
    };

    ring_ctx_ptr->buffer_base = (unsigned char *)ring_ctx_ptr->buf_ring + sizeof(struct io_uring_buf) * BUFFERS;

    ret = io_uring_register_buf_ring(&ring_ctx_ptr->ring, &reg, 0);
    if (ret) {
        PPanic("Failed to register buffers");
        return ret;
    }

    for (i = 0; i < BUFFERS; i++) {
        io_uring_buf_ring_add(
            ring_ctx_ptr->buf_ring, 
            get_buffer(ring_ctx_ptr, i), 
            buffer_size(ring_ctx_ptr), 
            i, 
            io_uring_buf_ring_mask(BUFFERS), 
            i
        );
    }
    io_uring_buf_ring_advance(ring_ctx_ptr->buf_ring, BUFFERS);

    return 0;
}

int UDPTransport::add_recv(struct iouring_ctx *ring_ctx_ptr, int fdidx) {
    struct io_uring_sqe *sqe;
    int ret;

    sqe = io_uring_get_sqe(&(ring_ctx_ptr->ring));
    if (!sqe) {
        io_uring_submit(&(ring_ctx_ptr->ring));
        sqe = io_uring_get_sqe(&(ring_ctx_ptr->ring));
    }
    if (!sqe) {
        return -1;
    }

    io_uring_prep_recvmsg_multishot(sqe, fdidx, &ring_ctx_ptr->msg, MSG_TRUNC);
    sqe->flags |= IOSQE_FIXED_FILE;
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;

    // store the buffer index in the high 16 bits of the user data
    uint64_t user_data = (((uint64_t)fdidx) << 16) | (BUFFERS + 1);
    sqe->user_data = user_data;

    return 0;
}

int
UDPTransport::process_cqe_send(struct iouring_ctx *ring_ctx_ptr, struct io_uring_cqe *cqe) {
    // send completion

    int send_idx = cqe->user_data & FDIDX_MASK;
    if (cqe->res < 0) {
        PPanic("sendmsg failed with %d", cqe->res);
        return -1;
    }
    if ((size_t) cqe->res != ring_ctx_ptr->send[send_idx].iov.iov_len) {
        PPanic("sendmsg failed to send all bytes %d != %zu", cqe->res, ring_ctx_ptr->send[send_idx].iov.iov_len);
        return -1;
    }

    recycle_buffer(ring_ctx_ptr, send_idx);
    return 0;
}

int
UDPTransport::process_cqe_recv(struct iouring_ctx *ring_ctx_ptr, struct io_uring_cqe *cqe, int fdidx) {
    // recv completion, handle fragmentation and deliver

    // handling io_uring recvmsg completion to prepare for delivery //
    int ret, idx;
    struct io_uring_recvmsg_out *recvmsg_out;

    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        ret = add_recv(ring_ctx_ptr, fdidx);
        if (ret) {
            PPanic("Failed to add recv");
            return ret;
        }
    }

    if (cqe->res == -ENOBUFS) { 
        return 0;
    }

    // for completions using io_uring buffer, 
    // IORING_CQE_F_BUFFER is set to indicate success
    if (!(cqe->flags & IORING_CQE_F_BUFFER) || cqe->res < 0) {
        PPanic("recvmsg failed with %d", cqe->res);
        if (cqe->res == -EFAULT || cqe->res == -EINVAL) {
            PPanic("NB: This requires a kernel version >= 6.0");
        }
        return -1;
    }

    idx = cqe->flags >> 16; // get the buffer index

    recvmsg_out = io_uring_recvmsg_validate(get_buffer(ring_ctx_ptr, idx), cqe->res, &ring_ctx_ptr->msg);
    if (!recvmsg_out) {
        PPanic("Failed to validate recvmsg");
        return -1;
    }
    if (recvmsg_out->namelen > ring_ctx_ptr->msg.msg_namelen) {
        PPanic("truncate address name");
    }
    if (recvmsg_out->flags & MSG_TRUNC) {
        unsigned int r;
        r = io_uring_recvmsg_payload_length(recvmsg_out, cqe->res, &ring_ctx_ptr->msg);
        PPanic("truncated msg need %u received %u", recvmsg_out->payloadlen, r);
    }

    if (ring_ctx_ptr->verbose) {
        struct sockaddr_in *addr = (sockaddr_in *) io_uring_recvmsg_name(recvmsg_out);
        struct sockaddr_in6 *addr6 = (sockaddr_in6 *)addr;
        char buf[INET6_ADDRSTRLEN + 1];
        const char *name;
        void *addrp;

        if (ring_ctx_ptr->af == AF_INET) {
            addrp = &addr->sin_addr;
        } else {
            addrp = &addr6->sin6_addr;
        }
        name = inet_ntop(ring_ctx_ptr->af, addrp, buf, sizeof(buf));
        if (!name) {
            name = "<INVALID>";
        }

        fprintf(stderr, "received %u bytes %d from [%s]:%d\n",
			io_uring_recvmsg_payload_length(
                recvmsg_out, cqe->res, &ring_ctx_ptr->msg),
			recvmsg_out->namelen, name, (int)ntohs(addr->sin_port));
    }

    // process the received message //
    void *pack_payload = io_uring_recvmsg_payload(recvmsg_out, &ring_ctx_ptr->msg);
    size_t pack_len = io_uring_recvmsg_payload_length(recvmsg_out, cqe->res, &ring_ctx_ptr->msg);

    string msgType, msg;
    sockaddr_in *sender = (sockaddr_in *)io_uring_recvmsg_name(recvmsg_out);
    ret = assemble_frag(pack_payload, pack_len, sender, msgType, msg);
    if (ret == 0) {
        int fd = idxfd_map[fdidx];
        UDPTransportAddress senderAddr(*sender);
        TransportReceiver *receiver = receivers[fd];
        receiver->ReceiveMessage(senderAddr, msgType, msg);
    }

    return 0;
}

int UDPTransport::assemble_frag(void *pack_payload, size_t pack_len, sockaddr_in *sender, string &msgType, string &msg) {
    ASSERT(pack_len > 0);
    ASSERT(sizeof(uint32_t) - pack_len > 0);

    char *buf = (char *)pack_payload;
    UDPTransportAddress senderAddr(*sender);

    uint32_t magic = *(uint32_t*)buf;
    if (magic == NONFRAG_MAGIC) {
        DecodePacket(buf+sizeof(uint32_t), pack_len-sizeof(uint32_t), msgType, msg);
        return 0; // ready to deliver
    } else if (magic == FRAG_MAGIC) {
        const char *ptr = buf;
        ptr += sizeof(uint32_t);
        ASSERT(ptr-buf < pack_len);
        uint64_t msgId = *((uint64_t *)ptr);
        ptr += sizeof(uint64_t);
        ASSERT(ptr-buf < pack_len);
        size_t fragStart = *((size_t *)ptr);
        ptr += sizeof(size_t);
        ASSERT(ptr-buf < pack_len);
        size_t msgLen = *((size_t *)ptr);
        ptr += sizeof(size_t);
        ASSERT(ptr-buf < pack_len);
        ASSERT(buf+pack_len-ptr == (ssize_t) std::min(msgLen-fragStart,
                                                    MAX_UDP_MESSAGE_SIZE));
        Notice("Received fragment of %zd byte packet %" PRIx64 " starting at %zd",
                msgLen, msgId, fragStart);
        UDPTransportFragInfo &info = fragInfo[senderAddr];
        if (info.msgId == 0) {
            info.msgId = msgId;
            info.data.clear();
        }
        if (info.msgId != msgId) {
            ASSERT(msgId > info.msgId);
            Warning("Failed to reconstruct packet %" PRIx64 "", info.msgId);
            info.msgId = msgId;
            info.data.clear();
        }
        
        if (fragStart != info.data.size()) {
            Warning("Fragments out of order for packet %" PRIx64 "; "
                    "expected start %zd, got %zd",
                    msgId, info.data.size(), fragStart);
            return -1; // drop the out-of-order fragment
        }
        
        info.data.append(string(ptr, buf+pack_len-ptr));
        if (info.data.size() == msgLen) {
            Debug("Completed packet reconstruction");
            DecodePacket(info.data.c_str(), info.data.size(), msgType, msg);
            info.msgId = 0;
            info.data.clear();
            return 0; // ready to deliver
        } 
    } else {
        Warning("Received packet with bad magic number");
    }

    return -1; // not ready to deliver
}

void 
UDPTransport::recycle_buffer(struct iouring_ctx *ring_ctx, int idx) {
    io_uring_buf_ring_add(
        ring_ctx->buf_ring, 
        get_buffer(ring_ctx, idx), 
        buffer_size(ring_ctx), 
        idx, 
        io_uring_buf_ring_mask(BUFFERS), 
        0
    );
    io_uring_buf_ring_advance(ring_ctx->buf_ring, 1);
}

bool
UDPTransport::sendmsg_iouring(
    TransportReceiver *src, 
    const UDPTransportAddress &dst, 
    const Message &m, 
    const void *my_buf
) {
    struct iouring_ctx *ring_ctx_ptr = &ring_ctx;
    sockaddr_in sin = dynamic_cast<const UDPTransportAddress &>(dst).addr;

    char *buf;
    size_t msgLen = SerializeMessage(m, &buf, my_buf);

    int fd = fds[src];
    int fdidx = fdidx_map[fd];
    int send_idx = ring_ctx_ptr->send_idx;
    
    struct io_uring_sqe *sqe;
    sqe = io_uring_get_sqe(&ring_ctx_ptr->ring);
    if (!sqe) {
        io_uring_submit(&ring_ctx_ptr->ring);
        sqe = io_uring_get_sqe(&ring_ctx_ptr->ring);
    }
    if (!sqe) {
        return false;
    }


    if (msgLen <= MAX_UDP_MESSAGE_SIZE) {
        ring_ctx_ptr->send[send_idx].iov = (struct iovec){
            .iov_base = buf,
            .iov_len = msgLen
        };

        ring_ctx_ptr->send[send_idx].msg.msg_name = &sin;
        ring_ctx_ptr->send[send_idx].msg.msg_namelen = sizeof(sin);
        ring_ctx_ptr->send[send_idx].msg.msg_iov = &ring_ctx_ptr->send[send_idx].iov;
        ring_ctx_ptr->send[send_idx].msg.msg_iovlen = 1;
        ring_ctx_ptr->send[send_idx].msg.msg_control = NULL;
        ring_ctx_ptr->send[send_idx].msg.msg_controllen = 0;

        io_uring_prep_sendmsg(sqe, fdidx, &ring_ctx_ptr->send[send_idx].msg, 0);
        io_uring_sqe_set_data64(sqe, send_idx);
        sqe->flags |= IOSQE_FIXED_FILE;
        
        ring_ctx_ptr->send_idx = (send_idx + 1) % ring_ctx_ptr->send_size;

    } else {
        msgLen -= sizeof(uint32_t);
        char *bodyStart = buf + sizeof(uint32_t);
        int numFrags = ((msgLen-1) / MAX_UDP_MESSAGE_SIZE) + 1;
        Notice("Sending large %s message in %d fragments",
               m.GetTypeName().c_str(), numFrags);
        uint64_t msgId = ++lastFragMsgId;
        for (size_t fragStart = 0; fragStart < msgLen;
             fragStart += MAX_UDP_MESSAGE_SIZE) {
            size_t fragLen = std::min(msgLen - fragStart,
                                      MAX_UDP_MESSAGE_SIZE);
            size_t fragHeaderLen = 2*sizeof(size_t) + sizeof(uint64_t) + sizeof(uint32_t);
            char fragBuf[fragLen + fragHeaderLen];
            char *ptr = fragBuf;
            *((uint32_t *)ptr) = FRAG_MAGIC;
            ptr += sizeof(uint32_t);
            *((uint64_t *)ptr) = msgId;
            ptr += sizeof(uint64_t);
            *((size_t *)ptr) = fragStart;
            ptr += sizeof(size_t);
            *((size_t *)ptr) = msgLen;
            ptr += sizeof(size_t);
            memcpy(ptr, &bodyStart[fragStart], fragLen);
            
            ring_ctx_ptr->send[send_idx].iov = (struct iovec){
                .iov_base = fragBuf,
                .iov_len = fragLen + fragHeaderLen
            };

            ring_ctx_ptr->send[send_idx].msg.msg_name = &sin;
            ring_ctx_ptr->send[send_idx].msg.msg_namelen = sizeof(sin);
            ring_ctx_ptr->send[send_idx].msg.msg_iov = &ring_ctx_ptr->send[send_idx].iov;
            ring_ctx_ptr->send[send_idx].msg.msg_iovlen = 1;
            ring_ctx_ptr->send[send_idx].msg.msg_control = NULL;
            ring_ctx_ptr->send[send_idx].msg.msg_controllen = 0;

            io_uring_prep_sendmsg(sqe, fdidx, &ring_ctx_ptr->send[send_idx].msg, 0);
            io_uring_sqe_set_data64(sqe, send_idx);
            sqe->flags |= IOSQE_FIXED_FILE;
            
            ring_ctx_ptr->send_idx = (send_idx + 1) % ring_ctx_ptr->send_size;
        }
    }


    io_uring_submit(&ring_ctx_ptr->ring); // TODO: can we batch the sends?

    delete [] buf;
    return true;           
}
