
# Electrode I/O Handling:
Given the event_base parameter, the UDPTransport class is likely designed to:

- Handle I/O Asynchronously: Use non-blocking sockets and register them with an event loop to respond to I/O events as they occur.
- Event-Driven Mechanism: Depend on callbacks associated with the event_base to manage incoming and outgoing network traffic efficiently.

**some relevent functions in their implementation**
- event_new
- event_add
- event_base_new
- event_base_dispatch

# Event-based Mechanism
## What Kind of I/O Handling is UDPTransport Using?
Based on the event_base parameter, it's reasonable to assume that the UDPTransport class currently uses event-driven I/O, where:
- libevent or a similar library is utilized to monitor file descriptors (e.g., sockets) for read/write readiness.
- The event_base facilitates non-blocking I/O operations by registering callbacks that get triggered when certain conditions are met (e.g., data is available to read, a socket is ready to write).

## How Event-Driven I/O Works:
Event Loop Initialization:
- The event_base structure is created and initialized to manage the event loop.
Event Registration:
- Events (e.g., sockets for network I/O) are registered with the event_base to specify which types of events (read, write, timeout, etc.) should trigger the callbacks.
Event Loop:
- The event_base continuously waits for registered events to occur and dispatches them to the appropriate callback functions without blocking.
Callback Execution:
- When an event (e.g., a UDP packet arriving) occurs, the registered callback is executed to handle the event (e.g., reading the packet and processing it).

## How io_uring Differs:
- Direct Kernel Interaction: io_uring interacts more directly with the kernel for asynchronous I/O, bypassing some user-space event-handling overhead.
- Multiple Operations: It supports batching multiple I/O operations and reduces the number of context switches, making it faster for high-throughput scenarios.
- Event Handling: Unlike event_base, which is a user-space event loop, io_uring uses ring buffers for submission and completion queues to handle events more efficiently.

# Implementation 
- Message sending and receiving has been implemented using io_uring in the UDPTransport class. 
- Main data structure for maintaining the io_uring functionality is iouring_ctx.

### **TODO**: Remove libevent-based timeout and implement using io_uring timeout tasks
- search for `Timeout` and `Timer`, try to understand how they are set and registered in the libevent events. They are mostly done in distributed protocol class initializers. Also, only the `vr/` directory (viewstamp replicated) paxos are of our interest right not.
- the problem is these timeout events are registered in different places and re-registered sometimes. So we need to implement so that it work with the io_uring in the `UDPTransport` class.
- this is probably the function you should use [io_uring_prep_timeout()](https://man7.org/linux/man-pages/man3/io_uring_prep_timeout.3.html)

# io_uring timeout events
## How to Handle Timeouts Using io_uring:
io_uring can be used to set up timers that integrate directly with the completion queue. This means you can add a timeout operation to io_uring, and when the timer expires, it will be processed like any other I/O operation in the completion queue.

## Steps to Handle Timeout with io_uring:
Prepare the Timeout Operation:
- Use io_uring_prep_timeout() to prepare an SQE (submission queue entry) for a timeout.
- Set the duration of the timeout using struct __kernel_timespec, which specifies the time in seconds and nanoseconds.

Submit the Timeout Operation:
- Submit the prepared SQE using io_uring_submit() to make the kernel aware of the timeout operation.

Handle the Timeout Event:
- When the timeout expires, it will generate a completion event that can be processed like any other I/O operation using io_uring_wait_cqe() or io_uring_peek_cqe().

