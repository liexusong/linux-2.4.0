```c
/*
 * Linux协议栈重要函数
 */

/*
 * 1. 上送数据包给协议栈
 */
netif_rx();
```

```c
/*
 * 2. 发送数据到网络
 */
dev_queue_xmit();
```

```c
////////////////////////////////////////////////////////////////////////////////
//                             应用层发送数据流程                               //
////////////////////////////////////////////////////////////////////////////////

send()
   \                                                                  user space
----\---------------------------------------------------------------------------
     \                                                              kernel space
       `+----------------------------------------+ BSD layer
        | sys_send()                             |
        | sys_sendto()                           |
        | sock_sendmsg()                         |
        v----------------------------------------+ INET layer
        | inet_sendmsg()                         |
        v----------------------------------------+ TCP layer
        | tcp_sendmsg()                          |
        | tcp_send_skb()                         |
        | tcp_transmit_skb()                     |
        v----------------------------------------+ IP layer
        | ip_queue_xmit()                        |
        | ip_queue_xmit2()                       |
        | ip_output()                            |
        | ip_finish_output()                     |
        | ip_finish_output2()                    |
        v----------------------------------------+ Link layer
        | neigh_resolve_output()                 |
        | dev_queue_xmit()                       |
        v----------------------------------------+ Physical layer
        | ei_start_xmit()                        |
        +----------------------------------------+
                   |
                   v
            +--------------+
            |  networking  |
            +--------------+
```

```c
////////////////////////////////////////////////////////////////////////////////
//                             内核接收数据包流程                               //
////////////////////////////////////////////////////////////////////////////////

                [Network Card Interrupt]
                           |
                           @
                +--> ei_interrupt() -----------------.
                |--> ei_receive()                     \_____> top half
                |--> netif_rx()                       /
                |--> __skb_queue_tail() _____________/
                \
                 +----------> input_pkt_queue
                                    /
                                   /  __skb_dequeue()
                  .-------<-------+
                  |
                  |--> net_rx_action() ------------.
                  |--> ip_rcv()                     \
                  |--> ip_rcv_finish()               \
                  |--> ip_local_deliver()             \_____> bottom half
                  |--> ip_local_deliver_finish()      /
                  |--> tcp_v4_rcv()                  /
                  |--> tcp_v4_do_rcv()              /
                  +--> tcp_rcv_established() ______/
                               |
                               |
                               `---> __skb_queue_tail(sk->receive_queue, skb)
                                            \
                                             + skb = skb_peek(sk->receive_queue)
                                             ^
                                             |
                        +--------------------+
                       /
                      +
                      |--> tcp_recvmsg()
                      |--> inet_recvmsg()
                      |--> sock_recvmsg()
                      |--> sys_recvfrom()
                      +--> sys_recv()
                               ^                                    kernel space
-------------------------------|------------------------------------------------
                               |                                      user space
                             recv()

```