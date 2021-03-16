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

/*

send()
   \                                                                  user space
----\---------------------------------------------------------------------------
     \                                                              kernel space
       `+--> sys_send()               BSD layer
        |--> sys_sendto()             BSD layer
        |--> sock_sendmsg()           BSD layer
        +=======================================
        |--> inet_sendmsg()           INET layer
        +=======================================
        |--> tcp_sendmsg()            TCP layer
        |--> tcp_send_skb()           TCP layer
        |--> tcp_transmit_skb()       TCP layer
        +=======================================
        |--> ip_queue_xmit()          IP layer
        |--> ip_queue_xmit2()         IP layer
        |--> ip_output()              IP layer
        |--> ip_finish_output()       IP layer
        |--> ip_finish_output2()      IP layer
        +=======================================
        |--> neigh_resolve_output()   Link layer
        |--> dev_queue_xmit()         Link layer
        +=======================================
        |--> ei_start_xmit()          Physical layer

*/
```

```c
////////////////////////////////////////////////////////////////////////////////
//                             内核接收数据包流程                               //
////////////////////////////////////////////////////////////////////////////////

/*

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

*/
```