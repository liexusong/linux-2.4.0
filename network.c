/*
 * Linux协议栈重要函数
 */

/*
 * 1. 上送数据包给协议栈
 */
netif_rx();


/*
 * 2. 发送数据到网络
 */
dev_queue_xmit();


////////////////////////////////////////////////////////////////////////////////
//                             应用层发送数据流程                               //
////////////////////////////////////////////////////////////////////////////////

send()
 \                                         user space
--\----------------------------------------------------
   \                                       kernel space
    \
     `+--> sys_send()               BSD layer
      |--> sys_sendto()             BSD layer
      |--> sock_sendmsg()           BSD layer
      |--> inet_sendmsg()           inet layer
      |--> tcp_sendmsg()            TCP layer
      |--> tcp_send_skb()           TCP layer
      |--> tcp_transmit_skb()       TCP layer
      |--> ip_queue_xmit()          IP layer
      |--> ip_queue_xmit2()         IP layer
      |--> ip_output()              IP layer
      |--> ip_finish_output()       IP layer
      |--> ip_finish_output2()      IP layer
      |--> neigh_resolve_output()   link layer
      +--> dev_queue_xmit()         link layer


////////////////////////////////////////////////////////////////////////////////
//                             内核接收数据包流程                               //
////////////////////////////////////////////////////////////////////////////////

