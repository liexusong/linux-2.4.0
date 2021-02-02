inet_init(); // 初始化网络使用
netif_receive_skb();
ip_rcv_finish();    // 接收IP数据包使用
inet_skb_parm;