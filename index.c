
/*************** memory manager ***************/

sys_fork();
do_page_fault();

/***************** networking *****************/

open_softirq();
ip_queue_xmit();
ip_build_xmit();
ip_output();
dev_queue_xmit();
ei_interrupt();

/**********************************************/