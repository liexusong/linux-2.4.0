#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/wait.h>
#include <linux/list.h>
#endif

/* Responses from hook functions. */
#define NF_DROP   0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE  3
#define NF_REPEAT 4
#define NF_MAX_VERDICT NF_REPEAT

/* Generic cache responses from hook functions. */
#define NFC_ALTERED 0x8000
#define NFC_UNKNOWN 0x4000

#ifdef __KERNEL__
#include <linux/config.h>
#ifdef CONFIG_NETFILTER

extern void netfilter_init(void);

/* Largest hook number + 1 */
#define NF_MAX_HOOKS 8

struct sk_buff;
struct net_device;

typedef unsigned int nf_hookfn(unsigned int hooknum,
                               struct sk_buff **skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));

struct nf_hook_ops
{
    struct list_head list; // 连接相同协议和类型的钩子

    /* User fills in from here down. */
    nf_hookfn *hook;   // 钩子函数
    int pf;            // 协议类型, 如: PF_INET, PF_INET6
    int hooknum;       // 钩子所在链(LOCAL_IN, FORWARD...)
    /* Hooks are ordered in ascending priority. */
    int priority;      // 优先级(通过优先级来管理钩子的顺序)
};

struct nf_sockopt_ops
{
    struct list_head list;

    int pf;

    /* Non-inclusive ranges: use 0/0/NULL to never get called. */
    int set_optmin;
    int set_optmax;
    int (*set)(struct sock *sk, int optval, void *user, unsigned int len);

    int get_optmin;
    int get_optmax;
    int (*get)(struct sock *sk, int optval, void *user, int *len);

    /* Number of users inside set() or get(). */
    unsigned int use;
    struct task_struct *cleanup_task;
};

/* Each queued (to userspace) skbuff has one of these. */
struct nf_info
{
    /* The ops struct which sent us to userspace. */
    struct nf_hook_ops *elem;

    /* If we're sent to userspace, this keeps housekeeping info */
    int pf;
    unsigned int hook;
    struct net_device *indev, *outdev;
    int (*okfn)(struct sk_buff *);
};

/* Function to register/unregister hook points. */
int nf_register_hook(struct nf_hook_ops *reg);
void nf_unregister_hook(struct nf_hook_ops *reg);

/* Functions to register get/setsockopt ranges (non-inclusive).  You
   need to check permissions yourself! */
int nf_register_sockopt(struct nf_sockopt_ops *reg);
void nf_unregister_sockopt(struct nf_sockopt_ops *reg);

extern struct list_head nf_hooks[NPROTO][NF_MAX_HOOKS];

/* Activate hook; either okfn or kfree_skb called, unless a hook
   returns NF_STOLEN (in which case, it's up to the hook to deal with
   the consequences).

   Returns -ERRNO if packet dropped.  Zero means queued, stolen or
   accepted.
*/

/* RR:
   > I don't want nf_hook to return anything because people might forget
   > about async and trust the return value to mean "packet was ok".

   AK:
   Just document it clearly, then you can expect some sense from kernel
   coders :)
*/

/* This is gross, but inline doesn't cut it for avoiding the function
   call in fast path: gcc doesn't inline (needs value tracking?). --RR */
#ifdef CONFIG_NETFILTER_DEBUG
#define NF_HOOK nf_hook_slow
#else
// pf: 协议族名
// hook: 钩子阶段
// skb: 要过滤的数据包
// indev: 输入设备对象
// outdev: 输出设备对象
// okfn: 如果钩子函数执行成功, 那么将会调用这个函数
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn)    \
    (list_empty(&nf_hooks[(pf)][(hook)])               \
        ? (okfn)(skb)                                  \
        : nf_hook_slow((pf), (hook), (skb), (indev), (outdev), (okfn)))
#endif

int nf_hook_slow(int pf, unsigned int hook, struct sk_buff *skb,
                 struct net_device *indev, struct net_device *outdev,
                 int (*okfn)(struct sk_buff *));

/* Call setsockopt() */
int nf_setsockopt(struct sock *sk, int pf, int optval, char *opt, int len);
int nf_getsockopt(struct sock *sk, int pf, int optval, char *opt, int *len);

/* Packet queuing */
typedef int (*nf_queue_outfn_t)(struct sk_buff *skb, struct nf_info *info,
                                void *data);

extern int nf_register_queue_handler(int pf, nf_queue_outfn_t outfn, void *data);
extern int nf_unregister_queue_handler(int pf);
extern void nf_reinject(struct sk_buff *skb, struct nf_info *info,
                        unsigned int verdict);

#ifdef CONFIG_NETFILTER_DEBUG
extern void nf_dump_skb(int pf, struct sk_buff *skb);
#endif

/* FIXME: Before cache is ever used, this must be implemented for real. */
extern void nf_invalidate_cache(int pf);

#else /* !CONFIG_NETFILTER */
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn) (okfn)(skb)
#endif /*CONFIG_NETFILTER*/

/* From arch/i386/kernel/smp.c:
 *
 *    Why isn't this somewhere standard ??
 *
 * Maybe because this procedure is horribly buggy, and does
 * not deserve to live.  Think about signedness issues for five
 * seconds to see why.        - Linus
 */

/* Two signed, return a signed. */
#define SMAX(a,b) ((ssize_t)(a)>(ssize_t)(b) ? (ssize_t)(a) : (ssize_t)(b))
#define SMIN(a,b) ((ssize_t)(a)<(ssize_t)(b) ? (ssize_t)(a) : (ssize_t)(b))

/* Two unsigned, return an unsigned. */
#define UMAX(a,b) ((size_t)(a)>(size_t)(b) ? (size_t)(a) : (size_t)(b))
#define UMIN(a,b) ((size_t)(a)<(size_t)(b) ? (size_t)(a) : (size_t)(b))

/* Two unsigned, return a signed. */
#define SUMAX(a,b) ((size_t)(a)>(size_t)(b) ? (ssize_t)(a) : (ssize_t)(b))
#define SUMIN(a,b) ((size_t)(a)<(size_t)(b) ? (ssize_t)(a) : (ssize_t)(b))
#endif /*__KERNEL__*/

#endif /*__LINUX_NETFILTER_H*/
