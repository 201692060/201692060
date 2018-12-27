/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Erik Nordström, <erik.nordstrom@it.uu.se>
 *          
 *
 *****************************************************************************/

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"	\*若NS_PORT已定义*\	
#else
#include <netinet/in.h>
#include "aodv_hello.h"
#include "aodv_timeout.h"
#include "aodv_rrep.h"
#include "aodv_rreq.h"
#include "routing_table.h"
#include "timer_queue.h"
#include "params.h"
#include "aodv_socket.h"
#include "defs.h"
#include "debug.h"	\*若NS_PORT未定义*\

extern int unidir_hack, receive_n_hellos, hello_jittering, optimized_hellos;
static struct timer hello_timer;

#endif

/* #define DEBUG_HELLO */


long NS_CLASS hello_jitter()
{
    if (hello_jittering) {
#ifdef NS_PORT
	return (long) (((float) Random::integer(RAND_MAX + 1) / RAND_MAX - 0.5)//生成-0.5~0.5之间的随机小数
		       * JITTER_INTERVAL);
#else
	return (long) (((float) random() / RAND_MAX - 0.5) * JITTER_INTERVAL);
#endif
    } else
	return 0;
}

void NS_CLASS hello_start()
{
    if (hello_timer.used)//检测hello_timer定时器是否开启，若开启表明hello信息已发送，直接返回
	    return;

    gettimeofday(&this_host.fwd_time, NULL);//获取当前时间
/*在Debug.h中宏定义的DEBUG函数第三个参数设置输出信息“Starting to send HELLOs”表示此刻准备要发送hello消息。
随后调用的timer_init函数的传入三个参数，分别是&hello_timer:启动hello_timer定时器；&NS_CLASS_ hello_send: hello_send; 
NULL:显然此处不需要参数*/
    DEBUG(LOG_DEBUG, 0, "Starting to send HELLOs!");
    timer_init(&hello_timer, &NS_CLASS hello_send, NULL);//定时

    hello_send(NULL);
}
/*当当前节点没有任何活跃路径与相邻节点相连时执行hello_stop函数
 首先调用DEBUG函数输出，接下来移除绑定的计时器hello_timer*/
void NS_CLASS hello_stop()
{
    DEBUG(LOG_DEBUG, 0,
	  "No active forwarding routes - stopped sending HELLOs!");
    timer_remove(&hello_timer);//停止定时
}

void NS_CLASS hello_send(void *arg)
{
    RREP *rrep;
    AODV_ext *ext = NULL;
    u_int8_t flags = 0;
    struct in_addr dest;//保存目的节点地址
    long time_diff, jitter;
    struct timeval now;//记录当前时间
    int msg_size = RREP_SIZE;
    int i;

    gettimeofday(&now, NULL);//得到当前的时间，写入now中
/*判断若当前时间和最后一个hello消息发送的时间差大于路由超时时间，可以断定当前节点没有任何一条活跃路径与相邻节点相连
 执行hello_stop()*/
    if (optimized_hellos &&
	timeval_diff(&now, &this_host.fwd_time) > ACTIVE_ROUTE_TIMEOUT/*若超时*/) {//超时则停止发送hello消息
	hello_stop();
	return;
    }
/*获取当前时间与最后一个广播分组发送时的时间差*/
    time_diff = timeval_diff(&now, &this_host.bcast_time);
    jitter = hello_jitter();

    /* This check will ensure we don't send unnecessary hello msgs, in case
       we have sent other bcast msgs within HELLO_INTERVAL 
       这个检查将确保我们不发送不必要的hello消息，以防我们在HELLO_INTERVAL中发送其他bcast消息 */
    if (time_diff >= HELLO_INTERVAL) {

	for (i = 0; i < MAX_NR_INTERFACES; i++) {
	    if (!DEV_NR(i).enabled)
		continue;
#ifdef DEBUG_HELLO /*程序判断如果宏定义了DEBUG_HELLO则显示广播hello消息*/
	    DEBUG(LOG_DEBUG, 0, "sending Hello to 255.255.255.255");
#endif /*实现了hello消息的创建，包括提供目标节点IP地址：DEV_NR(i).ipaddr、目标节点序列号、源节点IP地址、以及消息的生命周期*/
	    rrep = rrep_create(flags, 0, 0, DEV_NR(i).ipaddr,   //rrep: RouteReply,路线回复
			       this_host.seqno,
			       DEV_NR(i).ipaddr,
			       ALLOWED_HELLO_LOSS * HELLO_INTERVAL);

	    /* Assemble a RREP extension which contain our neighbor set... 组装包含我们的邻居集的RREP扩展 */
	    if (unidir_hack) {
		int i;

		if (ext)
		    ext = AODV_EXT_NEXT(ext);
		else
		    ext = (AODV_ext *) ((char *) rrep + RREP_SIZE);

		ext->type = RREP_HELLO_NEIGHBOR_SET_EXT;
		ext->length = 0;

		for (i = 0; i < RT_TABLESIZE; i++) {
		    list_t *pos;
		    list_foreach(pos, &rt_tbl.tbl[i]) {//对list中每个元素进行操作
			rt_table_t *rt = (rt_table_t *) pos;
			/* If an entry has an active hello timer, we assume
			   that we are receiving hello messages from that
			   node... 如果条目具有活动的hello计时器，我们假设我们从该节点接收hello消息 */
			if (rt->hello_timer.used) {
#ifdef DEBUG_HELLO
			    DEBUG(LOG_INFO, 0,
				  "Adding %s to hello neighbor set ext",
				  ip_to_str(rt->dest_addr));
#endif
			   memcpy(AODV_EXT_DATA(ext), &rt->dest_addr,     //内存拷贝函数
				   sizeof(struct in_addr));
			    ext->length += sizeof(struct in_addr);
			}
		    }
		}
		if (ext->length)
		    msg_size = RREP_SIZE + AODV_EXT_SIZE(ext);
	    }
	    dest.s_addr = AODV_BROADCAST;
	    aodv_socket_send((AODV_msg *) rrep, dest, msg_size, 1, &DEV_NR(i));
	}

	timer_set_timeout(&hello_timer, HELLO_INTERVAL + jitter);
    } else {
	if (HELLO_INTERVAL - time_diff + jitter < 0)
	    timer_set_timeout(&hello_timer,
			      HELLO_INTERVAL - time_diff - jitter);
	else
	    timer_set_timeout(&hello_timer,
			      HELLO_INTERVAL - time_diff + jitter);
    }
}


/* Process a hello message 处理问候消息 */
void NS_CLASS hello_process(RREP * hello, int rreplen, unsigned int ifindex)
{
    u_int32_t hello_seqno, timeout, hello_interval = HELLO_INTERVAL; //hello_seqno:记录hello消息的节点序列号
    u_int8_t state, flags = 0; //hello_interval:设置hello消息周期为HELLO_INTERVAL
    struct in_addr ext_neighbor, hello_dest; //hello_dest:记录hello消息目的节点的IP地址
    rt_table_t *rt;
    AODV_ext *ext = NULL;
    int i;
    struct timeval now; //记录当前时间

    gettimeofday(&now, NULL);//获取当前时间

    hello_dest.s_addr = hello->dest_addr; //设置hello_dest的值为接收到hello消息的目的节点
    hello_seqno = ntohl(hello->dest_seqno);//（将一个32位数由网络字节顺序转换为主机字节顺序）设置hello_seqno的值为hello消息的序列号

    rt = rt_table_find(hello_dest);

    if (rt)
	flags = rt->flags;

    if (unidir_hack)
	flags |= RT_UNIDIR;

    /* Check for hello interval extension: 检查hello interval扩展 */
    ext = (AODV_ext *) ((char *) hello + RREP_SIZE);

    while (rreplen > (int) RREP_SIZE) {
	switch (ext->type) {
	case RREP_HELLO_INTERVAL_EXT:
	    if (ext->length == 4) {
		memcpy(&hello_interval, AODV_EXT_DATA(ext), 4);
		hello_interval = ntohl(hello_interval);
#ifdef DEBUG_HELLO
		DEBUG(LOG_INFO, 0, "Hello extension interval=%lu!",
		      hello_interval);
#endif

	    } else
		alog(LOG_WARNING, 0,
		     __FUNCTION__, "Bad hello interval extension!");
	    break;
	case RREP_HELLO_NEIGHBOR_SET_EXT:

#ifdef DEBUG_HELLO
	    DEBUG(LOG_INFO, 0, "RREP_HELLO_NEIGHBOR_SET_EXT");
#endif
	    for (i = 0; i < ext->length; i = i + 4) {
		ext_neighbor.s_addr =
		    *(in_addr_t *) ((char *) AODV_EXT_DATA(ext) + i);

		if (ext_neighbor.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr)//DEV 开发；IFINDEX 索引序号
		    flags &= ~RT_UNIDIR;
	    }
	    break;
	default:
	    alog(LOG_WARNING, 0, __FUNCTION__,
		 "Bad extension!! type=%d, length=%d", ext->type, ext->length);
	    ext = NULL;
	    break;
	}
	if (ext == NULL)
	    break;

	rreplen -= AODV_EXT_SIZE(ext);
	ext = AODV_EXT_NEXT(ext);
    }

#ifdef DEBUG_HELLO
    DEBUG(LOG_DEBUG, 0, "rcvd HELLO from %s, seqno %lu",
	  ip_to_str(hello_dest), hello_seqno);
#endif
    /* This neighbor should only be valid after receiving 3
       consecutive hello messages... 该邻居只有在收到3个连续的问候消息后才有效 */
    if (receive_n_hellos)
	state = INVALID;//INVALID 无效
    else
	state = VALID;//VALID 有效

    timeout = ALLOWED_HELLO_LOSS/*允许丢失hello数*/ * hello_interval + ROUTE_TIMEOUT_SLACK/*路由超时延迟*/;

    if (!rt) {
	/* No active or expired route in the routing table. So we add a
	   new entry... 路由表中没有活动路由或过期路由。 所以我们添加一个新表项 */

	rt = rt_table_insert(hello_dest, hello_dest, 1,
			     hello_seqno, timeout, state, flags, ifindex);//创建一个新表项

	if (flags & RT_UNIDIR) {
	    DEBUG(LOG_INFO, 0, "%s new NEIGHBOR, link UNI-DIR",
		  ip_to_str(rt->dest_addr));
	} else {
	    DEBUG(LOG_INFO, 0, "%s new NEIGHBOR!", ip_to_str(rt->dest_addr));
	}
	rt->hello_cnt = 1;

    } else {
/*当路由表中已有活跃的表项时，这条路径的生命周期应该增加，至少为：ALLOWED_HELLO_LOSS*hello_interval.
 这条通向临近节点的路由必须包含hello消息中最新的目的序列号*/
	if ((flags & RT_UNIDIR) && rt->state == VALID && rt->hcnt > 1) {
	    goto hello_update;
	}

	if (receive_n_hellos && rt->hello_cnt < (receive_n_hellos - 1)) {
	    if (timeval_diff(&now, &rt->last_hello_time) <
		(long) (hello_interval + hello_interval / 2))
		rt->hello_cnt++;
	    else
		rt->hello_cnt = 1;

	    memcpy(&rt->last_hello_time, &now, sizeof(struct timeval));
	    return;
	}
	rt_table_update(rt, hello_dest, 1, hello_seqno, timeout, VALID, flags);
    }

  hello_update:

    hello_update_timeout(rt, &now, ALLOWED_HELLO_LOSS * hello_interval);
    return;
}


#define HELLO_DELAY 50		/* The extra time we should allow an hello
				   message to take (due to processing) before
				   assuming lost . 
				   在假设丢失之前我们应该允许一个hello消息（由于处理）的额外时间*/

NS_INLINE void NS_CLASS hello_update_timeout(rt_table_t * rt,
					     struct timeval *now, long time)
{
    timer_set_timeout(&rt->hello_timer, time + HELLO_DELAY);
    memcpy(&rt->last_hello_time, now, sizeof(struct timeval));
}
