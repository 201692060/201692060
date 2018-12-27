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
 *****************************************************************************/

#include <sys/types.h>

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/udp.h>
#include "aodv_socket.h"
#include "timer_queue.h"
#include "aodv_rreq.h"
#include "aodv_rerr.h"
#include "aodv_rrep.h"
#include "params.h"
#include "aodv_hello.h"
#include "aodv_neighbor.h"
#include "debug.h"
#include "defs.h"

#endif				/* NS_PORT */

#ifndef NS_PORT
#define SO_RECVBUF_SIZE 256*1024

static char recv_buf[RECV_BUF_SIZE];
static char send_buf[SEND_BUF_SIZE];

extern int wait_on_reboot, hello_qual_threshold, ratelimit;

static void aodv_socket_read(int fd);

/* Seems that some libc (for example ulibc) has a bug in the provided
 * CMSG_NXTHDR() routine... redefining it here
 似乎某些libc（例如ulibc）在提供的CMSG_NXTHDR（）例程中有一个错误...在这里重新定义它*/

static struct cmsghdr *__cmsg_nxthdr_fix(void *__ctl, size_t __size,
					 struct cmsghdr *__cmsg)
{
    struct cmsghdr *__ptr;

    __ptr = (struct cmsghdr *) (((unsigned char *) __cmsg) +
				CMSG_ALIGN(__cmsg->cmsg_len));
    if ((unsigned long) ((char *) (__ptr + 1) - (char *) __ctl) > __size)
	return NULL;

    return __ptr;
}

struct cmsghdr *cmsg_nxthdr_fix(struct msghdr *__msg, struct cmsghdr *__cmsg)
{
    return __cmsg_nxthdr_fix(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

#endif				/* NS_PORT */


void NS_CLASS aodv_socket_init()
{
/*创建udp套接字并为每一个允许AODV的接口开一个套接字并相互绑定*/
#ifndef NS_PORT
    struct sockaddr_in aodv_addr;
    struct ifreq ifr;
    int i, retval = 0;
    int on = 1;
    int tos = IPTOS_LOWDELAY;
    int bufsize = SO_RECVBUF_SIZE;
    socklen_t optlen = sizeof(bufsize);

    /* Create a UDP socket 创建一个UDP套接字*/

    if (this_host.nif == 0) {
	fprintf(stderr, "No interfaces configured\n");
	exit(-1);
    }

    /* Open a socket for every AODV enabled interface 为每个启用AODV的接口打开一个套接字 */
    for (i = 0; i < MAX_NR_INTERFACES; i++) {
	if (!DEV_NR(i).enabled)
	    continue;

	/* AODV socket */
	DEV_NR(i).sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (DEV_NR(i).sock < 0) {
	    perror("");
	    exit(-1);
	}
#ifdef CONFIG_GATEWAY
	/* Data packet send socket 数据包发送套接字 */
	DEV_NR(i).psock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	if (DEV_NR(i).psock < 0) {
	    perror("");
	    exit(-1);
	}
#endif
	/* Bind the socket to the AODV port number 将套接字绑定到AODV端口号 */
	memset(&aodv_addr, 0, sizeof(aodv_addr));
	aodv_addr.sin_family = AF_INET;
	aodv_addr.sin_port = htons(AODV_PORT);
	aodv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	retval = bind(DEV_NR(i).sock, (struct sockaddr *) &aodv_addr,
		      sizeof(struct sockaddr));
/*设定套接字选项，若其中有设定失败则报错退出*/
	if (retval < 0) {
	    perror("Bind failed ");
	    exit(-1);
	}
	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BROADCAST,
		       &on, sizeof(int)) < 0) {
	    perror("SO_BROADCAST failed ");
	    exit(-1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, DEV_NR(i).ifname);

	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BINDTODEVICE,
		       &ifr, sizeof(ifr)) < 0) {
	    fprintf(stderr, "SO_BINDTODEVICE failed for %s", DEV_NR(i).ifname);
	    perror(" ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_PRIORITY,
		       &tos, sizeof(int)) < 0) {
	    perror("Setsockopt SO_PRIORITY failed ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_IP, IP_RECVTTL,
		       &on, sizeof(int)) < 0) {
	    perror("Setsockopt IP_RECVTTL failed ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_IP, IP_PKTINFO,
		       &on, sizeof(int)) < 0) {
	    perror("Setsockopt IP_PKTINFO failed ");
	    exit(-1);
	}
#ifdef CONFIG_GATEWAY
	if (setsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_BINDTODEVICE,
		       &ifr, sizeof(ifr)) < 0) {
	    fprintf(stderr, "SO_BINDTODEVICE failed for %s", DEV_NR(i).ifname);
	    perror(" ");
	    exit(-1);
	}

	bufsize = 4 * 65535;

	if (setsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_SNDBUF,
		       (char *) &bufsize, optlen) < 0) {
	    DEBUG(LOG_NOTICE, 0, "Could not set send socket buffer size");
	}
	if (getsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_SNDBUF,
		       (char *) &bufsize, &optlen) == 0) {
	    alog(LOG_NOTICE, 0, __FUNCTION__,
		 "RAW send socket buffer size set to %d", bufsize);
	}
#endif
	/* 设定接受的最大缓冲区大小 */
	for (;; bufsize -= 1024) {
	    if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_RCVBUF,
			   (char *) &bufsize, optlen) == 0) {
		alog(LOG_NOTICE, 0, __FUNCTION__,
		     "Receive buffer size set to %d", bufsize);
		break;
	    }
	    if (bufsize < RECV_BUF_SIZE) {
		alog(LOG_ERR, 0, __FUNCTION__,
		     "Could not set receive buffer size");
		exit(-1);
	    }
	}

	retval = attach_callback_func(DEV_NR(i).sock, aodv_socket_read);

	if (retval < 0) {
	    perror("register input handler failed ");
	    exit(-1);
	}
    }
#endif				/* NS_PORT */

    num_rreq = 0;
    num_rerr = 0;
}

void NS_CLASS aodv_socket_process_packet(AODV_msg * aodv_msg, int len,
					 struct in_addr src,
					 struct in_addr dst,
					 int ttl, unsigned int ifindex)
{

    /* If this was a HELLO message... Process as HELLO.
    如果这是一条HELLO消息......请像HELLO一样处理。*/
    if ((aodv_msg->type == AODV_RREP && ttl == 1 &&
	 dst.s_addr == AODV_BROADCAST)) {
	hello_process((RREP *) aodv_msg, len, ifindex);
	return;
    }

    /* Make sure we add/update neighbors */
    neighbor_add(aodv_msg, src, ifindex);

    /* Check what type of msg we received and call the corresponding
       function to handle the msg... */
    switch (aodv_msg->type) {

    case AODV_RREQ:
	rreq_process((RREQ *) aodv_msg, len, src, dst, ttl, ifindex);
	break;
    case AODV_RREP:
	DEBUG(LOG_DEBUG, 0, "Received RREP");
	rrep_process((RREP *) aodv_msg, len, src, dst, ttl, ifindex);
	break;
    case AODV_RERR:
	DEBUG(LOG_DEBUG, 0, "Received RERR");
	rerr_process((RERR *) aodv_msg, len, src, dst);
	break;
    case AODV_RREP_ACK:
	DEBUG(LOG_DEBUG, 0, "Received RREP_ACK");
	rrep_ack_process((RREP_ack *) aodv_msg, len, src, dst);
	break;
    default:
	alog(LOG_WARNING, 0, __FUNCTION__,
	     "Unknown msg type %u rcvd from %s to %s", aodv_msg->type,
	     ip_to_str(src), ip_to_str(dst));
    }
}

#ifdef NS_PORT
void NS_CLASS recvAODVUUPacket(Packet * p)//处理收到的数据包
{/*先分配缓存空间，在确认数据包是AODV并且是从其他地址发向本机，就将数据存入缓存空间，释放数据包；
 若数据包是本地生成的，就忽略掉*/
    int len, i, ttl = 0;
    struct in_addr src, dst;
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    hdr_aodvuu *ah = HDR_AODVUU(p);

    src.s_addr = ih->saddr();
    dst.s_addr = ih->daddr();
    len = ch->size() - IP_HDR_LEN;
    ttl = ih->ttl();

    AODV_msg *aodv_msg = (AODV_msg *) recv_buf;

    /* Only handle AODVUU packets 只处理AODVUU数据包 */
    assert(ch->ptype() == PT_AODVUU);

    /* Only process incoming packets 仅处理传入的数据包 */
    assert(ch->direction() == hdr_cmn::UP);

    /* Copy message to receive buffer 将消息复制到接收缓冲区 */
    memcpy(recv_buf, ah, RECV_BUF_SIZE);

    /* Deallocate packet, we have the information we need... 解除分组，我们有我们需要的信息...... */
    Packet::free(p);

    /* Ignore messages generated locally 忽略本地生成的消息 */
    for (i = 0; i < MAX_NR_INTERFACES; i++)
	if (this_host.devs[i].enabled &&
	    memcmp(&src, &this_host.devs[i].ipaddr,
		   sizeof(struct in_addr)) == 0)
	    return;

    aodv_socket_process_packet(aodv_msg, len, src, dst, ttl, NS_IFINDEX);
}
#else
static void aodv_socket_read(int fd)
{
    struct in_addr src, dst;
    int i, len, ttl = -1;
    AODV_msg *aodv_msg;
    struct dev_info *dev;
    struct msghdr msgh;
    struct cmsghdr *cmsg;
    struct iovec iov;
    char ctrlbuf[CMSG_SPACE(sizeof(int)) +
		 CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct sockaddr_in src_addr;

    dst.s_addr = -1;

    iov.iov_base = recv_buf;
    iov.iov_len = RECV_BUF_SIZE;
    msgh.msg_name = &src_addr;
    msgh.msg_namelen = sizeof(src_addr);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = ctrlbuf;
    msgh.msg_controllen = sizeof(ctrlbuf);

    len = recvmsg(fd, &msgh, 0);

    if (len < 0) {
	alog(LOG_WARNING, 0, __FUNCTION__, "receive ERROR len=%d!", len);
	return;
    }

    src.s_addr = src_addr.sin_addr.s_addr;

    /* Get the ttl and destination address from the control message 
     * 从控制信息里读取ttl值和目的地址，如果ttl值小于0，就忽略该数据包
    */
    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
	 cmsg = CMSG_NXTHDR_FIX(&msgh, cmsg)) {
	if (cmsg->cmsg_level == SOL_IP) {
	    switch (cmsg->cmsg_type) {
	    case IP_TTL:
		ttl = *(CMSG_DATA(cmsg));
		break;
	    case IP_PKTINFO:
	      {
		struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		dst.s_addr = pi->ipi_addr.s_addr;
	      }
	    }
	}
    }

    if (ttl < 0) {
	DEBUG(LOG_DEBUG, 0, "No TTL, packet ignored!");
	return;
    }

    /* Ignore messages generated locally 
     * 如果是本地生成的数据包就忽略掉
    */
    for (i = 0; i < MAX_NR_INTERFACES; i++)
	if (this_host.devs[i].enabled &&
	    memcmp(&src, &this_host.devs[i].ipaddr,
		   sizeof(struct in_addr)) == 0)
	    return;

    aodv_msg = (AODV_msg *) recv_buf;

    dev = devfromsock(fd);

    if (!dev) {
	DEBUG(LOG_ERR, 0, "Could not get device info!\n");
	return;
    }
/*把控制交给aodv_socket_process_packet函数进行消息分类和处理*/
    aodv_socket_process_packet(aodv_msg, len, src, dst, ttl, dev->ifindex);
}
#endif				/* NS_PORT */
/*设置首部信息，设置ttl,检查当前状态是否允许RREP，清楚报文的AODV部分，把要发送的消息复制到报文相应位置，
设置其他常用首部信息，设置接收方的端口号*/
void NS_CLASS aodv_socket_send(AODV_msg * aodv_msg, struct in_addr dst,
			       int len, u_int8_t ttl, struct dev_info *dev)
{
    int retval = 0;
    struct timeval now;
    /* Rate limit stuff: */

#ifndef NS_PORT

    struct sockaddr_in dst_addr;

    if (wait_on_reboot && aodv_msg->type == AODV_RREP)
	return;

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = dst;
    dst_addr.sin_port = htons(AODV_PORT);

    /* Set ttl */
    if (setsockopt(dev->sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
	alog(LOG_WARNING, 0, __FUNCTION__, "ERROR setting ttl!");
	return;
    }
#else

    /*
       NS_PORT: Sending of AODV_msg messages to other AODV-UU routing agents
       by encapsulating them in a Packet. NS_PORT：
       通过将AODV msg消息封装在数据包中，将其发送到其他AODV-UU路由代理。

       Note: This method is _only_ for sending AODV packets to other routing
       agents, _not_ for forwarding "regular" IP packets! 
       注意：此方法仅用于将AODV数据包发送到其他路由代理，而不是用于转发“常规”IP数据包！
     */

    /* If we are in waiting phase after reboot, don't send any RREPs 
    如果我们在重启后处于等待阶段，请不要发送任何RREP */
    if (wait_on_reboot && aodv_msg->type == AODV_RREP)
	return;

    /*
       NS_PORT: Don't allocate packet until now. Otherwise packet uid
       (unique ID) space is unnecessarily exhausted at the beginning of
       the simulation, resulting in uid:s starting at values greater than 0.
       NS_PORT：直到现在才分配数据包。 否则，在模拟开始时，数据包uid（唯一ID）空间不必要地耗尽，导致uid：s从大于0的值开始。
     */
    Packet *p = allocpkt();
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    hdr_aodvuu *ah = HDR_AODVUU(p);

    // Clear AODVUU part of packet 清除AODVUU数据包的一部分
    memset(ah, '\0', ah->size());

    // Copy message contents into packet 将邮件内容复制到数据包中
    memcpy(ah, aodv_msg, len);

    // Set common header fields 设置公共标题字段
    ch->ptype() = PT_AODVUU;
    ch->direction() = hdr_cmn::DOWN;
    ch->size() += len + IP_HDR_LEN;
    ch->iface() = -2;
    ch->error() = 0;
    ch->prev_hop_ = (nsaddr_t) dev->ipaddr.s_addr;

    // Set IP header fields 设置IP标头字段
    ih->saddr() = (nsaddr_t) dev->ipaddr.s_addr;
    ih->daddr() = (nsaddr_t) dst.s_addr;
    ih->ttl() = ttl;

    // Note: Port number for routing agents, not AODV port number! 注意：路由代理的端口号，而不是AODV端口号！
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;

    // Fake success
    retval = len;
#endif				/* NS_PORT */

    /* If rate limiting is enabled, check if we are sending either a
       RREQ or a RERR. In that case, drop the outgoing control packet
       if the time since last transmit of that type of packet is less
       than the allowed RATE LIMIT time... 
       如果启用了速率限制，请检查我们是否正在发送RREQ或RERR。
       在这种情况下，如果自上次传输该类型数据包的时间小于允许的RATE LIMIT时间，则丢弃传出控制数据包... */

    if (ratelimit) {

	gettimeofday(&now, NULL);

	switch (aodv_msg->type) {
	case AODV_RREQ:
	    if (num_rreq == (RREQ_RATELIMIT - 1)) {
		if (timeval_diff(&now, &rreq_ratel[0]) < 1000) {
		    DEBUG(LOG_DEBUG, 0, "RATELIMIT: Dropping RREQ %ld ms",
			  timeval_diff(&now, &rreq_ratel[0]));
#ifdef NS_PORT
		  	Packet::free(p);
#endif
		    return;
		} else {
		    memmove(rreq_ratel, &rreq_ratel[1],
			    sizeof(struct timeval) * (num_rreq - 1));
		    memcpy(&rreq_ratel[num_rreq - 1], &now,
			   sizeof(struct timeval));
		}
	    } else {
		memcpy(&rreq_ratel[num_rreq], &now, sizeof(struct timeval));
		num_rreq++;
	    }
	    break;
	case AODV_RERR:
	    if (num_rerr == (RERR_RATELIMIT - 1)) {
		if (timeval_diff(&now, &rerr_ratel[0]) < 1000) {
		    DEBUG(LOG_DEBUG, 0, "RATELIMIT: Dropping RERR %ld ms",
			  timeval_diff(&now, &rerr_ratel[0]));
#ifdef NS_PORT
		  	Packet::free(p);
#endif
		    return;
		} else {
		    memmove(rerr_ratel, &rerr_ratel[1],
			    sizeof(struct timeval) * (num_rerr - 1));
		    memcpy(&rerr_ratel[num_rerr - 1], &now,
			   sizeof(struct timeval));
		}
	    } else {
		memcpy(&rerr_ratel[num_rerr], &now, sizeof(struct timeval));
		num_rerr++;
	    }
	    break;
	}
    }

    /* If we broadcast this message we update the time of last broadcast
       to prevent unnecessary broadcasts of HELLO msg's 
       如果我们广播此消息，我们更新上次广播的时间，以防止不必要的HELLO消息广播 */
    if (dst.s_addr == AODV_BROADCAST) {

	gettimeofday(&this_host.bcast_time, NULL);

#ifdef NS_PORT
	ch->addr_type() = NS_AF_NONE;

	sendPacket(p, dst, 0.0);
#else

	retval = sendto(dev->sock, send_buf, len, 0,
			(struct sockaddr *) &dst_addr, sizeof(dst_addr));

	if (retval < 0) {

	    alog(LOG_WARNING, errno, __FUNCTION__, "Failed send to bc %s",
		 ip_to_str(dst));
	    return;
	}
#endif

    } else {

#ifdef NS_PORT
	ch->addr_type() = NS_AF_INET;
	/* We trust the decision of next hop for all AODV messages...
	 我们相信所有AODV消息的下一跳决定...... */

	if (dst.s_addr == AODV_BROADCAST)
	    sendPacket(p, dst, 0.001 * Random::uniform());
	else
	    sendPacket(p, dst, 0.0);
#else
	retval = sendto(dev->sock, send_buf, len, 0,
			(struct sockaddr *) &dst_addr, sizeof(dst_addr));

	if (retval < 0) {
	    alog(LOG_WARNING, errno, __FUNCTION__, "Failed send to %s",
		 ip_to_str(dst));
	    return;
	}
#endif
    }

    /* Do not print hello msgs... 不要打印hello消息... */
    if (!(aodv_msg->type == AODV_RREP && (dst.s_addr == AODV_BROADCAST)))
	DEBUG(LOG_INFO, 0, "AODV msg to %s ttl=%d size=%u",
	      ip_to_str(dst), ttl, retval, len);

    return;
}
/*aodv_socket_queue_msg函数把一个AODV消息存储在发送缓冲区里*/
AODV_msg *NS_CLASS aodv_socket_new_msg(void)
{
    memset(send_buf, '\0', SEND_BUF_SIZE);
    return (AODV_msg *) (send_buf);
}

/* Copy an existing AODV message to the send buffer 
将现有AODV消息复制到发送缓冲区 */
AODV_msg *NS_CLASS aodv_socket_queue_msg(AODV_msg * aodv_msg, int size)
{
    memcpy((char *) send_buf, aodv_msg, size);
    return (AODV_msg *) send_buf;
}
/*清空套接字信息并关闭它*/
void aodv_socket_cleanup(void)
{
#ifndef NS_PORT
    int i;

    for (i = 0; i < MAX_NR_INTERFACES; i++) {
	if (!DEV_NR(i).enabled)
	    continue;
	close(DEV_NR(i).sock);
    }
#endif				/* NS_PORT */
}
