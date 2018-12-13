/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University & Ericsson AB.
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
#ifndef _AODV_RREP_H
#define _AODV_RREP_H

#ifndef NS_NO_GLOBALS
#include <endian.h>

#include "defs.h"
#include "routing_table.h"

/* RREP Flags: */

#define RREP_ACK       0x1
#define RREP_REPAIR    0x2

typedef struct {
    u_int8_t type;
#if defined(__LITTLE_ENDIAN)//小端
    u_int16_t res1:6;
    u_int16_t a:1;
    u_int16_t r:1;
    u_int16_t prefix:5;//前缀5个bit
    u_int16_t res2:3;
#elif defined(__BIG_ENDIAN)//大端
    u_int16_t r:1;
    u_int16_t a:1;
    u_int16_t res1:6;
    u_int16_t res2:3;
    u_int16_t prefix:5;//前缀5个bit
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    u_int8_t hcnt;//从发起节点到多播节点组里产生RREP信息的节点的跳数
    u_int32_t dest_addr;//目的节点ip地址
    u_int32_t dest_seqno;//目的节点序列号
    u_int32_t orig_addr;//发起节点ip地址
    u_int32_t lifetime;//路由生命时间，单位为毫秒，在这段时间内，接收RREP的节点会认 为这条路由是有效的
} RREP;

#define RREP_SIZE sizeof(RREP)

typedef struct {
    u_int8_t type;//消息种类标志，RREP-ACK 消息的这个标志是 4
    u_int8_t reserved; //填充 0; 接收时忽略

} RREP_ack;

#define RREP_ACK_SIZE sizeof(RREP_ack)
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS
RREP *rrep_create(u_int8_t flags,//标志位
		  u_int8_t prefix,//前缀
		  u_int8_t hcnt,//跳数
		  struct in_addr dest_addr,//目的节点ip地址
		  u_int32_t dest_seqno,//目的节点序列号
		  struct in_addr orig_addr, u_int32_t life);//生成路由回复

RREP_ack *rrep_ack_create();//生成路由回复的ACK
AODV_ext *rrep_add_ext(RREP * rrep, int type, unsigned int offset,
		       int len, char *data);
void rrep_send(RREP * rrep, rt_table_t * rev_rt, rt_table_t * fwd_rt, int size);
void rrep_forward(RREP * rrep, int size, rt_table_t * rev_rt,
		  rt_table_t * fwd_rt, int ttl);
void rrep_process(RREP * rrep, int rreplen, struct in_addr ip_src,
		  struct in_addr ip_dst, int ip_ttl, unsigned int ifindex);
void rrep_ack_process(RREP_ack * rrep_ack, int rreplen, struct in_addr ip_src,
		      struct in_addr ip_dst);
#endif				/* NS_NO_DECLARATIONS */

#endif				/* AODV_RREP_H */
