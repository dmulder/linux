/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *
 *   Author(s): Long Li <longli@microsoft.com>
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/ctype.h>
#include <linux/utsname.h>
#include <linux/mempool.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>
#include <linux/freezer.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <keys/user-type.h>
#include <net/ipv6.h>
#include <linux/parser.h>

#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_unicode.h"
#include "cifs_debug.h"
#include "cifs_fs_sb.h"
#include "ntlmssp.h"
#include "nterr.h"
#include "rfc1002pdu.h"
#include "fscache.h"

#include "cifsrdma.h"

/*
 * Per RDMA transport connection parameters
 * as defined in [MS-SMBD] 3.1.1.1
 */
static int receive_credit_max = 512;
static int send_credit_target = 512;
static int max_send_size = 8192;
static int max_fragmented_recv_size = 1024*1024;
static int max_receive_size = 8192;

// maximum number of SGEs in a RDMA I/O
static int max_send_sge = 16;
static int max_recv_sge = 16;

/* Logging functions
 * Logging are defined as classes. They can be ORed to define the actual
 * logging level via module parameter rdma_logging_class
 * e.g. cifs.rdma_logging_class=0x500 will log all log_rdma_recv() and
 * log_rdma_event()
 */
#define LOG_CREDIT			0x1
#define LOG_OUTGOING			0x2
#define LOG_INCOMING			0x4
#define LOG_RECEIVE_QUEUE		0x8
#define LOG_REASSEMBLY_QUEUE		0x10
#define LOG_CIFS_READ			0x20
#define LOG_CIFS_WRITE			0x40
#define LOG_RDMA_SEND			0x80
#define LOG_RDMA_RECV			0x100
#define LOG_KEEP_ALIVE			0x200
#define LOG_RDMA_EVENT			0x400

static unsigned int rdma_logging_class = 0;
module_param(rdma_logging_class, uint, 0644);
MODULE_PARM_DESC(rdma_logging_class,
	"Logging class for SMBD transport 0 to 512");

#define log_rdma(class, fmt, args...)					\
do {									\
	if (class & rdma_logging_class)					\
		cifs_dbg(VFS, "%s:%d " fmt, __func__, __LINE__, ##args);\
} while (0)

#define log_rdma_credit(fmt, args...)	log_rdma(LOG_CREDIT, fmt, ##args)
#define log_outgoing(fmt, args...)	log_rdma(LOG_OUTGOING, fmt, ##args)
#define log_incoming(fmt, args...)	log_rdma(LOG_INCOMING, fmt, ##args)
#define log_receive_queue(fmt, args...)		\
	log_rdma(LOG_RECEIVE_QUEUE, fmt, ##args)
#define log_reassembly_queue(fmt, args...) 	\
		log_rdma(LOG_REASSEMBLY_QUEUE, fmt, ##args)
#define log_cifs_read(fmt, args...)	log_rdma(LOG_CIFS_READ, fmt, ##args)
#define log_cifs_write(fmt, args...)	log_rdma(LOG_CIFS_WRITE, fmt, ##args)
#define log_rdma_send(fmt, args...)	log_rdma(LOG_RDMA_SEND, fmt, ##args)
#define log_rdma_recv(fmt, args...)	log_rdma(LOG_RDMA_RECV, fmt, ##args)
#define log_keep_alive(fmt, args...)	log_rdma(LOG_KEEP_ALIVE, fmt, ##args)
#define log_rdma_event(fmt, args...)	log_rdma(LOG_RDMA_EVENT, fmt, ##args)

#define log_transport_credit(info)					\
do {									\
	log_rdma_credit("receive_credits %d receive_credit_target %d "	\
			"send_credits %d send_credit_target %d\n",	\
			atomic_read(&info->receive_credits),		\
			atomic_read(&info->receive_credit_target),	\
			atomic_read(&info->send_credits),		\
			info->send_credit_target);			\
} while (0)
