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

static struct cifs_rdma_response* get_receive_buffer(
		struct cifs_rdma_info *info);
static void put_receive_buffer(
		struct cifs_rdma_info *info,
		struct cifs_rdma_response *response);
static int allocate_receive_buffers(struct cifs_rdma_info *info, int num_buf);
static void destroy_receive_buffers(struct cifs_rdma_info *info);

static int cifs_rdma_post_recv(
		struct cifs_rdma_info *info,
		struct cifs_rdma_response *response);

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

/* Upcall from RDMA CM */
static int cifs_rdma_conn_upcall(
		struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct cifs_rdma_info *info = id->context;

	log_rdma_event("event=%d status=%d\n", event->event, event->status);

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		info->ri_rc = 0;
		complete(&info->ri_done);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		info->ri_rc = -EHOSTUNREACH;
		complete(&info->ri_done);
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		info->ri_rc = -ENETUNREACH;
		complete(&info->ri_done);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		log_rdma_event("connected event=%d\n", event->event);
		info->connect_state = event->event;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		break;

	default:
		break;
	}

	return 0;
}

/* Upcall from RDMA QP */
static void
cifs_rdma_qp_async_error_upcall(struct ib_event *event, void *context)
{
	struct cifs_rdma_info *info = context;
	log_rdma_event("%s on device %s info %p\n",
		ib_event_msg(event->event), event->device->name, info);

	switch (event->event)
	{
	case IB_EVENT_CQ_ERR:
	case IB_EVENT_QP_FATAL:
	case IB_EVENT_QP_REQ_ERR:
	case IB_EVENT_QP_ACCESS_ERR:

	default:
		break;
	}
}

/* Called from softirq, when recv is done */
static void recv_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct smbd_data_transfer *data_transfer;
	struct cifs_rdma_response *response =
		container_of(wc->wr_cqe, struct cifs_rdma_response, cqe);
	struct cifs_rdma_info *info = response->info;

	log_rdma_recv("response=%p type=%d wc status=%d wc opcode %d "
		      "byte_len=%d pkey_index=%x\n",
		response, response->type, wc->status, wc->opcode,
		wc->byte_len, wc->pkey_index);

	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_RECV) {
		log_rdma_recv("wc->status=%d opcode=%d\n",
			wc->status, wc->opcode);
		goto error;
	}

	ib_dma_sync_single_for_cpu(
		wc->qp->device,
		response->sge.addr,
		response->sge.length,
		DMA_FROM_DEVICE);

	switch(response->type) {
	case SMBD_TRANSFER_DATA:
		data_transfer = (struct smbd_data_transfer *) response->packet;
		atomic_dec(&info->receive_credits);
		atomic_set(&info->receive_credit_target,
			le16_to_cpu(data_transfer->credits_requested));
		atomic_add(le16_to_cpu(data_transfer->credits_granted),
			&info->send_credits);

		log_incoming("data flags %d data_offset %d data_length %d "
			     "remaining_data_length %d\n",
			le16_to_cpu(data_transfer->flags),
			le32_to_cpu(data_transfer->data_offset),
			le32_to_cpu(data_transfer->data_length),
			le32_to_cpu(data_transfer->remaining_data_length));

		log_transport_credit(info);

		// process sending queue on new credits
		if (atomic_read(&info->send_credits))
			wake_up(&info->wait_send_queue);

		// process receive queue
		if (le32_to_cpu(data_transfer->data_length)) {
			if (info->full_packet_received) {
				response->first_segment = true;
			}

			if (le32_to_cpu(data_transfer->remaining_data_length))
				info->full_packet_received = false;
			else
				info->full_packet_received = true;

			goto queue_done;
		}

		// if we reach here, this is an empty packet, finish it
		break;

	default:
		log_rdma_recv("unexpected response type=%d\n", response->type);
	}

error:
	put_receive_buffer(info, response);

queue_done:
	if (atomic_dec_and_test(&info->recv_pending)) {
		wake_up(&info->wait_recv_pending);
	}

	return;
}

static struct rdma_cm_id* cifs_rdma_create_id(
		struct cifs_rdma_info *info, struct sockaddr *dstaddr)
{
	struct rdma_cm_id *id;
	int rc;
	struct sockaddr_in *addr_in = (struct sockaddr_in*) dstaddr;
	__be16 *sport;

	log_rdma_event("connecting to IP %pI4 port %d\n",
		&addr_in->sin_addr, ntohs(addr_in->sin_port));

	id = rdma_create_id(&init_net, cifs_rdma_conn_upcall, info,
		RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id)) {
		rc = PTR_ERR(id);
		log_rdma_event("rdma_create_id() failed %i\n", rc);
		return id;
	}

	if (dstaddr->sa_family == AF_INET6)
		sport = &((struct sockaddr_in6 *)dstaddr)->sin6_port;
	else
		sport = &((struct sockaddr_in *)dstaddr)->sin_port;

	*sport = htons(445);
try_again:
	init_completion(&info->ri_done);
	info->ri_rc = -ETIMEDOUT;
	rc = rdma_resolve_addr(id, NULL, (struct sockaddr*)dstaddr, 5000);
	if (rc) {
		log_rdma_event("rdma_resolve_addr() failed %i\n", rc);
		goto out;
	}
	wait_for_completion_interruptible_timeout(
		&info->ri_done, msecs_to_jiffies(8000));
	rc = info->ri_rc;
	if (rc) {
		log_rdma_event("rdma_resolve_addr() completed %i\n", rc);
		goto out;
	}

	info->ri_rc = -ETIMEDOUT;
	rc = rdma_resolve_route(id, 5000);
	if (rc) {
		log_rdma_event("rdma_resolve_route() failed %i\n", rc);
		goto out;
	}
	wait_for_completion_interruptible_timeout(
		&info->ri_done, msecs_to_jiffies(8000));
	rc = info->ri_rc;
	if (rc) {
		log_rdma_event("rdma_resolve_route() completed %i\n", rc);
		goto out;
	}

	return id;

out:
	// try port number 5445 if port 445 doesn't work
	if (*sport == htons(445)) {
		*sport = htons(5445);
		goto try_again;
	}
	rdma_destroy_id(id);
	return ERR_PTR(rc);
}

static int cifs_rdma_ia_open(
		struct cifs_rdma_info *info, struct sockaddr *dstaddr)
{
	int rc;

	info->id = cifs_rdma_create_id(info, dstaddr);
	if (IS_ERR(info->id)) {
		rc = PTR_ERR(info->id);
		goto out1;
	}

	info->pd = ib_alloc_pd(info->id->device, 0);
	if (IS_ERR(info->pd)) {
		rc = PTR_ERR(info->pd);
		log_rdma_event("ib_alloc_pd() returned %d\n", rc);
		goto out2;
	}

	return 0;

out2:
	rdma_destroy_id(info->id);
	info->id = NULL;

out1:
	return rc;
}

/*
 * Post a receive request to the transport
 * The remote peer can only send data when a receive is posted
 * The interaction is controlled by send/recieve credit system
 */
static int cifs_rdma_post_recv(struct cifs_rdma_info *info, struct cifs_rdma_response *response)
{
	struct ib_recv_wr recv_wr, *recv_wr_fail=NULL;
	int rc = -EIO;

	response->sge.addr = ib_dma_map_single(info->id->device, response->packet,
				info->max_receive_size, DMA_FROM_DEVICE);
	if (ib_dma_mapping_error(info->id->device, response->sge.addr))
		return rc;

	response->sge.length = info->max_receive_size;
	response->sge.lkey = info->pd->local_dma_lkey;

	response->cqe.done = recv_done;

	recv_wr.wr_cqe = &response->cqe;
	recv_wr.next = NULL;
	recv_wr.sg_list = &response->sge;
	recv_wr.num_sge = 1;

	atomic_inc(&info->recv_pending);
	rc = ib_post_recv(info->id->qp, &recv_wr, &recv_wr_fail);
	if (rc) {
		ib_dma_unmap_single(info->id->device, response->sge.addr,
				    response->sge.length, DMA_FROM_DEVICE);

		log_rdma_recv("ib_post_recv failed rc=%d\n", rc);
		atomic_dec(&info->recv_pending);
	}

	return rc;
}

/*
 * Receive buffer operations.
 * For each remote send, we need to post a receive. The receive buffers are
 * pre-allocated in advance.
 */
static struct cifs_rdma_response* get_receive_buffer(struct cifs_rdma_info *info)
{
	struct cifs_rdma_response *ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&info->receive_queue_lock, flags);
	if (!list_empty(&info->receive_queue)) {
		ret = list_first_entry(
			&info->receive_queue,
			struct cifs_rdma_response, list);
		list_del(&ret->list);
		info->count_receive_buffer--;
		info->count_get_receive_buffer++;
	}
	spin_unlock_irqrestore(&info->receive_queue_lock, flags);

	return ret;
}

static void put_receive_buffer(
	struct cifs_rdma_info *info, struct cifs_rdma_response *response)
{
	unsigned long flags;

	ib_dma_unmap_single(info->id->device, response->sge.addr,
		response->sge.length, DMA_FROM_DEVICE);

	spin_lock_irqsave(&info->receive_queue_lock, flags);
	list_add_tail(&response->list, &info->receive_queue);
	info->count_receive_buffer++;
	info->count_put_receive_buffer++;
	spin_unlock_irqrestore(&info->receive_queue_lock, flags);
}

static int allocate_receive_buffers(struct cifs_rdma_info *info, int num_buf)
{
	int i;
	struct cifs_rdma_response *response;

	INIT_LIST_HEAD(&info->receive_queue);
	spin_lock_init(&info->receive_queue_lock);

	for (i=0; i<num_buf; i++) {
		response = mempool_alloc(info->response_mempool, GFP_KERNEL);
		if (!response)
			goto allocate_failed;

		response->info = info;
		list_add_tail(&response->list, &info->receive_queue);
		info->count_receive_buffer++;
	}

	return 0;

allocate_failed:
	while (!list_empty(&info->receive_queue)) {
		response = list_first_entry(
				&info->receive_queue,
				struct cifs_rdma_response, list);
		list_del(&response->list);
		info->count_receive_buffer--;

		mempool_free(response, info->response_mempool);
	}
	return -ENOMEM;
}

static void destroy_receive_buffers(struct cifs_rdma_info *info)
{
	struct cifs_rdma_response *response;
	while ((response = get_receive_buffer(info)))
		mempool_free(response, info->response_mempool);
}

struct cifs_rdma_info* cifs_create_rdma_session(
	struct TCP_Server_Info *server, struct sockaddr *dstaddr)
{
	int rc;
	struct cifs_rdma_info *info;
	struct rdma_conn_param conn_param;
	struct ib_qp_init_attr qp_attr;
	char cache_name[80];
	int max_pending = receive_credit_max + send_credit_target;

	info = kzalloc(sizeof(struct cifs_rdma_info), GFP_KERNEL);
	if (!info)
		return NULL;

	info->server_info = server;

	rc = cifs_rdma_ia_open(info, dstaddr);
	if (rc) {
		log_rdma_event("cifs_rdma_ia_open rc=%d\n", rc);
		goto out1;
	}

	if (max_pending > info->id->device->attrs.max_cqe ||
	    max_pending > info->id->device->attrs.max_qp_wr) {
		log_rdma_event("consider lowering receive_credit_max and "
			"send_credit_target. Possible CQE overrun, device "
			"reporting max_cpe %d max_qp_wr %d\n",
			info->id->device->attrs.max_cqe,
			info->id->device->attrs.max_qp_wr);
		goto out2;
	}

	info->receive_credit_max = receive_credit_max;
	info->send_credit_target = send_credit_target;
	info->max_send_size = max_send_size;
	info->max_fragmented_recv_size = max_fragmented_recv_size;
	info->max_receive_size = max_receive_size;

	max_send_sge = min_t(int, max_send_sge,
		info->id->device->attrs.max_sge);
	max_recv_sge = min_t(int, max_recv_sge,
		info->id->device->attrs.max_sge_rd);

	info->cq = ib_alloc_cq(info->id->device, info,
			info->receive_credit_max + info->send_credit_target,
			0, IB_POLL_SOFTIRQ);
	if (IS_ERR(info->cq))
		goto out2;

	memset(&qp_attr, 0, sizeof qp_attr);
	qp_attr.event_handler = cifs_rdma_qp_async_error_upcall;
	qp_attr.qp_context = info;
	qp_attr.cap.max_send_wr = info->send_credit_target;
	qp_attr.cap.max_recv_wr = info->receive_credit_max;
	qp_attr.cap.max_send_sge = max_send_sge;
	qp_attr.cap.max_recv_sge = max_recv_sge;
	qp_attr.cap.max_inline_data = 0;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = info->cq;
	qp_attr.recv_cq = info->cq;
	qp_attr.port_num = ~0;

	rc = rdma_create_qp(info->id, info->pd, &qp_attr);
	if (rc) {
		log_rdma_event("rdma_create_qp failed %i\n", rc);
		rc = -ENETUNREACH;
		goto out2;
	}

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.private_data = NULL;
	conn_param.private_data_len = 0;
	conn_param.initiator_depth = 0;
	conn_param.responder_resources = 32;
	if (info->id->device->attrs.max_qp_rd_atom < 32)
		conn_param.responder_resources =
			info->id->device->attrs.max_qp_rd_atom;
	conn_param.retry_count = 6;
	conn_param.rnr_retry_count = 6;
	conn_param.flow_control = 0;
	rc = rdma_connect(info->id, &conn_param);
	if (rc) {
		log_rdma_event("rdma_connect() failed with %i\n", rc);
		goto out2;
	}

	if (info->connect_state != RDMA_CM_EVENT_ESTABLISHED)
		goto out2;

	log_rdma_event("rdma_connect connected\n");

	sprintf(cache_name, "cifs_smbd_request_%p", info);
	info->request_cache =
		kmem_cache_create(
			cache_name,
			sizeof(struct cifs_rdma_request) +
				sizeof(struct smbd_data_transfer),
			0, SLAB_HWCACHE_ALIGN, NULL);

	info->request_mempool =
		mempool_create(info->send_credit_target, mempool_alloc_slab,
			mempool_free_slab, info->request_cache);

	sprintf(cache_name, "cifs_smbd_response_%p", info);
	info->response_cache =
		kmem_cache_create(
			cache_name,
			sizeof(struct cifs_rdma_response) +
				info->max_receive_size,
			0, SLAB_HWCACHE_ALIGN, NULL);

	info->response_mempool =
		mempool_create(info->receive_credit_max, mempool_alloc_slab,
		       mempool_free_slab, info->response_cache);

	allocate_receive_buffers(info, info->receive_credit_max);
	init_waitqueue_head(&info->wait_send_queue);

	init_waitqueue_head(&info->wait_recv_pending);
	atomic_set(&info->recv_pending, 0);
out2:
	rdma_destroy_id(info->id);

out1:
	kfree(info);
	return NULL;
}
