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

static int cifs_rdma_post_send_empty(struct cifs_rdma_info *info);
static int cifs_rdma_post_send_data(
		struct cifs_rdma_info *info,
		struct kvec *iov, int n_vec, int remaining_data_length);
static int cifs_rdma_post_send_page(struct cifs_rdma_info *info,
		struct page *page, unsigned long offset,
		size_t size, int remaining_data_length);

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

/* Called in softirq, when a RDMA send is donea */
static void send_done(struct ib_cq *cq, struct ib_wc *wc)
{
	int i;
	struct cifs_rdma_request *request =
		container_of(wc->wr_cqe, struct cifs_rdma_request, cqe);

	log_rdma_send("cifs_rdma_request %p completed wc->status=%d\n",
		request, wc->status);

	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_SEND) {
		log_rdma_send("wc->status=%d wc->opcode=%d\n",
			wc->status, wc->opcode);
	}

	for (i=0; i<request->num_sge; i++)
		ib_dma_unmap_single(request->info->id->device,
			request->sge[i].addr,
			request->sge[i].length,
			DMA_TO_DEVICE);

	kfree(request->sge);
	mempool_free(request, request->info->request_mempool);
}

static void dump_smbd_negotiate_resp(struct smbd_negotiate_resp *resp)
{
	log_rdma_event("resp message min_version %u max_version %u "
		      "negotiated_version %u credits_requested %u "
		      "credits_granted %u status %u max_readwrite_size %u "
		      "preferred_send_size %u max_receive_size %u "
		      "max_fragmented_size %u\n",
		resp->min_version, resp->max_version, resp->negotiated_version,
		resp->credits_requested, resp->credits_granted, resp->status,
		resp->max_readwrite_size, resp->preferred_send_size,
		resp->max_receive_size, resp->max_fragmented_size);
}

/* Process a negotiation response message, according to [MS-SMBD]3.1.5.7 */
static bool process_negotiation_response(struct cifs_rdma_response *response, int packet_length)
{
	struct cifs_rdma_info *info = response->info;
	struct smbd_negotiate_resp *packet =
		(struct smbd_negotiate_resp *) response->packet;

	if (packet_length < sizeof (struct smbd_negotiate_resp)) {
		log_rdma_event("error: packet_length=%d\n", packet_length);
		return false;
	}

	if (le16_to_cpu(packet->negotiated_version) != 0x100) {
		log_rdma_event("error: negotiated_version=%x\n",
			le16_to_cpu(packet->negotiated_version));
		return false;
	}
	info->protocol = le16_to_cpu(packet->negotiated_version);

	if (packet->credits_requested == 0) {
		log_rdma_event("error: credits_requested==0\n");
		return false;
	}
	atomic_set(&info->receive_credit_target,
			le16_to_cpu(packet->credits_requested));

	if (packet->credits_granted == 0) {
		log_rdma_event("error: credits_granted==0\n");
		return false;
	}
	atomic_set(&info->send_credits, le16_to_cpu(packet->credits_granted));

	atomic_set(&info->receive_credits, 0);

	if (le32_to_cpu(packet->preferred_send_size) > info->max_receive_size) {
		log_rdma_event("error: preferred_send_size=%d\n",
			le32_to_cpu(packet->preferred_send_size));
		return false;
	}
	info->max_receive_size = le32_to_cpu(packet->preferred_send_size);

	if (le32_to_cpu(packet->max_receive_size) < 128) {
		log_rdma_event("error: max_receive_size=%d\n",
			le32_to_cpu(packet->max_receive_size));
		return false;
	}
	info->max_send_size = min_t(int, info->max_send_size,
					le32_to_cpu(packet->max_receive_size));

	if (le32_to_cpu(packet->max_fragmented_size) < 131072) {
		log_rdma_event("error: max_fragmented_size=%d\n",
			le32_to_cpu(packet->max_fragmented_size));
		return false;
	}
	info->max_fragmented_send_size = le32_to_cpu(packet->max_fragmented_size);

	info->max_readwrite_size = le32_to_cpu(packet->max_readwrite_size);

	return true;
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
	case SMBD_NEGOTIATE_RESP:
		dump_smbd_negotiate_resp(
			(struct smbd_negotiate_resp *) response->packet);
		info->full_packet_received = true;
		info->negotiate_done = process_negotiation_response(response, wc->byte_len);
		complete(&info->negotiate_completion);
		break;

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
 * Send a negotiation request message to the peer
 * The negotiation procedure is in [MS-SMBD] 3.1.5.2 and 3.1.5.3
 * After negotiation, the transport is connected and ready for
 * carrying upper layer SMB payload
 */
static int cifs_rdma_post_send_negotiate_req(struct cifs_rdma_info *info)
{
	struct ib_send_wr send_wr, *send_wr_fail;
	int rc = -ENOMEM;
	struct cifs_rdma_request *request;
	struct smbd_negotiate_req *packet;

	request = mempool_alloc(info->request_mempool, GFP_KERNEL);
	if (!request)
		return rc;

	request->info = info;

	packet = (struct smbd_negotiate_req *) request->packet;
	packet->min_version = cpu_to_le16(0x100);
	packet->max_version = cpu_to_le16(0x100);
	packet->reserved = cpu_to_le16(0);
	packet->credits_requested = cpu_to_le16(info->send_credit_target);
	packet->preferred_send_size = cpu_to_le32(info->max_send_size);
	packet->max_receive_size = cpu_to_le32(info->max_receive_size);
	packet->max_fragmented_size =
		cpu_to_le32(info->max_fragmented_recv_size);

	request->sge = kzalloc(sizeof(struct ib_sge), GFP_KERNEL);
	if (!request->sge)
		goto allocate_sge_failed;

	request->num_sge = 1;
	request->sge[0].addr = ib_dma_map_single(
				info->id->device, (void *)packet,
				sizeof(*packet), DMA_TO_DEVICE);
	if(ib_dma_mapping_error(info->id->device, request->sge[0].addr)) {
		rc = -EIO;
		goto dma_mapping_failed;
	}

	request->sge[0].length = sizeof(*packet);
	request->sge[0].lkey = info->pd->local_dma_lkey;

	ib_dma_sync_single_for_device(
		info->id->device, request->sge[0].addr,
		request->sge[0].length, DMA_TO_DEVICE);

	request->cqe.done = send_done;

	send_wr.next = NULL;
	send_wr.wr_cqe = &request->cqe;
	send_wr.sg_list = request->sge;
	send_wr.num_sge = request->num_sge;
	send_wr.opcode = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	log_rdma_send("sge addr=%llx length=%x lkey=%x\n",
		request->sge[0].addr,
		request->sge[0].length, request->sge[0].lkey);

	rc = ib_post_send(info->id->qp, &send_wr, &send_wr_fail);
	if (!rc)
		return 0;

	// if we reach here, post send failed
	log_rdma_send("ib_post_send failed rc=%d\n", rc);
	ib_dma_unmap_single(info->id->device, request->sge[0].addr,
		request->sge[0].length, DMA_TO_DEVICE);

dma_mapping_failed:
	kfree(request->sge);

allocate_sge_failed:
	mempool_free(request, info->request_mempool);
	return rc;
}

/*
 * Send a page
 * page: the page to send
 * offset: offset in the page to send
 * size: length in the page to send
 * remaining_data_length: remaining data to send in this payload
 */
static int cifs_rdma_post_send_page(struct cifs_rdma_info *info, struct page *page,
		unsigned long offset, size_t size, int remaining_data_length)
{
	struct cifs_rdma_request *request;
	struct smbd_data_transfer *packet;
	struct ib_send_wr send_wr, *send_wr_fail;
	int rc = -ENOMEM;
	int i;

	request = mempool_alloc(info->request_mempool, GFP_KERNEL);
	if (!request)
		return rc;

	request->info = info;

	wait_event(info->wait_send_queue, atomic_read(&info->send_credits) > 0);
	atomic_dec(&info->send_credits);

	packet = (struct smbd_data_transfer *) request->packet;
	packet->credits_requested = cpu_to_le16(info->send_credit_target);
	packet->flags = cpu_to_le16(0);

	packet->reserved = cpu_to_le16(0);
	packet->data_offset = cpu_to_le32(24);
	packet->data_length = cpu_to_le32(size);
	packet->remaining_data_length = cpu_to_le32(remaining_data_length);

	packet->padding = cpu_to_le32(0);

	log_outgoing("credits_requested=%d credits_granted=%d data_offset=%d "
		     "data_length=%d remaining_data_length=%d\n",
		le16_to_cpu(packet->credits_requested),
		le16_to_cpu(packet->credits_granted),
		le32_to_cpu(packet->data_offset),
		le32_to_cpu(packet->data_length),
		le32_to_cpu(packet->remaining_data_length));

	request->sge = kzalloc(sizeof(struct ib_sge)*2, GFP_KERNEL);
	if (!request->sge)
		goto allocate_sge_failed;
	request->num_sge = 2;

	request->sge[0].addr = ib_dma_map_single(info->id->device,
						 (void *)packet,
						 sizeof(*packet),
						 DMA_BIDIRECTIONAL);
	if(ib_dma_mapping_error(info->id->device, request->sge[0].addr)) {
		rc = -EIO;
		goto dma_mapping_failed;
	}
	request->sge[0].length = sizeof(*packet);
	request->sge[0].lkey = info->pd->local_dma_lkey;
	ib_dma_sync_single_for_device(info->id->device, request->sge[0].addr,
				      request->sge[0].length, DMA_TO_DEVICE);

	request->sge[1].addr = ib_dma_map_page(info->id->device, page,
					       offset, size, DMA_BIDIRECTIONAL);
	if(ib_dma_mapping_error(info->id->device, request->sge[1].addr)) {
		rc = -EIO;
		goto dma_mapping_failed;
	}
	request->sge[1].length = size;
	request->sge[1].lkey = info->pd->local_dma_lkey;
	ib_dma_sync_single_for_device(info->id->device, request->sge[1].addr,
				      request->sge[1].length, DMA_TO_DEVICE);

	log_rdma_send("rdma_request sge[0] addr=%llu legnth=%u lkey=%u sge[1] "
		      "addr=%llu length=%u lkey=%u\n",
		request->sge[0].addr, request->sge[0].length,
		request->sge[0].lkey, request->sge[1].addr,
		request->sge[1].length, request->sge[1].lkey);

	request->cqe.done = send_done;

	send_wr.next = NULL;
	send_wr.wr_cqe = &request->cqe;
	send_wr.sg_list = request->sge;
	send_wr.num_sge = request->num_sge;
	send_wr.opcode = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	rc = ib_post_send(info->id->qp, &send_wr, &send_wr_fail);
	if (!rc)
		return 0;

	// post send failed
	log_rdma_send("ib_post_send failed rc=%d\n", rc);

dma_mapping_failed:
	for (i=0; i<2; i++)
		if (request->sge[i].addr)
			ib_dma_unmap_single(info->id->device,
					    request->sge[i].addr,
					    request->sge[i].length,
					    DMA_TO_DEVICE);
	kfree(request->sge);

allocate_sge_failed:
	mempool_free(request, info->request_mempool);
	return rc;
}

/*
 * Send an empty message
 * Empty message is used to extend credits to peer to for keep live
 */
static int cifs_rdma_post_send_empty(struct cifs_rdma_info *info)
{
	struct cifs_rdma_request *request;
	struct smbd_data_transfer_no_data *packet;
	struct ib_send_wr send_wr, *send_wr_fail;
	int rc;
	u16 credits_granted, flags=0;

	request = mempool_alloc(info->request_mempool, GFP_KERNEL);
	if (!request) {
		log_rdma_send("failed to get send buffer for empty packet\n");
		return -ENOMEM;
	}

	request->info = info;
	packet = (struct smbd_data_transfer_no_data *) request->packet;

	/* nothing to do? */
	if (credits_granted==0 && flags==0) {
		mempool_free(request, info->request_mempool);
		log_keep_alive("nothing to do, not sending anything\n");
		return 0;
	}

	packet->credits_requested = cpu_to_le16(info->send_credit_target);
	packet->credits_granted = cpu_to_le16(credits_granted);
	packet->flags = cpu_to_le16(flags);
	packet->reserved = cpu_to_le16(0);
	packet->remaining_data_length = cpu_to_le32(0);
	packet->data_offset = cpu_to_le32(0);
	packet->data_length = cpu_to_le32(0);

	log_outgoing("credits_requested=%d credits_granted=%d data_offset=%d "
		     "data_length=%d remaining_data_length=%d\n",
		le16_to_cpu(packet->credits_requested),
		le16_to_cpu(packet->credits_granted),
		le32_to_cpu(packet->data_offset),
		le32_to_cpu(packet->data_length),
		le32_to_cpu(packet->remaining_data_length));

	request->num_sge = 1;
	request->sge = kzalloc(sizeof(struct ib_sge), GFP_KERNEL);
	if (!request->sge) {
		rc = -ENOMEM;
		goto allocate_sge_failed;
	}

	request->sge[0].addr = ib_dma_map_single(info->id->device,
				(void *)packet, sizeof(*packet), DMA_TO_DEVICE);
	if(ib_dma_mapping_error(info->id->device, request->sge[0].addr)) {
		rc = -EIO;
		goto dma_mapping_failure;
	}

	request->sge[0].length = sizeof(*packet);
	request->sge[0].lkey = info->pd->local_dma_lkey;
	ib_dma_sync_single_for_device(info->id->device, request->sge[0].addr,
				request->sge[0].length, DMA_TO_DEVICE);

	wait_event(info->wait_send_queue, atomic_read(&info->send_credits) > 0);
	atomic_dec(&info->send_credits);
	info->count_send_empty++;
	log_rdma_send("rdma_request sge addr=%llu legnth=%u lkey=%u\n",
		request->sge[0].addr, request->sge[0].length,
		request->sge[0].lkey);

	request->cqe.done = send_done;

	send_wr.next = NULL;
	send_wr.wr_cqe = &request->cqe;
	send_wr.sg_list = request->sge;
	send_wr.num_sge = request->num_sge;
	send_wr.opcode = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	rc = ib_post_send(info->id->qp, &send_wr, &send_wr_fail);
	if (!rc)
		return 0;

	log_rdma_send("ib_post_send failed rc=%d\n", rc);
	ib_dma_unmap_single(info->id->device, request->sge[0].addr,
			    request->sge[0].length, DMA_TO_DEVICE);

dma_mapping_failure:
	kfree(request->sge);

allocate_sge_failed:
	mempool_free(request, info->request_mempool);
	return rc;
}

/*
 * Send a data buffer
 * iov: the iov array describing the data buffers
 * n_vec: number of iov array
 * remaining_data_length: remaining data to send in this payload
 */
static int cifs_rdma_post_send_data(
	struct cifs_rdma_info *info, struct kvec *iov, int n_vec,
	int remaining_data_length)
{
	struct cifs_rdma_request *request;
	struct smbd_data_transfer *packet;
	struct ib_send_wr send_wr, *send_wr_fail;
	int rc = -ENOMEM, i;
	u32 data_length;

	request = mempool_alloc(info->request_mempool, GFP_KERNEL);
	if (!request)
		return rc;

	request->info = info;

	wait_event(info->wait_send_queue, atomic_read(&info->send_credits) > 0);
	atomic_dec(&info->send_credits);

	packet = (struct smbd_data_transfer *) request->packet;
	packet->credits_requested = cpu_to_le16(info->send_credit_target);
	packet->flags = cpu_to_le16(0);
	packet->reserved = cpu_to_le16(0);

	packet->data_offset = cpu_to_le32(24);

	data_length = 0;
	for (i=0; i<n_vec; i++)
		data_length += iov[i].iov_len;
	packet->data_length = cpu_to_le32(data_length);

	packet->remaining_data_length = cpu_to_le32(remaining_data_length);
	packet->padding = cpu_to_le32(0);

	log_rdma_send("credits_requested=%d credits_granted=%d data_offset=%d "
		      "data_length=%d remaining_data_length=%d\n",
		le16_to_cpu(packet->credits_requested),
		le16_to_cpu(packet->credits_granted),
		le32_to_cpu(packet->data_offset),
		le32_to_cpu(packet->data_length),
		le32_to_cpu(packet->remaining_data_length));

	request->sge = kzalloc(sizeof(struct ib_sge)*(n_vec+1), GFP_KERNEL);
	if (!request->sge)
		goto allocate_sge_failed;

	request->num_sge = n_vec+1;

	request->sge[0].addr = ib_dma_map_single(
				info->id->device, (void *)packet,
				sizeof(*packet), DMA_BIDIRECTIONAL);
	if(ib_dma_mapping_error(info->id->device, request->sge[0].addr)) {
		rc = -EIO;
		goto dma_mapping_failure;
	}
	request->sge[0].length = sizeof(*packet);
	request->sge[0].lkey = info->pd->local_dma_lkey;
	ib_dma_sync_single_for_device(info->id->device, request->sge[0].addr,
		request->sge[0].length, DMA_TO_DEVICE);

	for (i=0; i<n_vec; i++) {
		request->sge[i+1].addr = ib_dma_map_single(info->id->device, iov[i].iov_base,
						iov[i].iov_len, DMA_BIDIRECTIONAL);
		if(ib_dma_mapping_error(info->id->device, request->sge[i+1].addr)) {
			rc = -EIO;
			goto dma_mapping_failure;
		}
		request->sge[i+1].length = iov[i].iov_len;
		request->sge[i+1].lkey = info->pd->local_dma_lkey;
		ib_dma_sync_single_for_device(info->id->device, request->sge[i+i].addr,
			request->sge[i+i].length, DMA_TO_DEVICE);
	}

	log_rdma_send("rdma_request sge[0] addr=%llu legnth=%u lkey=%u\n",
		request->sge[0].addr, request->sge[0].length, request->sge[0].lkey);
	for (i=0; i<n_vec; i++)
		log_rdma_send("rdma_request sge[%d] addr=%llu legnth=%u lkey=%u\n",
			i+1, request->sge[i+1].addr,
			request->sge[i+1].length, request->sge[i+1].lkey);

	request->cqe.done = send_done;

	send_wr.next = NULL;
	send_wr.wr_cqe = &request->cqe;
	send_wr.sg_list = request->sge;
	send_wr.num_sge = request->num_sge;
	send_wr.opcode = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	rc = ib_post_send(info->id->qp, &send_wr, &send_wr_fail);
	if (!rc)
		return 0;

	// post send failed
	log_rdma_send("ib_post_send failed rc=%d\n", rc);

dma_mapping_failure:
	for (i=0; i<n_vec+1; i++)
		if (request->sge[i].addr)
			ib_dma_unmap_single(info->id->device,
					    request->sge[i].addr,
					    request->sge[i].length,
					    DMA_TO_DEVICE);
	kfree(request->sge);

allocate_sge_failed:
	mempool_free(request, info->request_mempool);
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

// Perform SMBD negotiate according to [MS-SMBD] 3.1.5.2
static int cifs_rdma_negotiate(struct cifs_rdma_info *info)
{
	int rc;
	struct cifs_rdma_response* response = get_receive_buffer(info);
	response->type = SMBD_NEGOTIATE_RESP;

	rc = cifs_rdma_post_recv(info, response);

	log_rdma_event("cifs_rdma_post_recv rc=%d iov.addr=%llx iov.length=%x "
		       "iov.lkey=%x\n",
		rc, response->sge.addr,
		response->sge.length, response->sge.lkey);
	if (rc)
		return rc;

	init_completion(&info->negotiate_completion);
	info->negotiate_done = false;
	rc = cifs_rdma_post_send_negotiate_req(info);
	if (rc)
		return rc;

	rc = wait_for_completion_interruptible_timeout(
		&info->negotiate_completion, 60 * HZ);
	log_rdma_event("wait_for_completion_timeout rc=%d\n", rc);

	if (info->negotiate_done)
		return 0;

	if (rc == 0)
		rc = -ETIMEDOUT;
	else if (rc == -ERESTARTSYS)
		rc = -EINTR;
	else
		rc = -ENOTCONN;

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

	rc = cifs_rdma_negotiate(info);
	if (!rc)
		return info;

	// negotiation failed
	log_rdma_event("cifs_rdma_negotiate rc=%d\n", rc);

out2:
	rdma_destroy_id(info->id);

out1:
	kfree(info);
	return NULL;
}
