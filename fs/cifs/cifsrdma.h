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
#ifndef _CIFS_RDMA_H
#define _CIFS_RDMA_H

#include "cifsglob.h"
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/mempool.h>

enum cifs_rdma_transport_status {
	CIFS_RDMA_CREATED,
	CIFS_RDMA_CONNECTING,
	CIFS_RDMA_CONNECTED,
	CIFS_RDMA_DISCONNECTING,
	CIFS_RDMA_DISCONNECTED,
	CIFS_RDMA_DESTROYED
};

/*
 * The context for the SMBDirect transport
 * Everything related to the transport is here. It has several logical parts
 * 1. RDMA related structures
 * 2. SMBDirect connection parameters
 * 3. Reassembly queue for data receive path
 * 4. mempools for allocating packets
 */
struct cifs_rdma_info {
	struct TCP_Server_Info *server_info;
	enum cifs_rdma_transport_status transport_status;

	// RDMA related
	struct rdma_cm_id *id;
	struct ib_qp_init_attr qp_attr;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_device_attr dev_attr;
	int connect_state;
	int ri_rc;
	struct completion ri_done;
	wait_queue_head_t conn_wait;

	struct completion negotiate_completion;
	bool negotiate_done;

	//connection paramters
	int receive_credit_max;
	int send_credit_target;
	int max_send_size;
	int max_fragmented_recv_size;
	int max_fragmented_send_size;
	int max_receive_size;
	int max_readwrite_size;
	int protocol;
	atomic_t send_credits;
	atomic_t receive_credits;
	atomic_t receive_credit_target;

	atomic_t send_pending;
	wait_queue_head_t wait_send_pending;

	atomic_t recv_pending;
	wait_queue_head_t wait_recv_pending;

	struct list_head receive_queue;
	spinlock_t receive_queue_lock;

	wait_queue_head_t wait_send_queue;

	// request pool for RDMA send
	struct kmem_cache *request_cache;
	mempool_t *request_mempool;

	bool full_packet_received;

	// response pool for RDMA receive
	struct kmem_cache *response_cache;
	mempool_t *response_mempool;

	// for debug purposes
	unsigned int count_receive_buffer;
	unsigned int count_get_receive_buffer;
	unsigned int count_put_receive_buffer;
	unsigned int count_send_empty;
};

enum smbd_message_type {
	SMBD_NEGOTIATE_RESP,
	SMBD_TRANSFER_DATA,
};

#define SMB_DIRECT_RESPONSE_REQUESTED 0x0001

// SMBD negotiation request packet [MS-SMBD] 2.2.1
struct smbd_negotiate_req {
	__le16 min_version;
	__le16 max_version;
	__le16 reserved;
	__le16 credits_requested;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

// SMBD negotiation response packet [MS-SMBD] 2.2.2
struct smbd_negotiate_resp {
	__le16 min_version;
	__le16 max_version;
	__le16 negotiated_version;
	__le16 reserved;
	__le16 credits_requested;
	__le16 credits_granted;
	__le32 status;
	__le32 max_readwrite_size;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

// SMBD data transfer packet with no payload [MS-SMBD] 2.2.3
struct smbd_data_transfer_no_data {
	__le16 credits_requested;
	__le16 credits_granted;
	__le16 flags;
	__le16 reserved;
	__le32 remaining_data_length;
	__le32 data_offset;
	__le32 data_length;
} __packed;

// SMBD data transfer packet with payload [MS-SMBD] 2.2.3
struct smbd_data_transfer {
	__le16 credits_requested;
	__le16 credits_granted;
	__le16 flags;
	__le16 reserved;
	__le32 remaining_data_length;
	__le32 data_offset;
	__le32 data_length;
	__le32 padding;
	char buffer[0];
} __packed;

// The context for a SMBD request
struct cifs_rdma_request {
	struct cifs_rdma_info *info;

	// completion queue entry
	struct ib_cqe cqe;

	// the SGE entries for this packet
	struct ib_sge *sge;
	int num_sge;

	// SMBD packet header follows this structure
	char packet[0];
};

// The context for a SMBD response
struct cifs_rdma_response {
	struct cifs_rdma_info *info;

	// completion queue entry
	struct ib_cqe cqe;

	// the SGE entry for the packet
	struct ib_sge sge;

	enum smbd_message_type type;

	// link to receive queue or reassembly queue
	struct list_head list;

	// indicate if this is the 1st packet of a payload
	bool first_segment;

	// SMBD packet header and payload follows this structure
	char packet[0];
};

// Create a SMBDirect session
struct cifs_rdma_info* cifs_create_rdma_session(
	struct TCP_Server_Info *server, struct sockaddr *dstaddr);

int cifs_rdma_write(struct cifs_rdma_info *rdma, struct smb_rqst *rqst);
#endif
