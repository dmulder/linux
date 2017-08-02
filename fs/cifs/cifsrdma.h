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

	// RDMA related
	struct rdma_cm_id *id;
	struct ib_qp_init_attr qp_attr;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_device_attr dev_attr;
	int connect_state;
	int ri_rc;
	struct completion ri_done;

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

	// for debug purposes
	unsigned int count_receive_buffer;
	unsigned int count_get_receive_buffer;
	unsigned int count_put_receive_buffer;
	unsigned int count_send_empty;
};

// Create a SMBDirect session
struct cifs_rdma_info* cifs_create_rdma_session(
	struct TCP_Server_Info *server, struct sockaddr *dstaddr);
#endif
