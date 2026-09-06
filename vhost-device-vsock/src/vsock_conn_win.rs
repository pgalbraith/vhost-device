// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! A vsock connection on the completion-port loop (ADR-0001 action item 5).
//!
//! This is the Windows+completion counterpart of [`crate::vsock_conn`]'s
//! `VsockConnection`, not a variant of it: the two differ enough in how
//! they move bytes that sharing one generic type would mean threading
//! readiness-vs-completion branches through every method. This type never
//! reads or writes the socket directly:
//!
//! - `recv_pkt` copies out of `rx_staging`, filled by completed `WSARecv`s
//!   ([`VhostUserVsockThread::continue_receive`], stage 4 of action item
//!   5). A receive is submitted only when guest credit allows it and none
//!   is already outstanding ([`VsockConnection::submit_recv_if_possible`]),
//!   which is how host-side back-pressure happens on this loop: with no
//!   credit, nothing reads from the socket, so its own OS buffer is what
//!   fills up, not `rx_staging`.
//! - `send_pkt` is not yet implemented (action item 5, stage 5): it tracks
//!   peer credit and connection state, which every packet carries
//!   regardless of direction, but guest-to-host data is dropped with a
//!   warning for now.

use std::{collections::VecDeque, num::Wrapping, os::windows::io::OwnedSocket, sync::Arc};

use log::warn;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::bitmap::BitmapSlice;
use vmm_sys_util::completion::{Operation, Port};

use crate::{
    rxops::RxOps,
    rxqueue::RxQueue,
    txbuf::LocalTxBuf,
    vhu_vsock::{
        ConnMapKey, Error, Result, VSOCK_FLAGS_SHUTDOWN_RCV, VSOCK_FLAGS_SHUTDOWN_SEND,
        VSOCK_OP_CREDIT_REQUEST, VSOCK_OP_CREDIT_UPDATE, VSOCK_OP_REQUEST, VSOCK_OP_RESPONSE,
        VSOCK_OP_RST, VSOCK_OP_RW, VSOCK_OP_SHUTDOWN, VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::HostIo,
};

pub(crate) struct VsockConnection {
    pub socket: OwnedSocket,
    pub connect: bool,
    pub peer_port: u32,
    pub rx_queue: RxQueue,
    local_cid: u64,
    pub local_port: u32,
    pub guest_cid: u64,
    pub fwd_cnt: Wrapping<u32>,
    last_fwd_cnt: Wrapping<u32>,
    pub(crate) peer_buf_alloc: u32,
    peer_fwd_cnt: Wrapping<u32>,
    rx_cnt: Wrapping<u32>,
    pub tx_buf: LocalTxBuf,
    tx_buffer_size: u32,
    /// Bytes a completed `WSARecv` delivered but that have not yet been
    /// copied into a packet for the guest.
    pub(crate) rx_staging: VecDeque<u8>,
    /// Whether a receive is currently submitted on `socket`.
    pub(crate) recv_outstanding: bool,
    /// The worker's port, for submitting the next receive.
    port: Arc<Port>,
}

/// How much to read at once. Arbitrary; large enough that a chatty
/// connection doesn't round-trip through the port for every few bytes.
const RECV_CHUNK_LEN: usize = 4096;

impl VsockConnection {
    /// A connection for a host-initiated request, once its "CONNECT PORT"
    /// handshake has been read (see `VhostUserVsockThread::continue_handshake`).
    #[allow(clippy::too_many_arguments)]
    pub fn new_local_init(
        socket: OwnedSocket,
        local_cid: u64,
        local_port: u32,
        guest_cid: u64,
        guest_port: u32,
        tx_buffer_size: u32,
        port: Arc<Port>,
    ) -> Self {
        Self {
            socket,
            connect: false,
            peer_port: guest_port,
            rx_queue: RxQueue::new(),
            local_cid,
            local_port,
            guest_cid,
            fwd_cnt: Wrapping(0),
            last_fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            tx_buf: LocalTxBuf::new(tx_buffer_size),
            tx_buffer_size,
            rx_staging: VecDeque::new(),
            recv_outstanding: false,
            port,
        }
    }

    /// Set the peer port to the guest side application's port.
    pub fn set_peer_port(&mut self, peer_port: u32) {
        self.peer_port = peer_port;
    }

    /// Process a vsock packet that is meant for this connection. See
    /// `vsock_conn::VsockConnection::recv_pkt`, which this mirrors except
    /// for `Rw`: it copies out of `rx_staging` instead of reading the
    /// stream, and re-enqueues itself if credit-limited delivery left
    /// staged bytes behind, since nothing else will notice them until the
    /// next receive completes.
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        self.init_pkt(pkt);

        match self.rx_queue.dequeue() {
            Some(RxOps::Request) => {
                pkt.set_op(VSOCK_OP_REQUEST);
                Ok(())
            }
            Some(RxOps::Rw) => {
                if !self.connect {
                    pkt.set_op(VSOCK_OP_RST);
                    return Ok(());
                }
                if self.rx_staging.is_empty() {
                    // A completion enqueues Rw only once it has staged
                    // something, so this would mean it was already
                    // delivered by an earlier packet in the same batch.
                    return Ok(());
                }
                if self.need_credit_update_from_peer() {
                    self.last_fwd_cnt = self.fwd_cnt;
                    pkt.set_op(VSOCK_OP_CREDIT_REQUEST);
                    return Ok(());
                }

                let buf = pkt.data_slice().ok_or(Error::PktBufMissing)?;
                let read_cnt = std::cmp::min(
                    std::cmp::min(buf.len(), self.peer_avail_credit()),
                    self.rx_staging.len(),
                );
                let bytes: Vec<u8> = self.rx_staging.drain(..read_cnt).collect();
                let buf = buf
                    .subslice(0, read_cnt)
                    .expect("subslicing should work since length was checked");
                buf.copy_from(&bytes);

                pkt.set_op(VSOCK_OP_RW).set_len(read_cnt as u32);
                self.rx_cnt += Wrapping(pkt.len());
                self.last_fwd_cnt = self.fwd_cnt;

                if !self.rx_staging.is_empty() {
                    // More is already staged than fit in one packet;
                    // nothing else will re-notice it, so ask to be
                    // revisited for the rest.
                    self.rx_queue.enqueue(RxOps::Rw);
                }
                self.submit_recv_if_possible();
                Ok(())
            }
            Some(RxOps::Response) => {
                self.connect = true;
                pkt.set_op(VSOCK_OP_RESPONSE);
                Ok(())
            }
            Some(RxOps::CreditUpdate) => {
                if !self.rx_queue.pending_rx() {
                    pkt.set_op(VSOCK_OP_CREDIT_UPDATE);
                    self.last_fwd_cnt = self.fwd_cnt;
                }
                Ok(())
            }
            _ => Err(Error::NoRequestRx),
        }
    }

    /// Deliver a guest generated packet to this connection.
    ///
    /// Peer credit and connection state are tracked regardless of `op`,
    /// since every packet carries them. Guest-to-host data (`VSOCK_OP_RW`)
    /// is not yet implemented (ADR-0001 action item 5, stage 5).
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) -> Result<()> {
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        match pkt.op() {
            VSOCK_OP_RESPONSE => {
                self.connect = true;
            }
            VSOCK_OP_RW => {
                warn!(
                    "vsock: guest-to-host data is not yet implemented on the completion loop \
                     (ADR-0001 action item 5); dropping it (lp={}, pp={})",
                    self.local_port, self.peer_port
                );
            }
            VSOCK_OP_CREDIT_UPDATE => {}
            VSOCK_OP_CREDIT_REQUEST => {
                self.rx_queue.enqueue(RxOps::CreditUpdate);
            }
            VSOCK_OP_SHUTDOWN => {
                let recv_off = pkt.flags() & VSOCK_FLAGS_SHUTDOWN_RCV != 0;
                let send_off = pkt.flags() & VSOCK_FLAGS_SHUTDOWN_SEND != 0;
                if recv_off && send_off && self.tx_buf.is_empty() {
                    self.rx_queue.enqueue(RxOps::Reset);
                }
            }
            _ => {}
        }

        // Every packet may have raised peer_buf_alloc/peer_fwd_cnt, which
        // is the only thing a stalled receive was waiting on.
        self.submit_recv_if_possible();
        Ok(())
    }

    /// Submit the next receive if credit allows it and none is already
    /// outstanding. Called after every completion (to chain the next one
    /// while credit remains) and after every packet from the guest (since
    /// any of them may have raised credit).
    pub(crate) fn submit_recv_if_possible(&mut self) {
        if self.recv_outstanding || !self.connect || self.need_credit_update_from_peer() {
            return;
        }

        use std::os::windows::io::AsSocket;
        use vmm_sys_util::completion::socket;

        let mut operation = Operation::new(vec![0u8; RECV_CHUNK_LEN]);
        operation.hold(Box::new(HostIo::Connection(ConnMapKey::new(
            self.local_port,
            self.peer_port,
        ))));
        match socket::recv(&self.port, self.socket.as_socket(), operation) {
            Ok(_) => self.recv_outstanding = true,
            Err(e) => warn!(
                "vsock: failed to submit a receive for lp={} pp={}: {e:?}",
                self.local_port, self.peer_port
            ),
        }
    }

    /// Initialize all header fields in the vsock packet. See
    /// `vsock_conn::VsockConnection::init_pkt`.
    fn init_pkt<'a, 'b, B: BitmapSlice>(
        &self,
        pkt: &'a mut VsockPacket<'b, B>,
    ) -> &'a mut VsockPacket<'b, B> {
        pkt.set_header_from_raw(&[0u8; PKT_HEADER_SIZE]).unwrap();
        pkt.set_src_cid(self.local_cid)
            .set_dst_cid(self.guest_cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(VSOCK_TYPE_STREAM)
            .set_buf_alloc(self.tx_buffer_size)
            .set_fwd_cnt(self.fwd_cnt.0)
    }

    /// Get max number of bytes we can send to peer without overflowing
    /// the peer's buffer.
    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    /// Check if we need a credit update from the peer before sending
    /// more data to it.
    fn need_credit_update_from_peer(&self) -> bool {
        self.peer_avail_credit() == 0
    }
}
