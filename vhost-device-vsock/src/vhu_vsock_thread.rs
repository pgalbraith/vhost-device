// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader},
    iter::FromIterator,
    num::Wrapping,
    ops::Deref,
    sync::{
        mpsc::{self, Sender},
        Arc, RwLock,
    },
    thread,
};

use log::{error, warn};
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::platform::{AsRawDescriptor, RawDescriptor, UnixListener, UnixStream};
#[cfg(all(feature = "backend_vsock", unix))]
use vsock::{VsockListener, VMADDR_CID_ANY};

use crate::{
    registrar::Registrar,
    rxops::*,
    thread_backend::*,
    vhu_vsock::{
        BackendType, CidMap, ConnMapKey, Error, Result, VhostUserVsockBackend, SIBLING_VM_EVENT,
        VSOCK_HOST_CID,
    },
    vsock_conn::*,
};

// Unused on a Windows build with the `completion` feature; see
// `register_listeners` below.
#[cfg_attr(all(windows, feature = "completion"), allow(dead_code))]
type ArcVhostBknd = Arc<VhostUserVsockBackend>;

/// Key the host listener's `AcceptEx` operations are associated under
/// (ADR-0001 action item 5). Above `num_queues()`, like every key this
/// device owns, and distinct from `SIBLING_VM_EVENT`.
#[cfg(all(windows, feature = "completion"))]
pub(crate) const LISTENER_ACCEPT_KEY: usize = (SIBLING_VM_EVENT + 1) as usize;

/// Key every established host connection's receives and sends are
/// associated under. One key for all of them, rather than one per
/// connection: `handle_completion` tells them apart by what the
/// `Operation` holds (see [`HostIo`]), the way [`Operation::hold`]'s own
/// docs describe.
#[cfg(all(windows, feature = "completion"))]
pub(crate) const HOST_IO_KEY: usize = LISTENER_ACCEPT_KEY + 1;

/// What an `Operation` under [`HOST_IO_KEY`] is for, carried in its held
/// slot so `handle_completion` can route the result without a separate
/// id-to-connection table.
///
/// Unlike an accept operation, a receive or send never claims the held
/// slot for anything of its own, which is what makes this possible here
/// (see `socket::accept`'s own use of it for the in-progress socket).
#[cfg(all(windows, feature = "completion"))]
pub(crate) enum HostIo {
    /// Reading the `"CONNECT <port>\n"` line from a freshly accepted
    /// socket, before it is a tracked connection. The key is the socket's
    /// own raw value, used to find it in `pending_handshakes`.
    Handshake(std::os::windows::io::RawSocket),
    /// A receive for an established connection.
    Connection(ConnMapKey),
}

/// A host connection accepted but still being read for its
/// `"CONNECT <port>\n"` line -- see `VhostUserVsockThread::continue_handshake`.
#[cfg(all(windows, feature = "completion"))]
struct PendingHandshake {
    socket: std::os::windows::io::OwnedSocket,
    /// Bytes read so far, across possibly more than one receive.
    buf: Vec<u8>,
}

/// Parse a `"CONNECT <port>\n"` line (without its trailing newline).
/// `None` means malformed, not "not yet enough data" -- the caller only
/// calls this once a newline has been found.
#[cfg(all(windows, feature = "completion"))]
fn parse_connect_line(line: &[u8]) -> Option<u32> {
    let mut words = std::str::from_utf8(line).ok()?.split_whitespace();
    if words.next()?.to_lowercase() != "connect" {
        return None;
    }
    words.next()?.parse::<u32>().ok()
}

enum RxQueueType {
    Standard,
    RawPkts,
}

// Data which is required by a worker handling event idx.
struct EventData {
    vring: VringRwLock,
    event_idx: bool,
    head_idx: u16,
    used_len: usize,
}

enum ListenerType {
    Unix(UnixListener),
    #[cfg(all(feature = "backend_vsock", unix))]
    Vsock(VsockListener),
}

pub(crate) struct VhostUserVsockThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    backend_info: BackendType,
    /// Where host descriptors are registered.
    ///
    /// Must stay declared above every field that owns a descriptor it
    /// watches. Fields drop in declaration order, and closing a descriptor
    /// that is still registered kills the process on Windows.
    registrar: Arc<Registrar>,
    /// Host socket raw file descriptor and listener.
    host_listeners_map: HashMap<RawDescriptor, ListenerType>,
    /// VsockThreadBackend instance.
    pub thread_backend: VsockThreadBackend,
    /// CID of the guest.
    guest_cid: u64,
    /// Channel to a worker which handles event idx.
    sender: Sender<EventData>,
    /// host side port on which application listens.
    local_port: Wrapping<u32>,
    /// The tx buffer size
    tx_buffer_size: u32,
    /// EventFd to notify this thread for custom events. Currently used to
    /// notify this thread to process raw vsock packets sent from a sibling
    /// VM.
    pub sibling_event_fd: EventFd,
    /// Keeps track of which RX queue was processed first in the last iteration.
    /// Used to alternate between the RX queues to prevent the starvation of one
    /// by the other.
    last_processed: RxQueueType,
    /// The worker's completion port, once `attach` has run (ADR-0001
    /// action item 5). `handle_completion` needs it to resubmit an accept
    /// or a receive but is not itself given the port, so `attach` stashes
    /// it here.
    #[cfg(all(windows, feature = "completion"))]
    port: Option<Arc<vmm_sys_util::completion::Port>>,
    /// Host connections accepted but still being read for their
    /// `"CONNECT <port>\n"` line, keyed by the accepted socket's raw
    /// value. See [`PendingHandshake`] and
    /// `VhostUserVsockThread::continue_handshake`.
    #[cfg(all(windows, feature = "completion"))]
    pending_handshakes: HashMap<std::os::windows::io::RawSocket, PendingHandshake>,
}

impl VhostUserVsockThread {
    /// Create a new instance of VhostUserVsockThread.
    pub fn new(
        backend_info: BackendType,
        guest_cid: u64,
        tx_buffer_size: u32,
        groups: Vec<String>,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Result<Self> {
        let mut host_listeners_map = HashMap::new();
        match &backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                // TODO: better error handling, maybe add a param to force the unlink
                let _ = std::fs::remove_file(uds_path.clone());
                let host_listener = UnixListener::bind(uds_path)
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::UnixBind)?;
                let host_sock = host_listener.as_raw_descriptor();
                host_listeners_map.insert(host_sock, ListenerType::Unix(host_listener));
            }
            #[cfg(all(feature = "backend_vsock", unix))]
            BackendType::Vsock(vsock_info) => {
                for p in &vsock_info.listen_ports {
                    let host_listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, *p)
                        .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                        .map_err(Error::VsockBind)?;
                    let host_sock = host_listener.as_raw_descriptor();
                    host_listeners_map.insert(host_sock, ListenerType::Vsock(host_listener));
                }
            }
        }

        // The backend's event loop arrives later, in `register_listeners`.
        // Until then the registrar just records what is registered.
        let registrar = Arc::new(Registrar::pending());

        let mut groups = groups;
        let groups_set: Arc<RwLock<HashSet<String>>> =
            Arc::new(RwLock::new(HashSet::from_iter(groups.drain(..))));

        let sibling_event_fd = EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?;

        let thread_backend = VsockThreadBackend::new(
            backend_info.clone(),
            registrar.clone(),
            guest_cid,
            tx_buffer_size,
            groups_set.clone(),
            cid_map.clone(),
        );

        {
            let mut cid_map = cid_map.write().unwrap();
            if cid_map.contains_key(&guest_cid) {
                return Err(Error::CidAlreadyInUse);
            }

            cid_map.insert(
                guest_cid,
                (
                    thread_backend.raw_pkts_queue.clone(),
                    groups_set,
                    sibling_event_fd.try_clone().unwrap(),
                ),
            );
        }
        let (sender, receiver) = mpsc::channel::<EventData>();
        thread::spawn(move || loop {
            // TODO: Understand why doing the following in the background thread works.
            // maybe we'd better have thread pool for the entire application if necessary.
            let Ok(event_data) = receiver.recv() else {
                break;
            };
            Self::vring_handle_event(event_data);
        });

        let thread = VhostUserVsockThread {
            mem: None,
            event_idx: false,
            backend_info: backend_info.clone(),
            registrar: registrar.clone(),
            host_listeners_map,
            thread_backend,
            guest_cid,
            sender,
            local_port: Wrapping(0),
            tx_buffer_size,
            sibling_event_fd,
            last_processed: RxQueueType::Standard,
            #[cfg(all(windows, feature = "completion"))]
            port: None,
            #[cfg(all(windows, feature = "completion"))]
            pending_handshakes: HashMap::new(),
        };

        for host_raw_fd in thread.host_listeners_map.keys() {
            VhostUserVsockThread::epoll_register(&registrar, *host_raw_fd, EventSet::IN)?;
        }

        Ok(thread)
    }

    fn vring_handle_event(event_data: EventData) {
        if event_data.event_idx {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            match event_data.vring.needs_notification() {
                Err(_) => {
                    warn!("Could not check if queue needs to be notified");
                    event_data.vring.signal_used_queue().unwrap();
                }
                Ok(needs_notification) => {
                    if needs_notification {
                        event_data.vring.signal_used_queue().unwrap();
                    }
                }
            }
        } else {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            event_data.vring.signal_used_queue().unwrap();
        }
    }
    /// Watch a descriptor for events in evset.
    pub fn epoll_register(registrar: &Registrar, fd: RawDescriptor, evset: EventSet) -> Result<()> {
        registrar.register(fd, evset)
    }

    /// Stop watching a descriptor.
    pub fn epoll_unregister(registrar: &Registrar, fd: RawDescriptor) -> Result<()> {
        registrar.unregister(fd)
    }

    /// Change what a descriptor is watched for.
    pub fn epoll_modify(registrar: &Registrar, fd: RawDescriptor, evset: EventSet) -> Result<()> {
        registrar.modify(fd, evset)
    }

    /// Where this thread registers its host descriptors.
    fn registrar(&self) -> &Registrar {
        &self.registrar
    }

    /// Give the registrar the backend's event loop, and register the
    /// sibling-VM doorbell with it.
    ///
    /// Unused on a Windows build with the `completion` feature: `main.rs`
    /// calls this only on the epoll path, and the completion path's
    /// `attach` (ADR-0001 action item 5) replaces it.
    #[cfg_attr(all(windows, feature = "completion"), allow(dead_code))]
    pub fn register_listeners(&mut self, epoll_handler: Arc<VringEpollHandler<ArcVhostBknd>>) {
        epoll_handler
            .register_listener(
                self.sibling_event_fd.as_raw_descriptor(),
                EventSet::IN,
                u64::from(SIBLING_VM_EVENT),
            )
            .unwrap();
        self.registrar
            .attach(Arc::downgrade(&epoll_handler))
            .unwrap();
    }

    /// Associate the host listener with `port` and submit its first
    /// accept (ADR-0001 action item 5, stage 3). Called once from
    /// `VhostUserCompletionBackend::attach`.
    #[cfg(all(windows, feature = "completion"))]
    pub(crate) fn attach_accept_loop(
        &mut self,
        port: Arc<vmm_sys_util::completion::Port>,
    ) -> std::io::Result<()> {
        let listener = self.unix_listener_socket()?;
        vmm_sys_util::completion::socket::associate(&port, listener, LISTENER_ACCEPT_KEY)?;
        Self::submit_accept(&port, listener)?;
        self.port = Some(port);
        Ok(())
    }

    /// Finish an accept `handle_completion` reported: extract the
    /// connected socket, resubmit the listener's next accept, and start
    /// reading the new connection's `"CONNECT <port>\n"` line (the host
    /// application is a bridge peer, not the guest, so it has to say
    /// which guest port it wants -- see `continue_handshake`).
    #[cfg(all(windows, feature = "completion"))]
    pub(crate) fn finish_accept(
        &mut self,
        mut operation: vmm_sys_util::completion::Operation,
    ) -> std::io::Result<()> {
        use std::os::windows::io::{AsRawSocket, AsSocket};

        let port = self
            .port
            .as_ref()
            .expect("finish_accept called before attach_accept_loop")
            .clone();
        let listener = self.unix_listener_socket()?;
        let accepted = vmm_sys_util::completion::socket::finish_accept(listener, &mut operation)?;
        Self::submit_accept(&port, listener)?;

        // The accepted socket is a different handle from the listener and
        // is not associated with the port just because the listener is:
        // association is per-handle, so its own receives would otherwise
        // complete nowhere `port.wait()` ever looks.
        vmm_sys_util::completion::socket::associate(&port, accepted.as_socket(), HOST_IO_KEY)?;

        let raw = accepted.as_raw_socket();
        self.pending_handshakes.insert(
            raw,
            PendingHandshake {
                socket: accepted,
                buf: Vec::new(),
            },
        );
        self.submit_handshake_recv(raw)
    }

    /// How many host connections are accepted but still waiting for their
    /// `"CONNECT <port>\n"` line. Test-only: production code has no need
    /// to know the count, only the individual sockets.
    #[cfg(all(test, windows, feature = "completion"))]
    pub(crate) fn pending_handshake_count(&self) -> usize {
        self.pending_handshakes.len()
    }

    /// Route a completion under [`HOST_IO_KEY`] to the handshake read it
    /// continues or the established connection it was received for.
    #[cfg(all(windows, feature = "completion"))]
    pub(crate) fn handle_host_io_completion(
        &mut self,
        result: std::io::Result<usize>,
        mut operation: vmm_sys_util::completion::Operation,
    ) -> std::io::Result<()> {
        let held = operation.take_held().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a host I/O completion held nothing",
            )
        })?;
        let io = held.downcast::<HostIo>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a host I/O completion held something other than HostIo",
            )
        })?;

        match *io {
            HostIo::Handshake(raw) => self.continue_handshake(raw, result, &operation),
            HostIo::Connection(key) => self.continue_receive(key, result, &operation),
        }
    }

    /// Append what a handshake receive returned; once a full
    /// `"CONNECT <port>\n"` line is in, turn the socket into a tracked
    /// connection. Resubmits the read if the line isn't complete yet.
    #[cfg(all(windows, feature = "completion"))]
    fn continue_handshake(
        &mut self,
        raw: std::os::windows::io::RawSocket,
        result: std::io::Result<usize>,
        operation: &vmm_sys_util::completion::Operation,
    ) -> std::io::Result<()> {
        let n = result?;
        let Some(pending) = self.pending_handshakes.get_mut(&raw) else {
            // Already torn down (e.g. the peer closed on an earlier read).
            return Ok(());
        };
        if n == 0 {
            self.pending_handshakes.remove(&raw);
            return Ok(());
        }
        pending.buf.extend_from_slice(&operation.buffer()[..n]);

        let Some(newline) = pending.buf.iter().position(|&b| b == b'\n') else {
            return self.submit_handshake_recv(raw);
        };
        let line = pending.buf[..newline].to_vec();
        let pending = self
            .pending_handshakes
            .remove(&raw)
            .expect("looked up above");

        let Some(peer_port) = parse_connect_line(&line) else {
            warn!(
                "vsock: malformed \"CONNECT PORT\" from a host connection: {:?}",
                String::from_utf8_lossy(&line)
            );
            return Ok(());
        };
        let local_port = match self.allocate_local_port() {
            Ok(p) => p,
            Err(e) => {
                warn!("vsock: no free local port for a new host connection: {e:?}");
                return Ok(());
            }
        };

        let port = self
            .port
            .clone()
            .expect("attach must run before accepts complete");
        let mut new_conn = crate::vsock_conn_win::VsockConnection::new_local_init(
            pending.socket,
            VSOCK_HOST_CID,
            local_port,
            self.guest_cid,
            peer_port,
            self.tx_buffer_size,
            port,
        );
        new_conn.rx_queue.enqueue(RxOps::Request);
        new_conn.set_peer_port(peer_port);

        let conn_map_key = ConnMapKey::new(local_port, peer_port);
        self.thread_backend
            .win_conn_map
            .insert(conn_map_key.clone(), new_conn);
        self.thread_backend.backend_rxq.push_back(conn_map_key);
        Ok(())
    }

    /// Submit (or resubmit) a receive for a socket still in
    /// `pending_handshakes`.
    #[cfg(all(windows, feature = "completion"))]
    fn submit_handshake_recv(&self, raw: std::os::windows::io::RawSocket) -> std::io::Result<()> {
        use std::os::windows::io::AsSocket;

        let Some(pending) = self.pending_handshakes.get(&raw) else {
            return Ok(());
        };
        let port = self
            .port
            .as_ref()
            .expect("attach must run before accepts complete");
        let mut operation = vmm_sys_util::completion::Operation::new(vec![0u8; 256]);
        operation.hold(Box::new(HostIo::Handshake(raw)));
        vmm_sys_util::completion::socket::recv(port, pending.socket.as_socket(), operation)?;
        Ok(())
    }

    /// A receive completed for an established connection: stage its bytes,
    /// tell the guest there is something to read, and chain the next
    /// receive if credit allows. A zero-byte read or an error is treated
    /// as the peer closing: enqueue `Reset` so the connection is cleaned
    /// up the way an RST from the guest already is.
    #[cfg(all(windows, feature = "completion"))]
    fn continue_receive(
        &mut self,
        key: ConnMapKey,
        result: std::io::Result<usize>,
        operation: &vmm_sys_util::completion::Operation,
    ) -> std::io::Result<()> {
        let Some(conn) = self.thread_backend.win_conn_map.get_mut(&key) else {
            return Ok(());
        };
        conn.recv_outstanding = false;

        let n = match result {
            Ok(n) => n,
            Err(e) => {
                warn!("vsock: receive failed for a host connection: {e:?}");
                conn.rx_queue.enqueue(RxOps::Reset);
                self.thread_backend.backend_rxq.push_back(key);
                return Ok(());
            }
        };
        if n == 0 {
            conn.rx_queue.enqueue(RxOps::Reset);
            self.thread_backend.backend_rxq.push_back(key);
            return Ok(());
        }

        conn.rx_staging
            .extend(operation.buffer()[..n].iter().copied());
        conn.rx_queue.enqueue(RxOps::Rw);
        self.thread_backend.backend_rxq.push_back(key);
        conn.submit_recv_if_possible();
        Ok(())
    }

    /// The host UDS listener as a socket, for associating with the port
    /// and for `AcceptEx`/`finish_accept`. `backend_vsock`'s AF_VSOCK
    /// listener is Unix-only (see `ListenerType`), so this crate's only
    /// Windows listener is the UDS one.
    #[cfg(all(windows, feature = "completion"))]
    fn unix_listener_socket(&self) -> std::io::Result<std::os::windows::io::BorrowedSocket<'_>> {
        use std::os::windows::io::AsRawSocket;

        let Some(listener) = self.host_listeners_map.values().next() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no host UDS listener to accept on",
            ));
        };
        // `ListenerType::Vsock` is Unix-only (AF_VSOCK forwarding), so this
        // is the only variant a Windows build can construct.
        let ListenerType::Unix(listener) = listener;
        // SAFETY: `listener` outlives the borrow this returns, which does
        // not outlive `self`.
        Ok(unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(listener.as_raw_socket()) })
    }

    /// Submit one accept on `listener`: a fresh, unbound `AF_UNIX` socket
    /// for `AcceptEx` to fill in. `uds_windows` has no public constructor
    /// for an unbound socket, so this creates one the same way
    /// `vmm-sys-util`'s own verified test does
    /// (`socket(AF_UNIX, SOCK_STREAM, 0)`).
    #[cfg(all(windows, feature = "completion"))]
    fn submit_accept(
        port: &vmm_sys_util::completion::Port,
        listener: std::os::windows::io::BorrowedSocket<'_>,
    ) -> std::io::Result<()> {
        use std::os::windows::io::{FromRawSocket, RawSocket};
        use windows_sys::Win32::Networking::WinSock::{
            socket, AF_UNIX, INVALID_SOCKET, SOCK_STREAM,
        };

        // SAFETY: a plain socket() call; the result is checked before use.
        let raw = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if raw == INVALID_SOCKET {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `raw` was just created above and is owned by nothing
        // else.
        let accepted =
            unsafe { std::os::windows::io::OwnedSocket::from_raw_socket(raw as RawSocket) };

        vmm_sys_util::completion::socket::accept(
            port,
            listener,
            accepted,
            vmm_sys_util::completion::Operation::new(vec![
                0u8;
                vmm_sys_util::completion::socket::ACCEPT_BUFFER_LEN
            ]),
        )?;
        Ok(())
    }

    /// Handle an event the backend's loop reported for a host descriptor.
    ///
    /// `id` is the id the descriptor was registered under, not the descriptor
    /// itself, so it has to be looked up.
    pub fn process_host_evt(&mut self, id: u16, evset: EventSet) {
        let Some(fd) = self.registrar.descriptor_for(id) else {
            // The descriptor was unregistered after the event was
            // reported, which happens when a connection closes. Not an
            // error.
            return;
        };
        self.handle_event(fd, evset);
    }

    /// Accept a new connection, or forward a request to the connection the
    /// descriptor belongs to.
    fn handle_event(&mut self, fd: RawDescriptor, evset: EventSet) {
        if let Some(listener) = self.host_listeners_map.get(&fd) {
            // This is a new connection initiated by an application running on the host
            match listener {
                ListenerType::Unix(unix_listener) => {
                    let conn = unix_listener.accept().map_err(Error::UnixAccept);
                    if self.mem.is_some() {
                        conn.and_then(|(stream, _)| {
                            stream
                                .set_nonblocking(true)
                                .map(|_| stream)
                                .map_err(Error::UnixAccept)
                        })
                        .and_then(|stream| self.add_stream_listener(stream))
                        .unwrap_or_else(|err| {
                            warn!("Unable to accept new local connection: {err:?}");
                        });
                    } else {
                        // If we aren't ready to process requests, accept and immediately close
                        // the connection.
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
                #[cfg(all(feature = "backend_vsock", unix))]
                ListenerType::Vsock(vsock_listener) => {
                    let conn = vsock_listener.accept().map_err(Error::VsockAccept);
                    if self.mem.is_some() {
                        match conn {
                            Ok((stream, addr)) => {
                                if let Err(err) = stream.set_nonblocking(true) {
                                    warn!("Failed to set stream to non-blocking: {err:?}");
                                    return;
                                }

                                let peer_port = match vsock_listener.local_addr() {
                                    Ok(listener_addr) => listener_addr.port(),
                                    Err(err) => {
                                        warn!("Failed to get peer address: {err:?}");
                                        return;
                                    }
                                };

                                let local_port = addr.port();
                                let stream_raw_fd = stream.as_raw_descriptor();
                                self.add_new_connection_from_host(
                                    stream_raw_fd,
                                    StreamType::Vsock(stream),
                                    local_port,
                                    peer_port,
                                );
                                if let Err(err) = Self::epoll_register(
                                    self.registrar(),
                                    stream_raw_fd,
                                    EventSet::IN | EventSet::OUT,
                                ) {
                                    warn!("Failed to register with epoll: {err:?}");
                                }
                            }
                            Err(err) => {
                                warn!("Unable to accept new local connection: {err:?}");
                            }
                        }
                    } else {
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
            }
        } else {
            // Check if the stream represented by fd has already established a
            // connection with the application running in the guest
            if let std::collections::hash_map::Entry::Vacant(_) =
                self.thread_backend.listener_map.entry(fd)
            {
                // New connection from the host
                if evset.bits() != EventSet::IN.bits() {
                    // Has to be EPOLLIN as it was not connected previously
                    return;
                }
                let mut stream = match self.thread_backend.stream_map.remove(&fd) {
                    Some(s) => s,
                    None => {
                        warn!("Error while searching fd in the stream map");
                        return;
                    }
                };

                match stream {
                    #[cfg(all(feature = "backend_vsock", unix))]
                    StreamType::Vsock(_) => {
                        error!("Stream type should not be of type vsock");
                    }
                    StreamType::Unix(ref mut unix_stream) => {
                        // Local peer is sending a "connect PORT\n" command
                        let peer_port = match Self::read_local_stream_port(unix_stream) {
                            Ok(port) => port,
                            Err(err) => {
                                warn!("Error while parsing \"connect PORT\n\" command: {err:?}");
                                return;
                            }
                        };

                        // Allocate a local port number
                        let local_port = match self.allocate_local_port() {
                            Ok(lp) => lp,
                            Err(err) => {
                                warn!("Error while allocating local port: {err:?}");
                                return;
                            }
                        };

                        self.add_new_connection_from_host(fd, stream, local_port, peer_port);

                        // Re-register the fd to listen for EPOLLIN and EPOLLOUT events
                        Self::epoll_modify(self.registrar(), fd, EventSet::IN | EventSet::OUT)
                            .unwrap();
                    }
                }
            } else {
                // Previously connected connection

                // Get epoll fd before getting conn as that takes self mut ref
                let registrar = self.registrar.clone();
                let key = self.thread_backend.listener_map.get(&fd).unwrap();
                let conn = self.thread_backend.conn_map.get_mut(key).unwrap();

                if evset.bits() == EventSet::OUT.bits() {
                    // Flush any remaining data from the tx buffer
                    match conn.tx_buf.flush_to(&mut conn.stream) {
                        Ok(cnt) => {
                            if cnt > 0 {
                                conn.fwd_cnt += Wrapping(cnt as u32);
                                conn.rx_queue.enqueue(RxOps::CreditUpdate);
                            } else {
                                // If no remaining data to flush, try to disable EPOLLOUT
                                if Self::epoll_modify(&registrar, fd, EventSet::IN).is_err() {
                                    error!("Failed to disable EPOLLOUT");
                                }
                            }
                            self.thread_backend
                                .backend_rxq
                                .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
                        }
                        Err(e) => {
                            log::debug!("Error: {e:?}");
                        }
                    }
                    return;
                }

                // Unregister stream from the epoll, register when connection is
                // established with the guest
                Self::epoll_unregister(&registrar, fd).unwrap();

                // Enqueue a read request
                conn.rx_queue.enqueue(RxOps::Rw);
                self.thread_backend
                    .backend_rxq
                    .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
            }
        }
    }

    fn add_new_connection_from_host(
        &mut self,
        fd: RawDescriptor,
        stream: StreamType,
        local_port: u32,
        peer_port: u32,
    ) {
        // Insert the fd into the backend's maps
        self.thread_backend
            .listener_map
            .insert(fd, ConnMapKey::new(local_port, peer_port));

        // Create a new connection object an enqueue a connection request
        // packet to be sent to the guest
        let conn_map_key = ConnMapKey::new(local_port, peer_port);
        let mut new_conn = VsockConnection::new_local_init(
            stream,
            VSOCK_HOST_CID,
            local_port,
            self.guest_cid,
            peer_port,
            self.registrar.clone(),
            self.tx_buffer_size,
        );
        new_conn.rx_queue.enqueue(RxOps::Request);
        new_conn.set_peer_port(peer_port);

        // Add connection object into the backend's maps
        self.thread_backend.conn_map.insert(conn_map_key, new_conn);

        self.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(local_port, peer_port));
    }

    /// Allocate a new local port number.
    fn allocate_local_port(&mut self) -> Result<u32> {
        // TODO: Improve space efficiency of this operation
        // TODO: Reuse the conn_map HashMap
        // TODO: Test this.
        let mut alloc_local_port = self.local_port.0;
        loop {
            if !self
                .thread_backend
                .local_port_set
                .contains(&alloc_local_port)
            {
                // The port set doesn't contain the newly allocated port number.
                self.local_port = Wrapping(alloc_local_port + 1);
                self.thread_backend.local_port_set.insert(alloc_local_port);
                return Ok(alloc_local_port);
            } else {
                alloc_local_port = alloc_local_port.wrapping_add(1);
                if alloc_local_port == self.local_port.0 {
                    // We have exhausted our search and wrapped back to the starting port
                    return Err(Error::NoFreeLocalPort);
                }
            }
        }
    }

    /// Read `CONNECT PORT_NUM\n` from the connected stream.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stream);

        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(Error::UnixRead)?;

        let mut word_iter = std::str::from_utf8(&buf[..n])
            .map_err(Error::ConvertFromUtf8)?
            .split_whitespace();

        word_iter
            .next()
            .ok_or(Error::InvalidPortRequest)
            .and_then(|word| {
                if word.to_lowercase() == "connect" {
                    Ok(())
                } else {
                    Err(Error::InvalidPortRequest)
                }
            })
            .and_then(|_| word_iter.next().ok_or(Error::InvalidPortRequest))
            .and_then(|word| word.parse::<u32>().map_err(Error::ParseInteger))
            .map_err(|e| Error::ReadStreamPort(Box::new(e)))
    }

    /// Add a stream to epoll to listen for EPOLLIN events.
    fn add_stream_listener(&mut self, stream: UnixStream) -> Result<()> {
        let stream_fd = stream.as_raw_descriptor();
        self.thread_backend
            .stream_map
            .insert(stream_fd, StreamType::Unix(stream));
        VhostUserVsockThread::epoll_register(self.registrar(), stream_fd, EventSet::IN)?;

        Ok(())
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock, rx_queue_type: RxQueueType) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut vring_mut = vring.get_mut();

        let queue = vring_mut.get_queue_mut();

        while let Some(mut avail_desc) = queue
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(mut pkt) => {
                    let recv_result = match rx_queue_type {
                        RxQueueType::Standard => self.thread_backend.recv_pkt(&mut pkt),
                        RxQueueType::RawPkts => self.thread_backend.recv_raw_pkt(&mut pkt),
                    };

                    if recv_result.is_ok() {
                        PKT_HEADER_SIZE + pkt.len() as usize
                    } else {
                        queue.iter(mem).unwrap().go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {e:?}");
                    0
                }
            };

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .unwrap();

            match rx_queue_type {
                RxQueueType::Standard => {
                    if !self.thread_backend.pending_rx() {
                        break;
                    }
                }
                RxQueueType::RawPkts => {
                    if !self.thread_backend.pending_raw_pkts() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or
    /// not.
    fn process_unix_sockets(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                if !self.thread_backend.pending_rx() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::Standard)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::Standard)?;
        }
        Ok(())
    }

    /// Wrapper to process raw vsock packets queue based on whether event idx is
    /// enabled or not.
    pub fn process_raw_pkts(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            loop {
                if !self.thread_backend.pending_raw_pkts() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::RawPkts)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::RawPkts)?;
        }
        Ok(())
    }

    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        match self.last_processed {
            RxQueueType::Standard => {
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                    self.last_processed = RxQueueType::RawPkts;
                }
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                }
            }
            RxQueueType::RawPkts => {
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                    self.last_processed = RxQueueType::Standard;
                }
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                }
            }
        }
        Ok(())
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(mut avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let pkt = match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    log::debug!("vsock: error reading TX packet: {e:?}");
                    continue;
                }
            };

            if self.thread_backend.send_pkt(&pkt).is_err() {
                vring
                    .get_mut()
                    .get_queue_mut()
                    .iter(mem)
                    .unwrap()
                    .go_to_previous_position();
                break;
            }

            // TODO: Check if the protocol requires read length to be correct
            let used_len = 0;

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .unwrap();
        }

        Ok(())
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or
    /// not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                vring_lock.disable_notification().unwrap();
                self.process_tx_queue(vring_lock)?;
                if !vring_lock.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_tx_queue(vring_lock)?;
        }
        Ok(())
    }
}

impl Drop for VhostUserVsockThread {
    fn drop(&mut self) {
        match &self.backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                let _ = std::fs::remove_file(uds_path);
            }
            #[cfg(all(feature = "backend_vsock", unix))]
            BackendType::Vsock(_) => {
                // Nothing to do
            }
        }
        self.thread_backend
            .cid_map
            .write()
            .unwrap()
            .remove(&self.guest_cid);
    }
}
#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Read, Write},
        path::PathBuf,
    };

    use tempfile::tempdir;
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;
    #[cfg(all(feature = "backend_vsock", unix))]
    use vsock::{VsockStream, VMADDR_CID_LOCAL};

    use super::*;
    use crate::registrar::FIRST_HOST_EVENT;
    #[cfg(all(feature = "backend_vsock", unix))]
    use crate::vhu_vsock::VsockProxyInfo;
    use vmm_sys_util::epoll::Epoll;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    impl VhostUserVsockThread {
        fn get_registrar(&self) -> Arc<Registrar> {
            self.registrar.clone()
        }
    }

    fn test_vsock_thread(backend_info: BackendType) {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(backend_info, 3, CONN_TX_BUF_SIZE, groups, cid_map);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let registrar = t.get_registrar();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let dummy_fd = EventFd::new(0).unwrap();

        // What this covers is register/modify/unregister/register. The set it
        // starts in is incidental, and cannot be the same on both hosts: an
        // EventFd is a handle, and a Windows Epoll reports readability only
        // for those -- there is nothing to wait for on a doorbell becoming
        // writable, so asking is refused rather than accepted and never
        // reported.
        #[cfg(unix)]
        let initial = EventSet::OUT;
        #[cfg(windows)]
        let initial = EventSet::IN;

        VhostUserVsockThread::epoll_register(&registrar, dummy_fd.as_raw_descriptor(), initial)
            .unwrap();
        VhostUserVsockThread::epoll_modify(&registrar, dummy_fd.as_raw_descriptor(), EventSet::IN)
            .unwrap();
        VhostUserVsockThread::epoll_unregister(&registrar, dummy_fd.as_raw_descriptor()).unwrap();
        VhostUserVsockThread::epoll_register(
            &registrar,
            dummy_fd.as_raw_descriptor(),
            EventSet::IN,
        )
        .unwrap();
        // Registered handles have to be removed before they are closed.
        // Closing first implicitly removes an fd from a Linux epoll, so
        // leaving this to the drop below is harmless there; on Windows it
        // leaves a thread-pool wait on a closed handle and takes the
        // process down.
        VhostUserVsockThread::epoll_unregister(&registrar, dummy_fd.as_raw_descriptor()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        t.process_tx(&vring, false).unwrap();
        t.process_tx(&vring, true).unwrap();
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        t.process_rx(&vring, false).unwrap();
        t.process_rx(&vring, true).unwrap();
        t.process_raw_pkts(&vring, false).unwrap();
        t.process_raw_pkts(&vring, true).unwrap();

        VhostUserVsockThread::vring_handle_event(EventData {
            vring: vring.clone(),
            event_idx: false,
            head_idx: 0,
            used_len: 0,
        });
        VhostUserVsockThread::vring_handle_event(EventData {
            vring,
            event_idx: true,
            head_idx: 0,
            used_len: 0,
        });

        dummy_fd.write(1).unwrap();

        // An id for a descriptor that is not registered is ignored rather
        // than dispatched: a connection can close under a pending event.
        t.process_host_evt(FIRST_HOST_EVENT, EventSet::IN);
    }

    #[test]
    fn test_vsock_thread_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let backend_info =
            BackendType::UnixDomainSocket(test_dir.path().join("test_vsock_thread.vsock"));
        test_vsock_thread(backend_info);
        test_dir.close().unwrap();
    }

    #[cfg(all(feature = "backend_vsock", unix))]
    #[test]
    fn test_vsock_thread_vsock() {
        let backend_info = BackendType::Vsock(VsockProxyInfo {
            forward_cid: 1,
            listen_ports: vec![],
        });
        test_vsock_thread(backend_info);
    }

    #[test]
    fn test_vsock_thread_failures() {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(PathBuf::from("/sys/not_allowed.vsock")),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        );
        assert!(t.is_err());

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_failures.vsock");
        let mut t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        )
        .unwrap();
        // A descriptor that names nothing must be refused rather than
        // registered, on either host.
        let bad = Registrar::with_epoll(Arc::new(Epoll::new().unwrap()));
        assert!(VhostUserVsockThread::epoll_register(&bad, -1, EventSet::IN).is_err());
        assert!(VhostUserVsockThread::epoll_modify(&bad, -1, EventSet::IN).is_err());
        assert!(VhostUserVsockThread::epoll_unregister(&bad, -1).is_err());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // memory is not configured, so processing TX should fail
        assert!(t.process_tx(&vring, false).is_err());
        assert!(t.process_tx(&vring, true).is_err());

        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_err());
        assert!(t.process_rx(&vring, true).is_err());

        // trying to use a CID that is already in use should fail
        let vsock_socket_path2 = test_dir.path().join("test_vsock_thread_failures2.vsock");
        let t2 = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path2),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );
        assert!(t2.is_err());

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_thread_unix_backend() {
        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vsock_path = test_dir.path().join("test_vsock_thread.vsock");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_path.clone()),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut uds = UnixStream::connect(vsock_path).unwrap();

        // What the backend's event loop would report: the host listener is
        // readable, so there is a connection to accept.
        let listener_fd = *t.host_listeners_map.keys().next().unwrap();
        t.handle_event(listener_fd, EventSet::IN);

        // Then the accepted stream is readable, carrying the connect command.
        let stream_fd = *t.thread_backend.stream_map.keys().next().unwrap();
        uds.write_all(b"CONNECT 1234\n").unwrap();
        t.handle_event(stream_fd, EventSet::IN);

        // Write and read something from the Unix socket
        uds.write_all(b"some data").unwrap();

        let mut buf = vec![0u8; 16];
        uds.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        uds.read(&mut buf).unwrap_err();

        t.handle_event(stream_fd, EventSet::IN);

        test_dir.close().unwrap();
    }

    #[cfg(all(feature = "backend_vsock", unix))]
    #[test]
    fn test_vsock_thread_vsock_backend() {
        VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, libc::VMADDR_PORT_ANY).expect(
            "This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded",
        );

        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: VMADDR_CID_LOCAL,
                listen_ports: vec![9003, 9004],
            }),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut vs1 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9003).unwrap();
        let mut vs2 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9004).unwrap();
        t.process_backend_evt(EventSet::empty());

        vs1.write_all(b"some data").unwrap();
        vs2.write_all(b"some data").unwrap();
        t.process_backend_evt(EventSet::empty());

        let mut buf = vec![0u8; 16];
        vs1.set_nonblocking(true).unwrap();
        vs2.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        vs1.read(&mut buf).unwrap_err();
        vs2.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());
    }

    /// The registration lifecycle a host connection goes through.
    ///
    /// `handle_event` unregisters an established stream and leaves it to the
    /// next `recv_pkt` to put it back, which it does by trying `epoll_modify`
    /// and falling back to `epoll_register` when that reports the stream is
    /// not registered. The whole cycle therefore rests on `modify` failing
    /// -- and failing rather than quietly succeeding -- once a stream has
    /// been unregistered. This asserts that on a real socket.
    #[test]
    fn a_stream_can_be_unregistered_and_registered_again() {
        use crate::platform::{UnixListener, UnixStream};

        let path = std::env::temp_dir().join(format!(
            "vhost-device-vsock-lifecycle-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let fd = server.as_raw_descriptor();

        let registrar = Registrar::with_epoll(Arc::new(Epoll::new().unwrap()));

        // As a guest-initiated connection is registered.
        VhostUserVsockThread::epoll_register(&registrar, fd, EventSet::IN | EventSet::OUT).unwrap();
        // Registering twice is refused, which is what makes the fallback
        // below meaningful rather than accidentally idempotent.
        assert!(
            VhostUserVsockThread::epoll_register(&registrar, fd, EventSet::IN).is_err(),
            "a second registration of the same stream must be refused"
        );

        // As the tx buffer draining narrows it.
        VhostUserVsockThread::epoll_modify(&registrar, fd, EventSet::IN).unwrap();

        // As handle_event drops it once the guest is to be told.
        VhostUserVsockThread::epoll_unregister(&registrar, fd).unwrap();

        // recv_pkt's first move, which must now fail: if it were to succeed
        // the stream would never be registered again and readiness on it
        // would stop being observed entirely.
        assert!(
            VhostUserVsockThread::epoll_modify(&registrar, fd, EventSet::IN | EventSet::OUT)
                .is_err(),
            "modify must report an unregistered stream, or the fallback never runs"
        );

        // recv_pkt's fallback, restoring the cycle.
        VhostUserVsockThread::epoll_register(&registrar, fd, EventSet::IN | EventSet::OUT).unwrap();

        // And it really is registered again.
        assert!(
            VhostUserVsockThread::epoll_register(&registrar, fd, EventSet::IN).is_err(),
            "the stream should be registered again after the fallback"
        );

        drop(client);
        VhostUserVsockThread::epoll_unregister(&registrar, fd).unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
