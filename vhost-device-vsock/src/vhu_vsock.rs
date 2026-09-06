// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    io::Result as IoResult,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use log::warn;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap, Le64};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
    eventfd::EventFd,
};

use crate::{registrar::FIRST_HOST_EVENT, thread_backend::RawPktsQ, vhu_vsock_thread::*};

pub(crate) type CidMap =
    HashMap<u64, (Arc<RwLock<RawPktsQ>>, Arc<RwLock<HashSet<String>>>, EventFd)>;

const NUM_QUEUES: usize = 3;

// New descriptors pending on the rx queue
const RX_QUEUE_EVENT: u16 = 0;
// New descriptors are pending on the tx queue.
const TX_QUEUE_EVENT: u16 = 1;
// New descriptors are pending on the event queue.
const EVT_QUEUE_EVENT: u16 = 2;

/// Notification coming from the sibling VM.
///
/// The backend keeps ids 0 to num_queues for the queues and the exit event,
/// so the device's own ids start above them.
pub(crate) const SIBLING_VM_EVENT: u16 = (NUM_QUEUES + 1) as u16;

/// CID of the host
pub(crate) const VSOCK_HOST_CID: u64 = 2;

/// Connection oriented packet
pub(crate) const VSOCK_TYPE_STREAM: u16 = 1;

/// Vsock packet operation ID - Connection request
pub(crate) const VSOCK_OP_REQUEST: u16 = 1;
/// Vsock packet operation ID - Connection response
pub(crate) const VSOCK_OP_RESPONSE: u16 = 2;
/// Vsock packet operation ID - Connection reset
pub(crate) const VSOCK_OP_RST: u16 = 3;
/// Vsock packet operation ID - Shutdown connection
pub(crate) const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Vsock packet operation ID - Data read/write
pub(crate) const VSOCK_OP_RW: u16 = 5;
/// Vsock packet operation ID - Flow control credit update
pub(crate) const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Vsock packet operation ID - Flow control credit request
pub(crate) const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will receive no more
/// data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will send no more
/// data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

// Queue mask to select vrings.
const QUEUE_MASK: u64 = 0b11;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Custom error types
// A Windows build with the `completion` feature no longer constructs a few
// of these (the ones only ever produced by the now Unix/epoll-only host
// socket path in `vsock_conn.rs`/`thread_backend.rs`, ADR-0001 action item
// 5); which ones drifts stage by stage, so this is allowed at the enum
// level rather than variant by variant.
#[cfg_attr(all(windows, feature = "completion"), allow(dead_code))]
#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleUnknownEvent,
    #[error("Failed to accept new local unix domain socket connection")]
    UnixAccept(std::io::Error),
    #[error("Failed to bind a unix stream")]
    UnixBind(std::io::Error),
    #[error("Failed to add to epoll")]
    EpollAdd(std::io::Error),
    #[error("Failed to modify evset associated with epoll")]
    EpollModify(std::io::Error),
    #[error("Failed to read from unix stream")]
    UnixRead(std::io::Error),
    #[error("Failed to convert byte array to string")]
    ConvertFromUtf8(std::str::Utf8Error),
    #[error("Invalid vsock connection request from host")]
    InvalidPortRequest,
    #[error("Unable to convert string to integer")]
    ParseInteger(std::num::ParseIntError),
    #[error("Error reading stream port")]
    ReadStreamPort(Box<Error>),
    #[error("Failed to de-register fd from epoll")]
    EpollRemove(std::io::Error),
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Unable to iterate queue")]
    IterateQueue,
    #[error("No rx request available")]
    NoRequestRx,
    #[error("Packet missing data buffer")]
    PktBufMissing,
    #[error("Failed to connect to unix socket")]
    UnixConnect(std::io::Error),
    #[cfg(all(feature = "backend_vsock", unix))]
    #[error("Failed to accept new local vsock socket connection")]
    VsockAccept(std::io::Error),
    #[cfg(all(feature = "backend_vsock", unix))]
    #[error("Failed to connect to vsock socket")]
    VsockConnect(std::io::Error),
    #[cfg(all(feature = "backend_vsock", unix))]
    #[error("Failed to bind a vsock stream")]
    VsockBind(std::io::Error),
    #[error("Unable to write to stream")]
    StreamWrite,
    #[error("Unable to push data to local tx buffer")]
    LocalTxBufFull,
    #[error("Unable to flush data from local tx buffer")]
    LocalTxBufFlush(std::io::Error),
    #[error("No free local port available for new host inititated connection")]
    NoFreeLocalPort,
    #[error("Backend rx queue is empty")]
    EmptyBackendRxQ,
    #[error("Failed to create an EventFd")]
    EventFdCreate(std::io::Error),
    #[error("Raw vsock packets queue is empty")]
    EmptyRawPktsQueue,
    #[error("CID already in use by another vsock device")]
    CidAlreadyInUse,
}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}

#[cfg(all(feature = "backend_vsock", unix))]
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct VsockProxyInfo {
    pub forward_cid: u32,
    pub listen_ports: Vec<u32>,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum BackendType {
    /// unix domain socket path
    UnixDomainSocket(PathBuf),
    /// the vsock CID and ports
    #[cfg(all(feature = "backend_vsock", unix))]
    Vsock(VsockProxyInfo),
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub(crate) struct VsockConfig {
    guest_cid: u64,
    socket: PathBuf,
    backend_info: BackendType,
    tx_buffer_size: u32,
    queue_size: usize,
    groups: Vec<String>,
}

impl VsockConfig {
    /// Create a new instance of the VsockConfig struct, containing the
    /// parameters to be fed into the vsock-backend server.
    pub fn new(
        guest_cid: u64,
        socket: PathBuf,
        backend_info: BackendType,
        tx_buffer_size: u32,
        queue_size: usize,
        groups: Vec<String>,
    ) -> Self {
        Self {
            guest_cid,
            socket,
            backend_info,
            tx_buffer_size,
            queue_size,
            groups,
        }
    }

    /// Return the guest's current CID.
    pub fn get_guest_cid(&self) -> u64 {
        self.guest_cid
    }

    pub fn get_backend_info(&self) -> BackendType {
        self.backend_info.clone()
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> PathBuf {
        self.socket.clone()
    }

    pub fn get_tx_buffer_size(&self) -> u32 {
        self.tx_buffer_size
    }

    pub fn get_queue_size(&self) -> usize {
        self.queue_size
    }

    pub fn get_groups(&self) -> Vec<String> {
        self.groups.clone()
    }
}

/// A local port and peer port pair used to retrieve
/// the corresponding connection.
#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub(crate) struct ConnMapKey {
    local_port: u32,
    peer_port: u32,
}

impl ConnMapKey {
    pub fn new(local_port: u32, peer_port: u32) -> Self {
        Self {
            local_port,
            peer_port,
        }
    }
}

/// Virtio Vsock Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
struct VirtioVsockConfig {
    pub guest_cid: Le64,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioVsockConfig {}

pub(crate) struct VhostUserVsockBackend {
    config: VirtioVsockConfig,
    queue_size: usize,
    pub threads: Vec<Mutex<VhostUserVsockThread>>,
    queues_per_thread: Vec<u64>,
    exit_consumer: EventConsumer,
    exit_notifier: EventNotifier,
}

impl VhostUserVsockBackend {
    pub fn new(config: VsockConfig, cid_map: Arc<RwLock<CidMap>>) -> Result<Self> {
        let thread = Mutex::new(VhostUserVsockThread::new(
            config.get_backend_info(),
            config.get_guest_cid(),
            config.get_tx_buffer_size(),
            config.get_groups(),
            cid_map,
        )?);
        let queues_per_thread = vec![QUEUE_MASK];

        let (exit_consumer, exit_notifier) =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK).map_err(Error::EventFdCreate)?;

        Ok(Self {
            config: VirtioVsockConfig {
                guest_cid: From::from(config.get_guest_cid()),
            },
            queue_size: config.get_queue_size(),
            threads: vec![thread],
            queues_per_thread,
            exit_consumer,
            exit_notifier,
        })
    }
}

impl VhostUserBackend for VhostUserVsockBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

    fn update_memory(&self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(atomic_mem.clone());
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        // Host descriptors are watched for writability too, so only the
        // device's own events have to be readable.
        if device_event < FIRST_HOST_EVENT && evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            RX_QUEUE_EVENT | TX_QUEUE_EVENT | EVT_QUEUE_EVENT => {
                self.process_kicked_queue(device_event, vrings, thread_id)
            }
            SIBLING_VM_EVENT => {
                let mut thread = self.threads[thread_id].lock().unwrap();
                let evt_idx = thread.event_idx;
                let _ = thread.sibling_event_fd.read();
                thread.process_raw_pkts(&vrings[0], evt_idx)?;
                Ok(())
            }
            id if id >= FIRST_HOST_EVENT => {
                let mut thread = self.threads[thread_id].lock().unwrap();
                let evt_idx = thread.event_idx;
                thread.process_host_evt(id, evset);
                if let Err(e) = thread.process_tx(&vrings[1], evt_idx) {
                    match e {
                        Error::NoMemoryConfigured => {
                            warn!("Received a host event before vring initialization")
                        }
                        _ => return Err(e.into()),
                    }
                }
                thread.process_rx(&vrings[0], evt_idx)?;
                Ok(())
            }
            _ => Err(Error::HandleUnknownEvent.into()),
        }
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let consumer = self.exit_consumer.try_clone().ok()?;
        let notifier = self.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }
}

impl VhostUserVsockBackend {
    /// Process the vring `handle_event` was told is kicked: the same
    /// dispatch for `RX_QUEUE_EVENT`/`TX_QUEUE_EVENT`/`EVT_QUEUE_EVENT` on
    /// both loops. `handle_event` calls this after its event-set check; the
    /// completion loop's `handle_kick` (below) calls it directly, since a
    /// kick there carries no event set to check.
    fn process_kicked_queue(
        &self,
        vring: u16,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        let vring_rx = &vrings[0];
        let vring_tx = &vrings[1];

        let mut thread = self.threads[thread_id].lock().unwrap();
        let evt_idx = thread.event_idx;

        match vring {
            RX_QUEUE_EVENT => {}
            TX_QUEUE_EVENT => {
                thread.process_tx(vring_tx, evt_idx)?;
            }
            EVT_QUEUE_EVENT => {
                warn!("Received an unexpected EVT_QUEUE_EVENT");
            }
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }

        if vring != EVT_QUEUE_EVENT {
            thread.process_rx(vring_rx, evt_idx)?;
        }

        Ok(())
    }
}

/// The same device on the completion-port loop (ADR-0001, action item 5).
///
/// A kick means the same thing on either loop, so every protocol method
/// here forwards to the `VhostUserBackend` implementation above; the two
/// traits are siblings that spell their protocol methods identically. The
/// differences are confined to the loop-facing methods: `handle_kick` has
/// no event set to check, and there is no exit event, because the loop
/// stops on a key it posts to itself.
///
/// `attach` and `handle_completion` are stubs for now (action item 5's
/// infra stage): the host-socket rewrite that gives them real bodies lands
/// in later stages. Until then this impl exists so the crate compiles
/// under `--features completion` on Windows, not so the daemon can
/// actually run on this loop.
// `VhostUserCompletionBackend` is named by full path rather than `use`d at
// module scope: it spells its protocol methods the same as
// `VhostUserBackend`, and importing both into one scope makes every call
// through `backend.method(...)` (as the existing epoll-path tests below
// do) ambiguous.
#[cfg(all(windows, feature = "completion"))]
impl vhost_user_backend::VhostUserCompletionBackend for VhostUserVsockBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        VhostUserBackend::num_queues(self)
    }

    fn max_queue_size(&self) -> usize {
        VhostUserBackend::max_queue_size(self)
    }

    fn features(&self) -> u64 {
        VhostUserBackend::features(self)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserBackend::protocol_features(self)
    }

    fn set_event_idx(&self, enabled: bool) {
        VhostUserBackend::set_event_idx(self, enabled)
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        VhostUserBackend::update_memory(self, mem)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        VhostUserBackend::get_config(self, offset, size)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        VhostUserBackend::queues_per_thread(self)
    }

    /// Register the sibling-VM doorbell as a `Signal` on the worker's port
    /// (ADR-0001 action item 5, stage 2). The host-socket side (accepts,
    /// receives, sends) still has no completion-loop implementation; that
    /// is the rest of action item 5.
    fn attach(
        &self,
        thread_index: usize,
        port: Arc<vmm_sys_util::completion::Port>,
    ) -> IoResult<()> {
        use std::os::windows::io::AsHandle;

        let mut thread = self.threads[thread_index].lock().unwrap();
        port.register(
            thread.sibling_event_fd.as_handle(),
            SIBLING_VM_EVENT as usize,
        )?;
        thread.attach_accept_loop(port)
    }

    fn handle_kick(&self, vring: u16, vrings: &[VringRwLock], thread_id: usize) -> IoResult<()> {
        self.process_kicked_queue(vring, vrings, thread_id)
    }

    /// The sibling-VM doorbell arrives here as a `Signal`, not through
    /// `handle_kick`: unlike a vring's kick, its key (`SIBLING_VM_EVENT`,
    /// above `num_queues()`) is the device's own, so the loop reports it as
    /// `Completion::Signal` rather than dispatching it as a queue. The
    /// kernel has already consumed the event by the time this is called
    /// (the wait that noticed it is what reset it), so there is nothing to
    /// read, unlike the epoll path's `sibling_event_fd.read()`.
    ///
    /// Anything else reaching here is host-socket I/O this device does not
    /// submit yet -- the rest of action item 5.
    fn handle_completion(
        &self,
        completion: vmm_sys_util::completion::Completion,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        match completion {
            vmm_sys_util::completion::Completion::Signal { key }
                if key == SIBLING_VM_EVENT as usize =>
            {
                let mut thread = self.threads[thread_id].lock().unwrap();
                let evt_idx = thread.event_idx;
                thread.process_raw_pkts(&vrings[0], evt_idx)?;
                Ok(())
            }
            vmm_sys_util::completion::Completion::Operation {
                key,
                result,
                operation,
            } if key == crate::vhu_vsock_thread::LISTENER_ACCEPT_KEY => {
                result?;
                let mut thread = self.threads[thread_id].lock().unwrap();
                thread.finish_accept(operation)
            }
            vmm_sys_util::completion::Completion::Operation {
                key,
                result,
                operation,
            } if key == crate::vhu_vsock_thread::HOST_IO_KEY => {
                let mut thread = self.threads[thread_id].lock().unwrap();
                thread.handle_host_io_completion(result, operation)
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "vhost-device-vsock does not yet implement the completion loop's \
                     host-socket path (ADR-0001 action item 5 is still in progress): {other:?}"
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use tempfile::tempdir;
    use vhost_user_backend::VringT;
    use vm_memory::GuestAddress;

    use super::*;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const QUEUE_SIZE: usize = 1024;

    fn test_vsock_backend(config: VsockConfig, expected_cid: u64) {
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = VhostUserVsockBackend::new(config, cid_map);

        assert!(backend.is_ok());
        let backend = backend.unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        backend.set_event_idx(false);

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];
        vrings[0].set_queue_info(0x100, 0x200, 0x300).unwrap();
        vrings[0].set_queue_ready(true);
        vrings[1].set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vrings[1].set_queue_ready(true);

        backend.update_memory(mem).unwrap();

        let queues_per_thread = backend.queues_per_thread();
        assert_eq!(queues_per_thread.len(), 1);
        assert_eq!(queues_per_thread[0], 0b11);

        let config = backend.get_config(0, 8);
        assert_eq!(config.len(), 8);
        let cid = u64::from_le_bytes(config.try_into().unwrap());
        assert_eq!(cid, expected_cid);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        let (_, notifier) = exit.unwrap();
        notifier.notify().unwrap();

        let ret = backend.handle_event(RX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(TX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(EVT_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        // A host event for a descriptor that is no longer registered. It
        // is ignored, not refused: a connection can close while an event
        // for it is still pending.
        let ret = backend.handle_event(FIRST_HOST_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();
    }

    #[test]
    fn test_vsock_backend_unix() {
        const CID: u64 = 3;

        let groups_list: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend_unix.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_backend.vsock");

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );

        test_vsock_backend(config, CID);

        // cleanup
        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    #[cfg(all(feature = "backend_vsock", unix))]
    #[test]
    fn test_vsock_backend_vsock() {
        const CID: u64 = 3;

        let groups_list: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend.socket");
        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![9001, 9002],
            }),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );

        test_vsock_backend(config, CID);

        // cleanup
        let _ = std::fs::remove_file(vhost_socket_path);
        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_backend_failures() {
        const CID: u64 = 3;

        let groups: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend_failures.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_backend_failures.vsock");

        let config = VsockConfig::new(
            CID,
            PathBuf::from("/sys/not_allowed.socket"),
            BackendType::UnixDomainSocket(PathBuf::from("/sys/not_allowed.vsock")),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups.clone(),
        );

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = VhostUserVsockBackend::new(config, cid_map.clone());
        assert!(backend.is_err());

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups,
        );

        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];

        backend.update_memory(mem).unwrap();

        // reading out of the config space, expecting empty config
        let config = backend.get_config(2, 8);
        assert_eq!(config.len(), 0);

        assert_eq!(
            backend
                .handle_event(RX_QUEUE_EVENT, EventSet::OUT, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleEventNotEpollIn.to_string()
        );
        assert_eq!(
            backend
                .handle_event(SIBLING_VM_EVENT - 1, EventSet::IN, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleUnknownEvent.to_string()
        );

        // cleanup
        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vhu_vsock_structs() {
        let unix_config = VsockConfig::new(
            0,
            PathBuf::new(),
            BackendType::UnixDomainSocket(PathBuf::new()),
            0,
            0,
            vec![String::new()],
        );
        assert_eq!(format!("{unix_config:?}"), "VsockConfig { guest_cid: 0, socket: \"\", backend_info: UnixDomainSocket(\"\"), tx_buffer_size: 0, queue_size: 0, groups: [\"\"] }");

        #[cfg(all(feature = "backend_vsock", unix))]
        let vsock_config = VsockConfig::new(
            0,
            PathBuf::new(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![9001, 9002],
            }),
            0,
            0,
            vec![String::new()],
        );
        #[cfg(all(feature = "backend_vsock", unix))]
        assert_eq!(format!("{vsock_config:?}"), "VsockConfig { guest_cid: 0, socket: \"\", backend_info: Vsock(VsockProxyInfo { forward_cid: 1, listen_ports: [9001, 9002] }), tx_buffer_size: 0, queue_size: 0, groups: [\"\"] }");

        let conn_map = ConnMapKey::new(0, 0);
        assert_eq!(
            format!("{conn_map:?}"),
            "ConnMapKey { local_port: 0, peer_port: 0 }"
        );
        assert_eq!(conn_map, conn_map.clone());

        let virtio_config = VirtioVsockConfig::default();
        assert_eq!(
            format!("{virtio_config:?}"),
            "VirtioVsockConfig { guest_cid: Le64(0) }"
        );
        assert_eq!(virtio_config, virtio_config.clone());

        let error = Error::HandleEventNotEpollIn;
        assert_eq!(format!("{error:?}"), "HandleEventNotEpollIn");
    }

    /// ADR-0001 action item 5, stage 2: `attach` registers the sibling-VM
    /// doorbell as a `Signal`, and `handle_completion` reports it back and
    /// dispatches it to `process_raw_pkts` the same way the epoll path's
    /// `SIBLING_VM_EVENT` arm does -- without a host-socket rewrite
    /// anywhere in this test.
    #[cfg(all(windows, feature = "completion"))]
    #[test]
    fn completion_signal_for_sibling_doorbell_dispatches_to_process_raw_pkts() {
        use std::time::Duration;

        use virtio_vsock::packet::PKT_HEADER_SIZE;
        use vmm_sys_util::completion::{Completion, Port};

        use crate::thread_backend::RawVsockPacket;

        const CID: u64 = 3;
        let groups_list: Vec<String> = vec![String::from("default")];
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vhost_socket_path = test_dir.path().join("test_completion_signal.socket");
        let vsock_socket_path = test_dir.path().join("test_completion_signal.vsock");
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );
        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];
        vrings[0].set_queue_info(0x100, 0x200, 0x300).unwrap();
        vrings[0].set_queue_ready(true);
        vrings[1].set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vrings[1].set_queue_ready(true);
        backend.update_memory(mem).unwrap();

        let port = Arc::new(Port::new().unwrap());
        vhost_user_backend::VhostUserCompletionBackend::attach(&backend, 0, port.clone())
            .expect("attach should register the sibling doorbell");

        // Simulate a sibling VM's `send_pkt` delivering a raw packet: the
        // same two steps it takes (`thread_backend.rs`'s sibling-forwarding
        // branch) without a second backend to send it from.
        {
            let thread = backend.threads[0].lock().unwrap();
            thread
                .thread_backend
                .raw_pkts_queue
                .write()
                .unwrap()
                .push_back(RawVsockPacket {
                    header: [0u8; PKT_HEADER_SIZE],
                    data: Vec::new(),
                });
            thread.sibling_event_fd.write(1).unwrap();
        }

        let mut completions = Vec::new();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        assert_eq!(completions.len(), 1);
        let completion = completions.pop().unwrap();
        assert!(
            matches!(completion, Completion::Signal { key } if key == SIBLING_VM_EVENT as usize),
            "expected the sibling doorbell's key, got {completion:?}"
        );

        // Delivering it exercises exactly what the epoll path's
        // `SIBLING_VM_EVENT` arm does (`process_raw_pkts` against the rx
        // vring); the vring here has no descriptors available, so this
        // checks the wiring succeeds without erroring, the same way
        // `thread_backend.rs`'s and `vsock_conn.rs`'s own tests check
        // `process_rx`/`process_raw_pkts` without asserting delivery.
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend, completion, &vrings, 0,
        )
        .unwrap();

        // Anything this device doesn't recognise -- not the sibling
        // doorbell, not one of its own accept operations -- is
        // unaccounted for and must be refused, not silently accepted.
        let unexpected = Completion::Posted {
            key: 999,
            bytes: 0,
            pointer: 0,
        };
        assert!(
            vhost_user_backend::VhostUserCompletionBackend::handle_completion(
                &backend, unexpected, &vrings, 0,
            )
            .is_err()
        );

        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    /// ADR-0001 action item 5, stage 3: `attach` submits the host
    /// listener's first accept, and each accept completion resubmits the
    /// next one. Two connects in a row prove the loop keeps running, not
    /// just its first iteration.
    #[cfg(all(windows, feature = "completion"))]
    #[test]
    fn completion_accept_loop_resubmits_after_each_connection() {
        use std::time::Duration;

        use uds_windows::UnixStream;
        use vmm_sys_util::completion::Port;

        const CID: u64 = 3;
        let groups_list: Vec<String> = vec![String::from("default")];
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vhost_socket_path = test_dir.path().join("test_completion_accept.socket");
        let vsock_socket_path = test_dir.path().join("test_completion_accept.vsock");
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );
        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();

        let port = Arc::new(Port::new().unwrap());
        vhost_user_backend::VhostUserCompletionBackend::attach(&backend, 0, port.clone())
            .expect("attach should submit the listener's first accept");

        // Kept alive for the whole test: since stage 4, finishing an
        // accept also submits a handshake receive, and dropping a client
        // early would complete that receive too (peer closed), adding an
        // unrelated completion to a later `wait` this test isn't about.
        let mut clients = Vec::new();
        for expected_count in 1..=2 {
            clients.push(
                UnixStream::connect(&vsock_socket_path)
                    .expect("the listener should be accepting connections"),
            );

            let mut completions = Vec::new();
            port.wait(Some(Duration::from_secs(5)), &mut completions)
                .unwrap();
            assert_eq!(completions.len(), 1);
            let completion = completions.pop().unwrap();

            vhost_user_backend::VhostUserCompletionBackend::handle_completion(
                &backend,
                completion,
                &[],
                0,
            )
            .expect("finish_accept should succeed and resubmit the next accept");

            // The test client never sends "CONNECT <port>\n", so each
            // connection stays a pending handshake rather than becoming a
            // tracked connection -- this test is only about the accept
            // mechanics (stage 3), not the handshake (stage 4's own test
            // covers that).
            assert_eq!(
                backend.threads[0].lock().unwrap().pending_handshake_count(),
                expected_count,
                "each connection should add exactly one pending handshake"
            );
        }

        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    /// ADR-0001 action item 5, stage 4: a host connection's
    /// `"CONNECT <port>\n"` line turns it into a tracked connection in
    /// `win_conn_map`, and once the guest has (in this test, simulated)
    /// granted credit, a receive completion stages bytes for it to read.
    #[cfg(all(windows, feature = "completion"))]
    #[test]
    fn completion_handshake_and_receive_track_a_real_connection() {
        use std::{io::Write, time::Duration};

        use uds_windows::UnixStream;
        use vmm_sys_util::completion::Port;

        use crate::rxops::RxOps;

        const CID: u64 = 3;
        let groups_list: Vec<String> = vec![String::from("default")];
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vhost_socket_path = test_dir.path().join("test_completion_handshake.socket");
        let vsock_socket_path = test_dir.path().join("test_completion_handshake.vsock");
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );
        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();

        let port = Arc::new(Port::new().unwrap());
        vhost_user_backend::VhostUserCompletionBackend::attach(&backend, 0, port.clone()).unwrap();

        let mut client = UnixStream::connect(&vsock_socket_path).unwrap();

        // The accept.
        let mut completions = Vec::new();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(
            backend.threads[0].lock().unwrap().pending_handshake_count(),
            1
        );

        // The "CONNECT <port>\n" handshake.
        client.write_all(b"CONNECT 1234\n").unwrap();
        completions.clear();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        assert_eq!(completions.len(), 1);
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        assert_eq!(
            backend.threads[0].lock().unwrap().pending_handshake_count(),
            0,
            "a completed handshake should stop being pending"
        );
        let local_port = {
            let thread = backend.threads[0].lock().unwrap();
            assert_eq!(thread.thread_backend.win_conn_map.len(), 1);
            let conn = thread.thread_backend.win_conn_map.values().next().unwrap();
            assert_eq!(conn.peer_port, 1234, "the requested guest port");
            assert!(
                thread
                    .thread_backend
                    .backend_rxq
                    .contains(&ConnMapKey::new(conn.local_port, 1234)),
                "the new connection should have a Request queued for the guest"
            );
            conn.local_port
        };

        // Simulate the guest's VSOCK_OP_RESPONSE having arrived: connected,
        // with credit -- which is what lets a receive be submitted at all.
        {
            let mut thread = backend.threads[0].lock().unwrap();
            let key = ConnMapKey::new(local_port, 1234);
            let conn = thread.thread_backend.win_conn_map.get_mut(&key).unwrap();
            conn.connect = true;
            conn.peer_buf_alloc = 65536;
            conn.submit_recv_if_possible();
        }

        client.write_all(b"hello").unwrap();
        completions.clear();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        assert_eq!(completions.len(), 1);
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        {
            let mut thread = backend.threads[0].lock().unwrap();
            let key = ConnMapKey::new(local_port, 1234);
            let conn = thread.thread_backend.win_conn_map.get_mut(&key).unwrap();
            assert_eq!(Vec::from(conn.rx_staging.clone()), b"hello");
            // The handshake's own Request is still queued too (nothing in
            // this test ever dequeued it by calling recv_pkt), and Request
            // outranks Rw in RxQueue's priority order, so check `contains`
            // rather than `peek`.
            assert!(conn.rx_queue.contains(RxOps::Rw.bitmask()));
        }

        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    /// ADR-0001 action item 5, stage 5: a guest `VSOCK_OP_RW` packet goes
    /// into `tx_buf`, a real `WSASend` carries it to the host application,
    /// and the completion clears `tx_buf` back out.
    #[cfg(all(windows, feature = "completion"))]
    #[test]
    fn completion_send_delivers_guest_data_to_the_host() {
        use std::{
            io::{Read, Write},
            time::Duration,
        };

        use uds_windows::UnixStream;
        use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
        use vmm_sys_util::completion::Port;

        const CID: u64 = 3;
        let groups_list: Vec<String> = vec![String::from("default")];
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vhost_socket_path = test_dir.path().join("test_completion_send.socket");
        let vsock_socket_path = test_dir.path().join("test_completion_send.vsock");
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );
        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();

        let port = Arc::new(Port::new().unwrap());
        vhost_user_backend::VhostUserCompletionBackend::attach(&backend, 0, port.clone()).unwrap();

        let mut client = UnixStream::connect(&vsock_socket_path).unwrap();

        // The accept.
        let mut completions = Vec::new();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        // The "CONNECT <port>\n" handshake.
        client.write_all(b"CONNECT 1234\n").unwrap();
        completions.clear();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        let local_port = {
            let thread = backend.threads[0].lock().unwrap();
            thread
                .thread_backend
                .win_conn_map
                .values()
                .next()
                .unwrap()
                .local_port
        };

        // Simulate the guest's VSOCK_OP_RESPONSE having arrived (building
        // one isn't what this test is about): connected, so a send is
        // actually delivered rather than just buffered.
        {
            let mut thread = backend.threads[0].lock().unwrap();
            let key = ConnMapKey::new(local_port, 1234);
            thread
                .thread_backend
                .win_conn_map
                .get_mut(&key)
                .unwrap()
                .connect = true;
        }

        // The guest sends "hello".
        const DATA_LEN: usize = 5;
        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);
        data_raw.copy_from_slice(b"hello");
        // SAFETY: hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };
        packet
            .set_type(VSOCK_TYPE_STREAM)
            .set_op(VSOCK_OP_RW)
            .set_src_cid(CID)
            .set_dst_cid(VSOCK_HOST_CID)
            .set_src_port(1234)
            .set_dst_port(local_port)
            .set_buf_alloc(65536)
            .set_fwd_cnt(0);

        {
            let mut thread = backend.threads[0].lock().unwrap();
            thread.thread_backend.send_pkt(&packet).unwrap();
        }

        // The send completion.
        completions.clear();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        assert_eq!(completions.len(), 1);
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        // The host application really received it, not just tx_buf
        // believing it did.
        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");

        let thread = backend.threads[0].lock().unwrap();
        let key = ConnMapKey::new(local_port, 1234);
        let conn = thread.thread_backend.win_conn_map.get(&key).unwrap();
        assert!(
            conn.tx_buf.is_empty(),
            "tx_buf should be drained once the send completes"
        );
        drop(thread);

        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    /// ADR-0001 action item 5, stage 6: a guest `VSOCK_OP_REQUEST` makes a
    /// real connect to the host application at `{uds_path}_{port}`, and
    /// once its own `VSOCK_OP_RESPONSE` reaches the guest, a receive is
    /// already submitted -- proving the `submit_recv_if_possible` call
    /// added to `recv_pkt`'s `Response` arm actually fires here, not just
    /// for a host-initiated connection (stage 4's credit comes from a
    /// later packet; a guest-initiated one has it from the request that
    /// created it).
    #[cfg(all(windows, feature = "completion"))]
    #[test]
    fn completion_guest_initiated_connect_then_receives() {
        use std::{io::Write, time::Duration};

        use uds_windows::UnixListener;
        use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
        use vmm_sys_util::completion::Port;

        const CID: u64 = 3;
        const GUEST_PORT: u32 = 5555;
        const HOST_PORT: u32 = 1234;
        let groups_list: Vec<String> = vec![String::from("default")];
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vhost_socket_path = test_dir.path().join("test_completion_connect.socket");
        let vsock_socket_path = test_dir.path().join("test_completion_connect.vsock");
        let host_app_path = test_dir
            .path()
            .join(format!("test_completion_connect.vsock_{HOST_PORT}"));
        let host_app_listener = UnixListener::bind(&host_app_path).unwrap();

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));
        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );
        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();

        let port = Arc::new(Port::new().unwrap());
        vhost_user_backend::VhostUserCompletionBackend::attach(&backend, 0, port.clone()).unwrap();

        // The guest asks to connect to HOST_PORT, carrying its own credit
        // information in the request (unlike a host-initiated connection,
        // which has none until the guest's response comes back).
        let mut pkt_raw = [0u8; PKT_HEADER_SIZE];
        // SAFETY: pkt_raw is guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(&mut pkt_raw, None).unwrap() };
        packet
            .set_type(VSOCK_TYPE_STREAM)
            .set_op(VSOCK_OP_REQUEST)
            .set_src_cid(CID)
            .set_dst_cid(VSOCK_HOST_CID)
            .set_src_port(GUEST_PORT)
            .set_dst_port(HOST_PORT)
            .set_buf_alloc(65536)
            .set_fwd_cnt(0);

        {
            let mut thread = backend.threads[0].lock().unwrap();
            thread.thread_backend.send_pkt(&packet).unwrap();
        }

        // The host application accepts the connect the backend just made.
        let (mut host_side, _) = host_app_listener.accept().unwrap();

        let key = ConnMapKey::new(HOST_PORT, GUEST_PORT);
        {
            let thread = backend.threads[0].lock().unwrap();
            assert!(thread.thread_backend.win_conn_map.contains_key(&key));
            assert!(thread.thread_backend.backend_rxq.contains(&key));
        }

        // Deliver the queued VSOCK_OP_RESPONSE to the guest.
        let mut resp_pkt_raw = [0u8; PKT_HEADER_SIZE];
        // SAFETY: resp_pkt_raw is guaranteed to be valid.
        let mut resp_pkt = unsafe { VsockPacket::new(&mut resp_pkt_raw, None).unwrap() };
        {
            let mut thread = backend.threads[0].lock().unwrap();
            thread.thread_backend.recv_pkt(&mut resp_pkt).unwrap();
        }
        assert_eq!(resp_pkt.op(), VSOCK_OP_RESPONSE);
        {
            let thread = backend.threads[0].lock().unwrap();
            let conn = thread.thread_backend.win_conn_map.get(&key).unwrap();
            assert!(
                conn.connect,
                "connect should be true once RESPONSE is delivered"
            );
        }

        // A receive should already be outstanding -- the host writing now
        // should complete without anything else nudging it.
        host_side.write_all(b"hi").unwrap();
        let mut completions = Vec::new();
        port.wait(Some(Duration::from_secs(5)), &mut completions)
            .unwrap();
        assert_eq!(completions.len(), 1);
        let completion = completions.pop().unwrap();
        vhost_user_backend::VhostUserCompletionBackend::handle_completion(
            &backend,
            completion,
            &[],
            0,
        )
        .unwrap();

        let thread = backend.threads[0].lock().unwrap();
        let conn = thread.thread_backend.win_conn_map.get(&key).unwrap();
        assert_eq!(Vec::from(conn.rx_staging.clone()), b"hi");
        drop(thread);

        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        let _ = std::fs::remove_file(host_app_path);
        test_dir.close().unwrap();
    }
}
