// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Registers the device's host sockets with the vhost-user backend's event
//! loop.
//!
//! Every host listener and connection is registered here. The backend's loop
//! is what then calls `VhostUserVsockThread::handle_event` when one of them
//! becomes readable or writable.
//!
//! The backend passes only a `u16` through to the device, so a descriptor
//! cannot be carried in it. Each descriptor gets a small id instead, and
//! `descriptor_for` turns the id back into the descriptor. Ids start at
//! `FIRST_HOST_EVENT`, clear of the ids the backend keeps for queues and the
//! ones the device uses itself.
//!
//! Closing a descriptor on Windows while it is still registered kills the
//! process, inside the thread pool, where nothing can catch it. The backend's
//! handler outlives the device thread, so the registrations do not go away
//! with it: `Registrar` unregisters everything it still holds when it is
//! dropped. Declare a `Registrar` before any field that owns a descriptor it
//! watches -- fields drop in declaration order, and this one has to go
//! first.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use vhost_user_backend::VringEpollHandler;
use vmm_sys_util::epoll::{ControlOperation, EventSet};
#[cfg(test)]
use vmm_sys_util::epoll::{Epoll, EpollEvent};

use crate::{
    platform::RawDescriptor,
    vhu_vsock::{Error, Result, VhostUserVsockBackend, SIBLING_VM_EVENT},
};
#[cfg(test)]
use crate::platform::{epoll_target, AsRawDescriptor};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

/// First id free for host descriptors.
///
/// The backend refuses anything within `[0, num_queues]`, and the device
/// spends the next on `SIBLING_VM_EVENT`.
pub(crate) const FIRST_HOST_EVENT: u16 = SIBLING_VM_EVENT + 1;

/// What a [`Registrar`] registers with.
enum Backing {
    /// Nothing yet. The backend supplies its handler only after the thread
    /// exists, so registrations made before then are remembered here and
    /// applied by [`Registrar::attach`].
    Pending,
    /// A standalone epoll, so a test can exercise registration without
    /// standing up a whole backend.
    #[cfg(test)]
    Own(Arc<Epoll>),
    /// The backend's event loop.
    ///
    /// Weak, or nothing is ever freed: the handler owns the backend, the
    /// backend owns the thread, and the thread owns this. The daemon holds
    /// the handler, so a weak reference is enough to keep working.
    Handler(Weak<VringEpollHandler<ArcVhostBknd>>),
}

struct Inner {
    backing: Backing,
    /// What is registered now, by descriptor.
    by_fd: HashMap<RawDescriptor, (u16, EventSet)>,
    /// The reverse direction, for translating a dispatched event back.
    by_id: HashMap<u16, RawDescriptor>,
    /// Ids returned by unregistered descriptors, reused before `next` grows.
    free: Vec<u16>,
    next: u16,
}

impl Inner {
    fn take_id(&mut self) -> u16 {
        self.free.pop().unwrap_or_else(|| {
            let id = self.next;
            self.next += 1;
            id
        })
    }

    /// Apply one registration to whatever is backing this registrar.
    ///
    /// `Pending` succeeds without doing anything: the descriptor is in the
    /// table, and `attach` will register it for real.
    fn apply(&self, op: ControlOperation, fd: RawDescriptor, evset: EventSet, id: u16) -> Result<()> {
        let err = match op {
            ControlOperation::Add => Error::EpollAdd,
            ControlOperation::Modify => Error::EpollModify,
            ControlOperation::Delete => Error::EpollRemove,
        };
        match &self.backing {
            Backing::Pending => Ok(()),
            #[cfg(test)]
            Backing::Own(epoll) => epoll
                .ctl(op, epoll_target(fd), EpollEvent::new(evset, u64::from(id)))
                .map_err(err),
            Backing::Handler(handler) => {
                let Some(handler) = handler.upgrade() else {
                    // The daemon has dropped the handler, so the event loop
                    // this would register with is gone. Nothing to do, and
                    // nothing wrong: teardown is under way.
                    return Ok(());
                };
                match op {
                    ControlOperation::Add => handler.register_listener(fd, evset, u64::from(id)),
                    ControlOperation::Modify => handler.modify_listener(fd, evset, u64::from(id)),
                    ControlOperation::Delete => {
                        handler.unregister_listener(fd, evset, u64::from(id))
                    }
                }
                .map_err(err)
            }
        }
    }
}

/// Registers host descriptors with the backend's event loop.
pub(crate) struct Registrar {
    inner: Mutex<Inner>,
}

impl Registrar {
    fn new(backing: Backing) -> Self {
        Registrar {
            inner: Mutex::new(Inner {
                backing,
                by_fd: HashMap::new(),
                by_id: HashMap::new(),
                free: Vec::new(),
                next: FIRST_HOST_EVENT,
            }),
        }
    }

    /// A registrar for a thread that does not have the backend's handler
    /// yet. Registrations are recorded and applied by `attach`.
    pub fn pending() -> Self {
        Self::new(Backing::Pending)
    }

    /// A registrar backed by a standalone epoll, for tests.
    #[cfg(test)]
    pub fn with_epoll(epoll: Arc<Epoll>) -> Self {
        Self::new(Backing::Own(epoll))
    }

    /// Start using the backend's event loop, registering everything that was
    /// recorded before it arrived.
    pub fn attach(&self, handler: Weak<VringEpollHandler<ArcVhostBknd>>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.backing = Backing::Handler(handler);
        let pending: Vec<_> = inner
            .by_fd
            .iter()
            .map(|(fd, (id, evset))| (*fd, *id, *evset))
            .collect();
        for (fd, id, evset) in pending {
            inner.apply(ControlOperation::Add, fd, evset, id)?;
        }
        Ok(())
    }

    /// Watch `fd` for the events in `evset`.
    ///
    /// Fails if `fd` is already registered, matching what epoll does. Use
    /// `modify` to change an existing registration.
    pub fn register(&self, fd: RawDescriptor, evset: EventSet) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.by_fd.contains_key(&fd) {
            return Err(Error::EpollAdd(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists,
            )));
        }
        let id = inner.take_id();
        inner.apply(ControlOperation::Add, fd, evset, id)?;
        inner.by_fd.insert(fd, (id, evset));
        inner.by_id.insert(id, fd);
        Ok(())
    }

    /// Change which events `fd` is watched for.
    ///
    /// Fails if `fd` is not registered. Callers rely on that: `recv_pkt`
    /// tries `modify` first and falls back to `register` when it fails.
    pub fn modify(&self, fd: RawDescriptor, evset: EventSet) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let Some((id, _)) = inner.by_fd.get(&fd).copied() else {
            return Err(Error::EpollModify(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        };
        inner.apply(ControlOperation::Modify, fd, evset, id)?;
        inner.by_fd.insert(fd, (id, evset));
        Ok(())
    }

    /// Stop watching `fd`, freeing its id.
    pub fn unregister(&self, fd: RawDescriptor) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let Some((id, evset)) = inner.by_fd.remove(&fd) else {
            return Err(Error::EpollRemove(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        };
        inner.by_id.remove(&id);
        inner.free.push(id);
        inner.apply(ControlOperation::Delete, fd, evset, id)
    }

    /// The descriptor an event id refers to.
    ///
    /// `None` if it was unregistered after the event was reported. That
    /// happens when a connection closes, and is not an error.
    pub fn descriptor_for(&self, id: u16) -> Option<RawDescriptor> {
        self.inner.lock().unwrap().by_id.get(&id).copied()
    }

    /// Whether `fd` is currently registered.
    #[cfg(test)]
    pub fn is_registered(&self, fd: RawDescriptor) -> bool {
        self.inner.lock().unwrap().by_fd.contains_key(&fd)
    }

    /// How many descriptors are registered.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_fd.len()
    }
}

impl Drop for Registrar {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        let live: Vec<_> = inner
            .by_fd
            .iter()
            .map(|(fd, (id, evset))| (*fd, *id, *evset))
            .collect();
        for (fd, id, evset) in live {
            // A `Drop` cannot report errors, and the usual cause is a
            // descriptor that has already been closed. Carry on: leaving
            // the others registered is the worse outcome.
            let _ = inner.apply(ControlOperation::Delete, fd, evset, id);
        }
        inner.by_fd.clear();
        inner.by_id.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::eventfd::EventFd;

    /// Dropping a registrar must leave nothing registered.
    ///
    /// A descriptor left registered outlives the thread that owned it,
    /// because the backend's event loop lives longer. On Windows, closing
    /// it then kills the process rather than leaking.
    #[test]
    fn dropping_a_registrar_leaves_nothing_registered() {
        let epoll = Arc::new(Epoll::new().unwrap());
        let doorbell = EventFd::new(0).unwrap();
        let fd = doorbell.as_raw_descriptor();

        let registrar = Registrar::with_epoll(epoll.clone());
        registrar.register(fd, EventSet::IN).unwrap();
        assert!(registrar.is_registered(fd));
        assert_eq!(registrar.len(), 1);

        drop(registrar);

        // The same epoll accepts the descriptor again. It would refuse a
        // descriptor it already held, so this only passes if the dropped
        // registrar removed it.
        let second = Registrar::with_epoll(epoll);
        second
            .register(fd, EventSet::IN)
            .expect("the dropped registrar left its registration behind");
        second.unregister(fd).unwrap();
    }

    /// Unregistering frees the id for the next descriptor, so a long-running
    /// device does not run out.
    #[test]
    fn an_unregistered_id_is_handed_out_again() {
        let registrar = Registrar::pending();
        registrar.register(10, EventSet::IN).unwrap();
        registrar.register(11, EventSet::IN).unwrap();
        assert_eq!(registrar.descriptor_for(FIRST_HOST_EVENT), Some(10));
        assert_eq!(registrar.descriptor_for(FIRST_HOST_EVENT + 1), Some(11));

        registrar.unregister(10).unwrap();
        assert_eq!(registrar.descriptor_for(FIRST_HOST_EVENT), None);

        registrar.register(12, EventSet::IN).unwrap();
        assert_eq!(registrar.descriptor_for(FIRST_HOST_EVENT), Some(12));
        assert_eq!(registrar.len(), 2);
    }

    /// `register` is for descriptors that are not registered yet, `modify`
    /// for ones that are. Each refuses the other's case.
    #[test]
    fn registering_twice_is_refused_and_modifying_an_absent_one_fails() {
        let registrar = Registrar::pending();
        registrar.register(10, EventSet::IN).unwrap();
        assert!(registrar.register(10, EventSet::IN).is_err());
        registrar.modify(10, EventSet::IN | EventSet::OUT).unwrap();

        assert!(registrar.modify(99, EventSet::IN).is_err());
        assert!(registrar.unregister(99).is_err());
    }
}
