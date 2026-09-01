// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Host-side I/O types that differ between platforms.
//!
//! The device itself is portable; what is not is how the host end of a
//! connection is named and waited on. On Unix that is a file descriptor
//! and `std`'s own `UnixStream`; on Windows it is a socket handle and
//! `uds_windows`, because Windows has had `AF_UNIX` since 1803 but `std`
//! does not expose it.
//!
//! Waiting for host connections is not in here. They are registered with the
//! vhost-user backend's event loop instead, which is the same on both
//! platforms -- see [`crate::registrar`].

pub use vhost::RawDescriptor;

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
pub use uds_windows::{UnixListener, UnixStream};

/// Read from a host stream into guest memory.
///
/// `vm-memory` implements `ReadVolatile` for `std`'s socket types, which
/// is enough on Unix. Windows has no `std` `UnixStream` to implement it
/// for, so the same job is done here against the raw socket, and callers
/// see one interface on both hosts.
#[cfg(unix)]
pub fn stream_read_volatile<B: vm_memory::bitmap::BitmapSlice>(
    stream: &mut UnixStream,
    buf: &mut vm_memory::VolatileSlice<'_, B>,
) -> Result<usize, vm_memory::VolatileMemoryError> {
    use vm_memory::ReadVolatile;
    stream.read_volatile(buf)
}

#[cfg(windows)]
pub fn stream_read_volatile<B: vm_memory::bitmap::BitmapSlice>(
    stream: &mut UnixStream,
    buf: &mut vm_memory::VolatileSlice<'_, B>,
) -> Result<usize, vm_memory::VolatileMemoryError> {
    use windows_sys::Win32::Networking::WinSock::{recv, SOCKET, SOCKET_ERROR};

    let sock = stream.as_raw_descriptor() as SOCKET;
    let guard = buf.ptr_guard_mut();
    // SAFETY: `sock` is a valid socket for as long as `stream` is borrowed,
    // and the destination is valid for `buf.len()` writes by the invariants
    // VolatileSlice upholds.
    let n = unsafe { recv(
            sock,
            guard.as_ptr().cast::<u8>(),
            i32::try_from(buf.len()).unwrap_or(i32::MAX),
            0,
        ) };
    if n == SOCKET_ERROR {
        // A partial read may have happened, so the whole range is suspect.
        buf.bitmap().mark_dirty(0, buf.len());
        return Err(vm_memory::VolatileMemoryError::IOError(
            std::io::Error::last_os_error(),
        ));
    }
    let n = n as usize;
    buf.bitmap().mark_dirty(0, n);
    Ok(n)
}

/// Write from guest memory to a host stream. Counterpart of
/// [`stream_read_volatile`].
#[cfg(unix)]
pub fn stream_write_volatile<B: vm_memory::bitmap::BitmapSlice>(
    stream: &mut UnixStream,
    buf: &vm_memory::VolatileSlice<'_, B>,
) -> Result<usize, vm_memory::VolatileMemoryError> {
    use vm_memory::WriteVolatile;
    stream.write_volatile(buf)
}

#[cfg(windows)]
pub fn stream_write_volatile<B: vm_memory::bitmap::BitmapSlice>(
    stream: &mut UnixStream,
    buf: &vm_memory::VolatileSlice<'_, B>,
) -> Result<usize, vm_memory::VolatileMemoryError> {
    use windows_sys::Win32::Networking::WinSock::{send, SOCKET, SOCKET_ERROR};

    let sock = stream.as_raw_descriptor() as SOCKET;
    let guard = buf.ptr_guard();
    // SAFETY: as above; the source is valid for `buf.len()` reads.
    let n = unsafe { send(
            sock,
            guard.as_ptr().cast::<u8>(),
            i32::try_from(buf.len()).unwrap_or(i32::MAX),
            0,
        ) };
    if n == SOCKET_ERROR {
        return Err(vm_memory::VolatileMemoryError::IOError(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(n as usize)
}

/// A descriptor in the form `Epoll::ctl` takes on this platform.
///
/// `RawDescriptor` is an integer on both hosts so that it can live in the
/// state a back-end shares across threads; `Epoll` names a handle on
/// Windows because it calls the OS. The conversion belongs at that one
/// boundary rather than in every caller.
#[cfg(all(unix, test))]
pub fn epoll_target(fd: RawDescriptor) -> RawDescriptor {
    fd
}
#[cfg(all(windows, test))]
pub fn epoll_target(fd: RawDescriptor) -> std::os::windows::io::RawHandle {
    fd as std::os::windows::io::RawHandle
}

/// The host descriptor for a thing this crate waits on.
///
/// A local trait rather than a re-export because the two platforms spell
/// the accessor differently (`as_raw_fd` against `as_raw_socket`) and
/// return different types; naming the question once keeps the call sites
/// free of `cfg`.
pub trait AsRawDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

#[cfg(unix)]
mod imp {
    use super::{AsRawDescriptor, RawDescriptor, UnixListener, UnixStream};
    use std::os::unix::io::AsRawFd;

    macro_rules! as_raw_descriptor {
        ($t:ty) => {
            impl AsRawDescriptor for $t {
                fn as_raw_descriptor(&self) -> RawDescriptor {
                    self.as_raw_fd()
                }
            }
        };
    }

    as_raw_descriptor!(UnixStream);
    as_raw_descriptor!(UnixListener);
    as_raw_descriptor!(vmm_sys_util::eventfd::EventFd);
    #[cfg(all(feature = "backend_vsock", unix))]
    as_raw_descriptor!(vsock::VsockStream);
    #[cfg(all(feature = "backend_vsock", unix))]
    as_raw_descriptor!(vsock::VsockListener);
}

#[cfg(windows)]
mod imp {
    use super::{AsRawDescriptor, RawDescriptor, UnixListener, UnixStream};
    use std::os::windows::io::AsRawSocket;

    macro_rules! as_raw_descriptor {
        ($t:ty) => {
            impl AsRawDescriptor for $t {
                fn as_raw_descriptor(&self) -> RawDescriptor {
                    // A socket handle and a kernel object handle are the
                    // same width and both are what `Epoll::ctl` takes;
                    // it tells them apart itself.
                    RawDescriptor::try_from(self.as_raw_socket())
                        .expect("a socket handle fits a descriptor")
                }
            }
        };
    }

    as_raw_descriptor!(UnixStream);
    as_raw_descriptor!(UnixListener);

    impl AsRawDescriptor for vmm_sys_util::eventfd::EventFd {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            use std::os::windows::io::AsRawHandle;
            self.as_raw_handle() as RawDescriptor
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use vm_memory::VolatileSlice;

    /// A connected pair, built the same way on both hosts: `std` has
    /// `UnixStream::pair()` but `uds_windows` does not, and going through a
    /// listener is what the crate does in production anyway.
    fn stream_pair() -> (UnixStream, UnixStream, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);

        let path = std::env::temp_dir().join(format!(
            "vhost-device-vsock-test-{}-{}.sock",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server, path)
    }

    #[test]
    fn read_shim_reads_what_the_peer_wrote() {
        let (mut client, mut server, path) = stream_pair();
        client.write_all(b"hello from the host").unwrap();

        let mut buf = [0u8; 64];
        let mut slice = VolatileSlice::from(&mut buf[..]);
        let n = stream_read_volatile(&mut server, &mut slice).unwrap();

        assert_eq!(n, b"hello from the host".len());
        assert_eq!(&buf[..n], b"hello from the host");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_shim_fills_a_smaller_buffer_and_reports_how_much() {
        // The caller loops on short reads; the shim must report the count it
        // actually took rather than claiming the whole buffer.
        let (mut client, mut server, path) = stream_pair();
        client.write_all(b"0123456789").unwrap();

        let mut buf = [0u8; 4];
        let mut slice = VolatileSlice::from(&mut buf[..]);
        let n = stream_read_volatile(&mut server, &mut slice).unwrap();

        assert_eq!(n, 4);
        assert_eq!(&buf, b"0123");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn write_shim_delivers_to_the_peer() {
        let (client, mut server, path) = stream_pair();
        let mut client = client;

        let mut out = *b"to the guest";
        let slice = VolatileSlice::from(&mut out[..]);
        let n = stream_write_volatile(&mut client, &slice).unwrap();
        assert_eq!(n, out.len());

        let mut got = vec![0u8; out.len()];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, out);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_and_write_shims_round_trip() {
        // The pairing the bridge actually depends on: what one side writes
        // through the shim, the other reads through it.
        let (mut client, mut server, path) = stream_pair();

        let mut out = *b"round trip";
        let slice = VolatileSlice::from(&mut out[..]);
        stream_write_volatile(&mut client, &slice).unwrap();

        let mut buf = [0u8; 32];
        let mut in_slice = VolatileSlice::from(&mut buf[..]);
        let n = stream_read_volatile(&mut server, &mut in_slice).unwrap();

        assert_eq!(&buf[..n], b"round trip");
        let _ = std::fs::remove_file(path);
    }
}
