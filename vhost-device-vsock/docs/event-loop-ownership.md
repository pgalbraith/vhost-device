# How host sockets are watched

## What happens now

Every host listener and connection is registered with the vhost-user backend's
`VringEpollHandler` — the same event loop that carries the queue events. When
one becomes readable or writable, the backend calls
`VhostUserVsockBackend::handle_event`, which hands it to
`VhostUserVsockThread::process_host_evt`.

`src/registrar.rs` does the registering. The device does not keep an `Epoll`
of its own. This is the same on Linux and Windows.

## Why not the device's own epoll

The device used to keep an `Epoll` for host connections and register that with
the backend, so the backend's loop watched the device's loop. On Linux an
epoll fd is itself pollable, so this works. On Windows an `Epoll` is an I/O
completion port, which cannot be waited on by another wait, and the same
registration kills the process.

The Windows build worked around it with a thread that blocked in
`Epoll::wait` and signalled an `EventFd` the backend could watch, plus a
hand-off so the thread did not poll again until the device had drained. That
thread, the `EventFd` and the hand-off are gone. Registering the sockets
directly is simpler on both platforms, not a Windows special case.

## What the backend's event loop requires

Four things, all read from `vhost-user-backend`:

1. **Only a `u16` reaches the device.** `event_loop.rs` does
   `let ev_type = event.data() as u16;` before dispatching, so the 64-bit
   value a descriptor was registered with is truncated. A descriptor does not
   survive that, so `Registrar` registers a small id instead and keeps a table
   to turn it back into the descriptor.
2. **Ids must be above `num_queues`.** `register_listener` rejects any id
   `<= num_queues`, which is 3 here. `SIBLING_VM_EVENT` takes 4, so host ids
   start at 5 (`FIRST_HOST_EVENT`).
3. **There was no way to change a registration.** The handler had
   `register_listener` and `unregister_listener` only, and its `epoll` field is
   private. The device needs to switch a connection between `IN` and
   `IN | OUT` as its transmit buffer fills and drains, so `modify_listener` was
   added to `vhost` alongside the other two.
4. **Unregistering has to be explicit.** See the next section.

## Teardown

**Closing a socket on Windows while it is still registered kills the process,
inside the thread pool, where nothing can catch it.**

This used to be handled by accident. The device owned the `Epoll`, so when the
device thread went away the `Epoll` went with it, and `Epoll::drop`
unregistered whatever was left. That is no longer true: the daemon owns the
backend's handler, and the handler outlives the device thread.

So `Registrar` unregisters everything still in its table when it is dropped,
and `VhostUserVsockThread` declares its `registrar` field above every field
that owns a socket. Struct fields drop in declaration order, and the registrar
has to go first. `dropping_a_registrar_leaves_nothing_registered` in
`src/registrar.rs` tests it.

The old arrangement did not really keep this rule either. The host listeners
were registered and never unregistered anywhere, and `host_listeners_map` was
declared above the `epoll` field, so those sockets closed while the `Epoll`
still held them. `VsockConnection` had the same shape: `stream` first, `epoll`
later. Nobody had noticed, because the failure is silent until it isn't.

A stronger version of this is possible and was considered: hand back a guard
that owns the socket *and* its registration, so there is no way to close one
without removing the other. It does not fit the code as it stands, because a
connection's stream is deliberately held in two places — `conn.stream` is a
`try_clone` of the stream in `stream_map` — so there is no single owner for a
guard to be. Worth revisiting if that changes.

## A Windows bug this uncovered

Registering a socket in the backend's epoll had never happened before; it had
only ever held handles. Mixing the two changes how that epoll waits. With a
socket registered, `vmm-sys-util`'s Windows `Epoll::wait` blocks in `WSAPoll`
rather than on the completion port, and a signalled handle then reaches the
waiter only through a write to an internal wake socket.

If that write is missed, the waiter never returns. `VhostUserHandler::drop`
signals its worker threads and then joins them, so a missed wake hung the
process during shutdown: `test_vsock_server_unix` failed to finish about one
run in three.

The fix is in `vmm-sys-util`. `wait` now caps how long it blocks and looks at
both sources again, so a missed wake costs a delay rather than a hang. The
hang rate went from 3/10 and 9/12 before to 0/20 after. It can go away
entirely when sockets move to AFD — see `docs/windows-socket-polling.md` in
`vmm-sys-util`, where handle and socket readiness both arrive on the
completion port and there is no wake to miss.

## Notes

`Registrar` holds the handler as a `Weak`. An `Arc` would leak everything: the
handler owns the backend, the backend owns the thread, and the thread owns the
registrar, so an `Arc` here closes that loop and none of them are ever freed.
The daemon holds the handler, so a `Weak` is enough.

An `Epoll` still cannot be registered inside another `Epoll` on Windows,
because a completion port cannot be waited on. Nothing here changes that. The
device no longer needs it.
