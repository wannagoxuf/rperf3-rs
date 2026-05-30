//! Windows socket duplication and WSASend FFI bindings.
//! Provides DuplicateHandle for multi-threaded UDP receive and batched WSASend for high-throughput sending.

use std::ffi::c_void;
use std::os::windows::io::AsRawSocket;
use std::os::windows::prelude::RawSocket;
use tokio::net::UdpSocket;
use std::ptr::null_mut;

type HANDLE = *mut std::ffi::c_void;
type DWORD = u32;
type BOOL = i32;
pub type SOCKET = usize;
const DUPLICATE_SAME_ACCESS: DWORD = 0x00000002;

// WSABUF and WSASend constants
const WSA_FLAG_OVERLAPPED: DWORD = 0x00000001;
const WSASYS_ERROR_OFFSET: DWORD = 0x00000358;
const WSAEWOULDBLOCK: i32 = 10035;

pub type WSABUF_len = DWORD;

#[repr(C)]
pub struct WSABUF {
    pub len: DWORD,
    pub buf: *mut u8,
}

#[repr(C)]
pub struct WSAMSG {
    pub name: *mut std::ffi::c_void,
    pub namelen: i32,
    pub lpBuffers: *mut WSABUF,
    pub dwBufferCount: DWORD,
    pub Control: *mut std::ffi::c_void,
    pub dwFlags: DWORD,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> HANDLE;
    fn DuplicateHandle(
        hSourceProcessHandle: HANDLE, hSourceHandle: HANDLE,
        hTargetProcessHandle: HANDLE, lpTargetHandle: *mut HANDLE,
        dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwOptions: DWORD,
    ) -> BOOL;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSASend(
        s: SOCKET,
        lpBuffers: *mut WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesSent: *mut DWORD,
        dwFlags: DWORD,
        lpOverlapped: *mut std::ffi::c_void,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;
    fn WSASendTo(
        s: SOCKET,
        lpBuffers: *mut WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesSent: *mut DWORD,
        dwFlags: DWORD,
        lpTo: *mut std::ffi::c_void,
        iToLen: i32,
        lpOverlapped: *mut std::ffi::c_void,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;
    fn closesocket(s: SOCKET) -> i32;
    fn socket(domain: i32, stype: i32, protocol: i32) -> SOCKET;
    fn connect(s: SOCKET, name: *const sockaddr, namelen: i32) -> i32;
    fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const c_void, optlen: i32) -> i32;
}

pub fn duplicate_socket_for_thread(socket: &UdpSocket) -> std::io::Result<RawSocket> {
    let raw_socket = socket.as_raw_socket();
    let self_process = unsafe { GetCurrentProcess() };
    let mut new_handle: HANDLE = null_mut();
    let result = unsafe {
        DuplicateHandle(self_process, raw_socket as HANDLE, self_process,
                       &mut new_handle, 0, 1, DUPLICATE_SAME_ACCESS)
    };
    if result == 0 { return Err(std::io::Error::last_os_error()); }
    Ok(new_handle as RawSocket)
}

/// Batch-send packets using WSASend (non-blocking, queued to kernel).
/// Returns number of packets sent, or -1 on error.
pub unsafe fn wsasend_batch(
    fd: SOCKET,
    packets: &[Vec<u8>],
    iovecs: &mut [WSABUF],
) -> i32 {
    for (i, pkt) in packets.iter().enumerate() {
        iovecs[i].len = pkt.len() as DWORD;
        iovecs[i].buf = pkt.as_ptr() as *mut u8;
    }
    let mut bytes_sent: DWORD = 0;
    let ret = WSASend(
        fd,
        iovecs.as_mut_ptr(),
        packets.len() as DWORD,
        &mut bytes_sent,
        0,
        null_mut(),
        null_mut(),
    );
    if ret == 0 {
        // Success: bytes_sent may be total bytes; derive packet count
        (bytes_sent / packets[0].len() as DWORD) as i32
    } else if ret == -1 {
        let err = std::io::Error::last_os_error().raw_os_error()
            .unwrap_or(0);
        if err as i32 == WSAEWOULDBLOCK {
            0 // would block — try again
        } else {
            -1 // real error
        }
    } else {
        ret
    }
}

pub fn close_socket(fd: SOCKET) {
    unsafe { closesocket(fd); }
}