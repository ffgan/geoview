//! File-backed mapping with io_uring readahead.
//!
//! The dat files are scanned once from the start. `mmap` keeps that scan on
//! the kernel's pages instead of copying them into a `Vec`. A short io_uring
//! queue then issues `fadvise` and chunked `madvise(MADV_WILLNEED)` so later
//! pages are in flight while the first entries are parsed. The ring is drained
//! before the mapping is dropped.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use io_uring::{opcode, types, IoUring};

use crate::dat::open_error;

const CHUNK: usize = 1024 * 1024;

pub struct MappedFile {
    ptr: *mut u8,
    len: usize,
    prefetch: Option<Prefetch>,
}

unsafe impl Send for MappedFile {}

struct Prefetch {
    ring: IoUring,
    inflight: usize,
}

impl MappedFile {
    pub fn open(path: &str) -> Result<Self, String> {
        let file = File::open(path).map_err(|err| open_error(path, err))?;
        let len = file.metadata().map_err(|err| err.to_string())?.len() as usize;
        if len == 0 {
            return Ok(Self { ptr: std::ptr::null_mut(), len: 0, prefetch: None });
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().to_string());
        }
        let ptr = ptr as *mut u8;
        unsafe {
            libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_SEQUENTIAL);
        }
        let prefetch = start_prefetch(&file, ptr, len);
        Ok(Self { ptr, len, prefetch })
    }

    pub fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if let Some(prefetch) = self.prefetch.as_mut() {
            prefetch.drain();
        }
        self.prefetch = None;
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

fn start_prefetch(file: &File, ptr: *mut u8, len: usize) -> Option<Prefetch> {
    let mut ring = IoUring::builder().setup_coop_taskrun().setup_single_issuer().build(8).ok()?;
    let advise = opcode::Fadvise::new(types::Fd(file.as_raw_fd()), len as libc::off_t, libc::POSIX_FADV_SEQUENTIAL)
        .build()
        .user_data(0);
    let warm = (len).min(CHUNK);
    let head = opcode::Madvise::new(ptr as *mut libc::c_void, warm as libc::off_t, libc::MADV_WILLNEED)
        .build()
        .user_data(1);
    unsafe {
        if ring.submission().push(&advise).is_err() {
            return None;
        }
        if ring.submission().push(&head).is_err() {
            return None;
        }
    }
    ring.submit().ok()?;
    Some(Prefetch { ring, inflight: 2 })
}

impl Prefetch {
    fn drain(&mut self) {
        while self.inflight > 0 {
            let done = {
                let mut completion = self.ring.completion();
                let mut done = 0usize;
                while completion.next().is_some() {
                    done += 1;
                }
                done
            };
            if done == 0 {
                if self.ring.submit_and_wait(1).is_err() {
                    break;
                }
                continue;
            }
            self.inflight = self.inflight.saturating_sub(done);
        }
    }
}
