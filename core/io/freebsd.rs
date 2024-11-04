extern crate mio;
extern crate mio_aio;
use crate::{Completion, File, Result, IO};
use log::trace;
use std::cell::RefCell;
use std::os::unix::fs::OpenOptionsExt;
use std::rc::Rc;
use std::{
    io::{IoSlice, IoSliceMut, Read, Seek, Write},
    ops::Deref,
    os::unix::io::AsFd,
};

use mio::{Events, Interest, Poll, Token};
use mio_aio::SourceApi;

const UDATA: Token = Token(0xdead_beef);

pub struct FreeBSDIO {}

impl FreeBSDIO {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl IO for FreeBSDIO {
    fn open_file(&self, path: &str) -> Result<Rc<dyn File>> {
        trace!("open_file(path = {})", path);
        let file = std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .write(true)
            .open(path)?;
        Ok(Rc::new(FreeBSDFile {
            file: RefCell::new(file),
        }))
    }

    fn run_once(&self) -> Result<()> {
        Ok(())
    }

    fn generate_random_number(&self) -> i64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).unwrap();
        i64::from_ne_bytes(buf)
    }

    fn get_current_time(&self) -> String {
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

pub struct FreeBSDFile {
    file: RefCell<std::fs::File>,
}

impl File for FreeBSDFile {
    // Since we let the OS handle the locking, file locking is not supported on the generic IO implementation
    // No-op implementation allows compilation but provides no actual file locking.
    fn lock_file(&self, exclusive: bool) -> Result<()> {
        Ok(())
    }

    fn unlock_file(&self) -> Result<()> {
        Ok(())
    }

    fn pread(&self, pos: usize, c: Rc<Completion>) -> Result<()> {
        let mut file = self.file.borrow_mut();
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);
        {
            let r = match &(*c) {
                Completion::Read(r) => r,
                Completion::Write(_) => unreachable!(),
            };

            let mut buf = r.buf_mut();

            let mut rbufs = [IoSliceMut::new(buf.as_mut_slice())];

            let mut aior = mio_aio::Source::readv_at(
                file.as_fd(),
                pos as u64, //offset
                &mut rbufs,
                0, //priority
            );
            poll.registry()
                .register(&mut aior, UDATA, Interest::AIO)
                .expect("registration failed");
            let mut aior = Box::pin(aior);
            aior.as_mut().submit().unwrap();
            poll.poll(&mut events, None).expect("poll failed");
            let mut it = events.iter();
            let ev = it.next().unwrap();
            assert_eq!(ev.token(), UDATA);
            assert!(ev.is_aio());
            assert!(aior.as_mut().error().is_ok());
            assert!(it.next().is_none());

            match aior.as_mut().aio_return() {
                Ok(_) => (),
                Err(_) => {}
            }
        }
        c.complete(0);
        Ok(())
    }

    fn pwrite(
        &self,
        pos: usize,
        buffer: Rc<RefCell<crate::Buffer>>,
        c: Rc<Completion>,
    ) -> Result<()> {
        let mut file = self.file.borrow_mut();
        let mut buf = (&*buffer).borrow_mut();
        let buf_slice = buf.as_mut_slice();
        let wbufs = [IoSlice::new(buf_slice)];
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);
        {
            let mut aiow = mio_aio::Source::writev_at(file.as_fd(), pos as u64, &wbufs, 0);
            poll.registry()
                .register(&mut aiow, UDATA, Interest::AIO)
                .expect("registration failed");
            let mut aiow = Box::pin(aiow);

            aiow.as_mut().submit().unwrap();

            poll.poll(&mut events, None).expect("poll failed");
            let mut it = events.iter();
            let ev = it.next().unwrap();
            assert_eq!(ev.token(), UDATA);
            assert!(ev.is_aio());

            assert!(aiow.as_mut().error().is_ok());

            assert!(it.next().is_none());

            let _ = aiow.as_mut().aio_return();
        }
        file.rewind().unwrap();

        Ok(())
    }
}

impl Drop for FreeBSDFile {
    fn drop(&mut self) {
        self.unlock_file().expect("Failed to unlock file");
    }
}
