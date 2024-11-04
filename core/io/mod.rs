use crate::Result;
use cfg_block::cfg_block;
use std::fmt;
use std::{
    cell::{Ref, RefCell, RefMut},
    fmt::Debug,
    mem::ManuallyDrop,
    pin::Pin,
    rc::Rc,
};

pub trait File {
    fn lock_file(&self, exclusive: bool) -> Result<()>;
    fn unlock_file(&self) -> Result<()>;
    fn pread(&self, pos: usize, c: Rc<Completion>) -> Result<()>;
    fn pwrite(&self, pos: usize, buffer: Rc<RefCell<Buffer>>, c: Rc<Completion>) -> Result<()>;
}

pub trait IO {
    fn open_file(&self, path: &str) -> Result<Rc<dyn File>>;

    fn run_once(&self) -> Result<()>;

    fn generate_random_number(&self) -> i64;

    fn get_current_time(&self) -> String;
}

pub type Complete = dyn Fn(Rc<RefCell<Buffer>>);
pub type WriteComplete = dyn Fn(i32);

pub enum Completion {
    Read(ReadCompletion),
    Write(WriteCompletion),
}

pub struct ReadCompletion {
    pub buf: Rc<RefCell<Buffer>>,
    pub complete: Box<Complete>,
}

impl Completion {
    pub fn complete(&self, result: i32) {
        match self {
            Completion::Read(r) => r.complete(),
            Completion::Write(w) => w.complete(result), // fix
        }
    }
}

pub struct WriteCompletion {
    pub complete: Box<WriteComplete>,
}

impl ReadCompletion {
    pub fn new(buf: Rc<RefCell<Buffer>>, complete: Box<Complete>) -> Self {
        Self { buf, complete }
    }

    pub fn buf(&self) -> Ref<'_, Buffer> {
        self.buf.borrow()
    }

    pub fn buf_mut(&self) -> RefMut<'_, Buffer> {
        self.buf.borrow_mut()
    }

    pub fn complete(&self) {
        (self.complete)(self.buf.clone());
    }
}

impl WriteCompletion {
    pub fn new(complete: Box<WriteComplete>) -> Self {
        Self { complete }
    }
    pub fn complete(&self, bytes_written: i32) {
        (self.complete)(bytes_written);
    }
}

pub type BufferData = Pin<Vec<u8>>;

pub type BufferDropFn = Rc<dyn Fn(BufferData)>;

#[derive(Clone)]
pub struct Buffer {
    data: ManuallyDrop<BufferData>,
    drop: BufferDropFn,
}

impl Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let data = unsafe { ManuallyDrop::take(&mut self.data) };
        (self.drop)(data);
    }
}

impl Buffer {
    pub fn allocate(size: usize, drop: BufferDropFn) -> Self {
        let data = ManuallyDrop::new(Pin::new(vec![0; size]));
        Self { data, drop }
    }

    pub fn new(data: BufferData, drop: BufferDropFn) -> Self {
        let data = ManuallyDrop::new(data);
        Self { data, drop }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

cfg_block! {
    #[cfg(target_os = "freebsd")] {
        mod freebsd;
        pub use freebsd::FreeBSDIO as PlatformIO;
    }

    #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::LinuxIO as PlatformIO;
    }

    #[cfg(target_os = "macos")] {
        mod darwin;
        pub use darwin::DarwinIO as PlatformIO;
    }

    #[cfg(target_os = "windows")] {
        mod windows;
        pub use windows::WindowsIO as PlatformIO;
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "linux", target_os = "macos", target_os = "windows")))] {
        mod generic;
        pub use generic::GenericIO as PlatformIO;
    }
}

mod common;
