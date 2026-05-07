use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::io;

// --- VFIO 协议常量 ---
const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
const VFIO_IRQ_SET_ACTION_MASK: u32 = 1 << 3;
const VFIO_IRQ_SET_ACTION_UNMASK: u32 = 1 << 4;
const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;

// 手动计算 IOCTL 码: _IOW('P', 0x01, VfioIrqSet) -> 0x40145001
const PMTHOR_IOCTL_SET_IRQS:i32 = 0x40145001 as i32;

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum IrqIndex {
    Job = 0,
    Mmu = 1,
    Gpu = 2,
}

#[repr(C)]
pub struct VfioIrqSet {
    pub argsz: u32,
    pub flags: u32,
    pub index: u32,
    pub start: u32,
    pub count: u32,
}

#[repr(C)]
struct IrqSetPayload {
    hdr: VfioIrqSet,
    fd: i32,
}

pub struct PmThorDevice {
    file: File,
}

impl PmThorDevice {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self { file })
    }

    fn set_irq_raw(&self, index: IrqIndex, action: u32, fd: RawFd) -> io::Result<()> {
        let payload = IrqSetPayload {
            hdr: VfioIrqSet {
                argsz: std::mem::size_of::<IrqSetPayload>() as u32,
                flags: VFIO_IRQ_SET_DATA_EVENTFD | action,
                index: index as u32,
                start: 0,
                count: 1,
            },
            fd,
        };

        let ret = unsafe {
            libc::ioctl(self.file.as_raw_fd(), PMTHOR_IOCTL_SET_IRQS, &payload.hdr)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn set_trigger(&self, index: IrqIndex, fd: RawFd) -> io::Result<()> {
        self.set_irq_raw(index, VFIO_IRQ_SET_ACTION_TRIGGER, fd)
    }

    pub fn set_unmask_event(&self, index: IrqIndex, fd: RawFd) -> io::Result<()> {
        self.set_irq_raw(index, VFIO_IRQ_SET_ACTION_UNMASK, fd)
    }
}