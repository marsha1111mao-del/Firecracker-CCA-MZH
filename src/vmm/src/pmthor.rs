//! Userspace wrapper for the local pmthor VFIO-style IRQ control device.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

const VFIO_IRQ_SET_DATA_EVENTFD: u32 = 1 << 2;
const VFIO_IRQ_SET_ACTION_UNMASK: u32 = 1 << 4;
const VFIO_IRQ_SET_ACTION_TRIGGER: u32 = 1 << 5;
const VFIO_IRQ_CLEAN: u32 = 1 << 6;

const PMTHOR_IOCTL_SET_IRQS: i32 = 0x40145001 as i32;

#[repr(u32)]
/// Physical GPU IRQ indices exposed by the host pmthor driver.
#[derive(Clone, Copy, Debug)]
pub enum IrqIndex {
    /// Job manager interrupt.
    Job = 0,
    /// MMU interrupt.
    Mmu = 1,
    /// GPU control interrupt.
    Gpu = 2,
}

#[repr(C)]
/// Header shared with the pmthor `PMTHOR_IOCTL_SET_IRQS` ioctl.
#[derive(Debug)]
pub struct VfioIrqSet {
    /// Size of the ioctl payload.
    pub argsz: u32,
    /// VFIO-style data and action flags.
    pub flags: u32,
    /// IRQ index.
    pub index: u32,
    /// First IRQ in the range.
    pub start: u32,
    /// Number of IRQs in the range.
    pub count: u32,
}

#[repr(C)]
struct IrqSetPayload {
    hdr: VfioIrqSet,
    fd: i32,
}
/// File-backed handle for `/dev/pmthor`.
#[derive(Debug)]
pub struct PmThorDevice {
    file: File,
}

impl PmThorDevice {
    /// Opens a pmthor misc device.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
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

        let ret =
            unsafe { libc::ioctl(self.file.as_raw_fd(), PMTHOR_IOCTL_SET_IRQS, &payload.hdr) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn clear_irq_raw(&self, index: IrqIndex, action: u32) -> io::Result<()> {
        let hdr = VfioIrqSet {
            argsz: std::mem::size_of::<VfioIrqSet>() as u32,
            flags: action,
            index: index as u32,
            start: 0,
            count: 0,
        };

        let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), PMTHOR_IOCTL_SET_IRQS, &hdr) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Installs an eventfd that is signaled when the selected physical IRQ fires.
    pub fn set_trigger(&self, index: IrqIndex, fd: RawFd) -> io::Result<()> {
        self.set_irq_raw(index, VFIO_IRQ_SET_ACTION_TRIGGER, fd)
    }

    /// Removes the trigger eventfd for the selected physical IRQ.
    pub fn clear_trigger(&self, index: IrqIndex) -> io::Result<()> {
        self.clear_irq_raw(index, VFIO_IRQ_SET_ACTION_TRIGGER)
    }

    /// Installs an eventfd that unmasks the selected physical IRQ after guest EOI.
    pub fn set_unmask_event(&self, index: IrqIndex, fd: RawFd) -> io::Result<()> {
        self.set_irq_raw(index, VFIO_IRQ_SET_ACTION_UNMASK, fd)
    }

    /// Removes the unmask eventfd for the selected physical IRQ.
    pub fn clear_unmask_event(&self, index: IrqIndex) -> io::Result<()> {
        self.set_irq_raw(index, VFIO_IRQ_SET_ACTION_UNMASK, -1)
    }

    /// Clears all pmthor IRQ bindings owned by this device session.
    pub fn clean_irq(&self) -> io::Result<()> {
        let hdr = VfioIrqSet {
            argsz: std::mem::size_of::<VfioIrqSet>() as u32,
            flags: VFIO_IRQ_CLEAN,
            index: 0,
            start: 0,
            count: 0,
        };

        let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), PMTHOR_IOCTL_SET_IRQS, &hdr) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
