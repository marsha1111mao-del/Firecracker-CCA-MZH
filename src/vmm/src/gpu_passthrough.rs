//! GPU passthrough IRQ wiring for the local pmthor host device.

use crate::pmthor::{IrqIndex, PmThorDevice};
use kvm_ioctls::VmFd;
use libc::EFD_NONBLOCK;
use std::io;
use std::os::unix::io::AsRawFd;
use vmm_sys_util::eventfd::EventFd;

const GPU_IRQS: [IrqIndex; 3] = [IrqIndex::Job, IrqIndex::Mmu, IrqIndex::Gpu];

/// Eventfds used to bridge one physical GPU IRQ into one guest GSI.
#[derive(Debug)]
pub struct GpuIrqContext {
    trigger: EventFd,
    resample: EventFd,
    gsi: u32,
}

/// Owns the host pmthor session and the KVM irqfds for a passthrough GPU VM.
#[derive(Debug)]
pub struct GpuPassthroughManager {
    pmthor: PmThorDevice,
    irqs: Vec<GpuIrqContext>,
}

impl GpuPassthroughManager {
    /// Opens the pmthor device and allocates one trigger/resample eventfd pair per GPU IRQ.
    pub fn new(path: &str, base_gsi: u32) -> io::Result<Self> {
        let pmthor = PmThorDevice::open(path)?;
        let mut irqs = Vec::with_capacity(GPU_IRQS.len());

        for irq in 0..GPU_IRQS.len() {
            irqs.push(GpuIrqContext {
                trigger: EventFd::new(EFD_NONBLOCK)?,
                resample: EventFd::new(EFD_NONBLOCK)?,
                gsi: base_gsi + irq as u32,
            });
        }

        Ok(Self { pmthor, irqs })
    }

    /// Registers KVM irqfds and binds the host GPU IRQs to their trigger eventfds.
    pub fn attach_to_kvm(&self, vm_fd: &VmFd) -> io::Result<()> {
        self.pmthor.clean_irq()?;

        for irq_idx in 0..self.irqs.len() {
            if let Err(err) = self.attach_irq(vm_fd, irq_idx) {
                self.detach_attached_irqs(vm_fd, irq_idx);
                return Err(err);
            }
        }

        Ok(())
    }

    /// Tears down the KVM irqfds and clears the host pmthor IRQ session.
    pub fn detach_from_kvm(&self, vm_fd: &VmFd) -> io::Result<()> {
        self.detach_attached_irqs(vm_fd, self.irqs.len());
        self.pmthor.clean_irq()
    }

    fn attach_irq(&self, vm_fd: &VmFd, irq_idx: usize) -> io::Result<()> {
        let ctx = &self.irqs[irq_idx];
        let host_irq = GPU_IRQS[irq_idx];

        vm_fd
            .register_irqfd_with_resample(&ctx.trigger, &ctx.resample, ctx.gsi)
            .map_err(io::Error::from)?;

        if let Err(err) = self
            .pmthor
            .set_unmask_event(host_irq, ctx.resample.as_raw_fd())
        {
            let _ = self.unregister_irqfd(vm_fd, ctx);
            return Err(err);
        }

        if let Err(err) = self.pmthor.set_trigger(host_irq, ctx.trigger.as_raw_fd()) {
            let _ = self.pmthor.clear_unmask_event(host_irq);
            let _ = self.unregister_irqfd(vm_fd, ctx);
            return Err(err);
        }

        println!(
            "GpuPassthrough: Attached IRQ {} (GSI {}) with resample support",
            irq_idx, ctx.gsi
        );
        Ok(())
    }

    fn detach_attached_irqs(&self, vm_fd: &VmFd, count: usize) {
        for irq_idx in 0..count.min(self.irqs.len()) {
            let ctx = &self.irqs[irq_idx];
            let host_irq = GPU_IRQS[irq_idx];

            let _ = self.pmthor.clear_unmask_event(host_irq);
            let _ = self.pmthor.clear_trigger(host_irq);
            let _ = self.unregister_irqfd(vm_fd, ctx);
        }
    }

    fn unregister_irqfd(&self, vm_fd: &VmFd, ctx: &GpuIrqContext) -> io::Result<()> {
        vm_fd
            .unregister_irqfd(&ctx.trigger, ctx.gsi)
            .map_err(io::Error::from)
    }
}
