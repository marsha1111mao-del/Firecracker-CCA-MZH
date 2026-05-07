// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::ptr;

use kvm_bindings::{kvm_create_guest_memfd, kvm_userspace_memory_region, kvm_userspace_memory_region2, KVM_MEM_GUEST_MEMFD, KVM_MEM_LOG_DIRTY_PAGES, KVM_VM_TYPE_ARM_NORMAL, KVM_VM_TYPE_ARM_REALM};
use kvm_ioctls::{Cap, VmFd};
use libc::{MAP_SHARED, PROT_READ, PROT_WRITE, off_t};
use vm_memory::guest_memory;
use vmm_sys_util::eventfd::EventFd;

use crate::arch::aarch64::layout;
use crate::dumbo::pdu::tcp::Flags;
use crate::logger::info;
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

pub use arch::{ArchVm as Vm, ArchVmError, VmState};

use crate::vstate::vcpu::VcpuError;
use crate::Vcpu;

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// Failed to create VM: {0}
    CreateVm(kvm_ioctls::Error),
    /// {0}
    Arch(#[from] ArchVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// Cannot create guest memory memfd: {0}
    CreateGuestMemFd(kvm_ioctls::Error),
}

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    #[cfg(all(target_arch = "aarch64", feature = "rme"))]
    fn create_vm(kvm: &crate::vstate::kvm::Kvm, machine_config: MachineConfig) -> Result<VmFd, VmError> {
        let vm_type = if machine_config.realm_config.is_some() {
            KVM_VM_TYPE_ARM_REALM
        } else {
            KVM_VM_TYPE_ARM_NORMAL
        };

        let ipa_size = u64::BITS - (layout::DRAM_MEM_START + ((machine_config.mem_size_mib as u64) << 20)).leading_zeros() + 1;
        if kvm.fd.check_extension(Cap::ArmVmIPASize) {
            let max_ipa_size = kvm.fd.get_host_ipa_limit();
            if ipa_size > max_ipa_size as u32 {
                return Err(VmError::CreateVm(kvm_ioctls::Error::new(libc::EINVAL)));
            }
        }
        let mut ipa_bit_shift = u64::BITS - ipa_size.leading_zeros();
        if machine_config.realm_config.is_some() {
            ipa_bit_shift += 1;
        }

        println!("ipa_bit_shift: {ipa_bit_shift}");
        
        // It is known that KVM_CREATE_VM occasionally fails with EINTR on heavily loaded machines
        // with many VMs.
        //
        // The behavior itself that KVM_CREATE_VM can return EINTR is intentional. This is because
        // the KVM_CREATE_VM path includes mm_take_all_locks() that is CPU intensive and all CPU
        // intensive syscalls should check for pending signals and return EINTR immediately to allow
        // userland to remain interactive.
        // https://lists.nongnu.org/archive/html/qemu-devel/2014-01/msg01740.html
        //
        // However, it is empirically confirmed that, even though there is no pending signal,
        // KVM_CREATE_VM returns EINTR.
        // https://lore.kernel.org/qemu-devel/8735e0s1zw.wl-maz@kernel.org/
        //
        // To mitigate it, QEMU does an inifinite retry on EINTR that greatly improves reliabiliy:
        // - https://github.com/qemu/qemu/commit/94ccff133820552a859c0fb95e33a539e0b90a75
        // - https://github.com/qemu/qemu/commit/bbde13cd14ad4eec18529ce0bf5876058464e124
        //
        // Similarly, we do retries up to 5 times. Although Firecracker clients are also able to
        // retry, they have to start Firecracker from scratch. Doing retries in Firecracker makes
        // recovery faster and improves reliability.
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match kvm.fd.create_vm_with_type((vm_type | ipa_bit_shift) as u64) {
                Ok(fd) => return Ok(fd),
                Err(e) if e.errno() == libc::EINTR && attempt < MAX_ATTEMPTS => {
                    info!("Attempt #{attempt} of KVM_CREATE_VM returned EINTR");
                    // Exponential backoff (1us, 2us, 4us, and 8us => 15us in total)
                    std::thread::sleep(std::time::Duration::from_micros(2u64.pow(attempt - 1)));
                }
                Err(e) => return Err(VmError::CreateVm(e)),
            }
        }
        unreachable!();
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "rme")))]
    fn create_vm(kvm: &crate::vstate::kvm::Kvm, machine_config: MachineConfig) -> Result<VmFd, VmError> {
        // It is known that KVM_CREATE_VM occasionally fails with EINTR on heavily loaded machines
        // with many VMs.
        //
        // The behavior itself that KVM_CREATE_VM can return EINTR is intentional. This is because
        // the KVM_CREATE_VM path includes mm_take_all_locks() that is CPU intensive and all CPU
        // intensive syscalls should check for pending signals and return EINTR immediately to allow
        // userland to remain interactive.
        // https://lists.nongnu.org/archive/html/qemu-devel/2014-01/msg01740.html
        //
        // However, it is empirically confirmed that, even though there is no pending signal,
        // KVM_CREATE_VM returns EINTR.
        // https://lore.kernel.org/qemu-devel/8735e0s1zw.wl-maz@kernel.org/
        //
        // To mitigate it, QEMU does an inifinite retry on EINTR that greatly improves reliabiliy:
        // - https://github.com/qemu/qemu/commit/94ccff133820552a859c0fb95e33a539e0b90a75
        // - https://github.com/qemu/qemu/commit/bbde13cd14ad4eec18529ce0bf5876058464e124
        //
        // Similarly, we do retries up to 5 times. Although Firecracker clients are also able to
        // retry, they have to start Firecracker from scratch. Doing retries in Firecracker makes
        // recovery faster and improves reliability.
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match kvm.fd.create_vm() {
                Ok(fd) => return Ok(fd),
                Err(e) if e.errno() == libc::EINTR && attempt < MAX_ATTEMPTS => {
                    info!("Attempt #{attempt} of KVM_CREATE_VM returned EINTR");
                    // Exponential backoff (1us, 2us, 4us, and 8us => 15us in total)
                    std::thread::sleep(std::time::Duration::from_micros(2u64.pow(attempt - 1)));
                }
                Err(e) => return Err(VmError::CreateVm(e)),
            }
        }
        unreachable!();
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// The returned [`EventFd`] is written to whenever any of the vcpus exit.
    pub fn create_vcpus(&mut self, vcpu_count: u8) -> Result<(Vec<Vcpu>, EventFd), VmError> {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        for cpu_idx in 0..vcpu_count {
            let exit_evt = exit_evt.try_clone().map_err(VmError::EventFd)?;
            let vcpu = Vcpu::new(cpu_idx, self, exit_evt).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok((vcpus, exit_evt))
    }

    /// Initializes the guest memory.
    pub fn memory_init(&self, guest_mem: &GuestMemoryMmap) -> Result<(), VmError> {
        self.set_kvm_memory_regions2(guest_mem)
    }

    pub(crate) fn create_guest_memfd(
        &self,
        mem_size_mib: usize,
    ) -> Result<File, VmError> { 
        let kvm_create_guest_memfd_args = kvm_create_guest_memfd {
          size: (mem_size_mib << 20) as u64,
            ..Default::default()
        };
        // SAFETY: Safe because the fd is a valid KVM file descriptor.
        let raw_fd = self.fd.create_guest_memfd(kvm_create_guest_memfd_args)
            .map_err(VmError::CreateGuestMemFd)?;
        // SAFETY: Safe because create_guest_memfd() already checked the fd.
        unsafe { Ok(File::from_raw_fd(raw_fd)) }
    }

    pub(crate) fn set_kvm_memory_regions(
        &self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<(), VmError> {
        guest_mem
            .iter()
            .zip(0u32..)
            .try_for_each(|(region, slot)| {
                let flags = if region.bitmap().is_some() {
                    KVM_MEM_LOG_DIRTY_PAGES
                } else {
                    0
                };

                let memory_region = kvm_userspace_memory_region {
                    slot,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    userspace_addr: region.as_ptr() as u64,
                    flags,
                };

                // SAFETY: Safe because the fd is a valid KVM file descriptor.
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
            .map_err(VmError::SetUserMemoryRegion)?;
        Ok(())
    }

    pub(crate) fn set_kvm_memory_regions2(
        &self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<(), VmError> {
        guest_mem
            .iter()
            .zip(0u32..)
            .try_for_each(|(region, slot)| {
                let flags = if region.bitmap().is_some() {
                    KVM_MEM_LOG_DIRTY_PAGES
                } else {
                    0
                };
                let mut memory_region2 = kvm_userspace_memory_region2 {
                    slot,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    userspace_addr: region.as_ptr() as u64,
                    flags,
                    ..Default::default()
                };
                if region.guest_memfd_file_offset().is_some() {
                    memory_region2.flags |= KVM_MEM_GUEST_MEMFD;
                    memory_region2.guest_memfd = region.guest_memfd_file_offset().unwrap().file().as_raw_fd() as u32;
                    memory_region2.guest_memfd_offset = region.guest_memfd_file_offset().unwrap().start();
                }

                // SAFETY: Safe because the fd is a valid KVM file descriptor.
                unsafe { self.fd.set_user_memory_region2(memory_region2) }
            })
            .map_err(VmError::SetUserMemoryRegion)?;
        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_utils::single_region_mem;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::GuestMemoryMmap;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> (Kvm, Vm) {
        let vm_config = MachineConfig {
            ..Default::default()
        };
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let vm = Vm::new(&kvm, vm_config).expect("Cannot create new vm");
        (kvm, vm)
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> (Kvm, Vm, GuestMemoryMmap) {
        let (kvm, vm) = setup_vm();
        let gm = single_region_mem(mem_size);
        vm.memory_init(&gm).unwrap();
        (kvm, vm, gm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
    let vm_config = MachineConfig {
        realm_config: Some(RealmConfig::new(Some("SHA256".to_string()), Some([0u8; 64]))),
        ..Default::default()
    };
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        Vm::new(&kvm, vm_config).unwrap();
    }

    #[test]
    fn test_vm_memory_init() {
        let (_, vm) = setup_vm();
        // Create valid memory region and test that the initialization is successful.
        let gm = single_region_mem(0x1000);
        vm.memory_init(&gm).unwrap();
    }

    #[test]
    fn test_set_kvm_memory_regions() {
        let (_, vm) = setup_vm();

        let gm = single_region_mem(0x1000);
        let res = vm.set_kvm_memory_regions(&gm);
        res.unwrap();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem(0x10);
        let res = vm.set_kvm_memory_regions(&gm);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );
    }

    #[test]
    fn test_create_vcpus() {
        let vcpu_count = 2;
        let (_, mut vm, _) = setup_vm_with_memory(128 << 20);

        let (vcpu_vec, _) = vm.create_vcpus(vcpu_count).unwrap();

        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }
}
