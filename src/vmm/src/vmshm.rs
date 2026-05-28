// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use kvm_bindings::kvm_userspace_memory_region2;
use kvm_ioctls::{IoEventAddress, NoDatamatch};
use log::info;
use vmm_sys_util::eventfd::EventFd;

use crate::arch::GUEST_PAGE_SIZE;
use crate::vmm_config::vmshm::VmshmDeviceConfig;
use crate::vstate::memory::{
    Address, FileOffset, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, MmapRegion,
    MmapRegionBuilder,
};
use crate::Vmm;

const VMSHM_MAGIC: u32 = u32::from_le_bytes(*b"VMSH");
const VMSHM_VERSION: u16 = 1;
const REQUEST_HEADER_LEN: usize = 12;
const REQUEST_FLAG_NOTIFY: u16 = 1 << 0;
const REQUEST_NOTIFY_LEN: usize = 24;
const REPLY_LEN: usize = 40;
const STATUS_OK: u16 = 0;

#[derive(Clone, Copy, Debug)]
struct VmshmHandshakeReply {
    magic: u32,
    version: u16,
    status: u16,
    window_size: u64,
    guest_phys_addr: u64,
    slot: u32,
    flags: u32,
    generation: u64,
}

impl VmshmHandshakeReply {
    fn from_bytes(bytes: &[u8; REPLY_LEN]) -> Self {
        Self {
            magic: u32::from_le_bytes(bytes[0..4].try_into().expect("slice length checked")),
            version: u16::from_le_bytes(bytes[4..6].try_into().expect("slice length checked")),
            status: u16::from_le_bytes(bytes[6..8].try_into().expect("slice length checked")),
            window_size: u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked")),
            guest_phys_addr: u64::from_le_bytes(
                bytes[16..24].try_into().expect("slice length checked"),
            ),
            slot: u32::from_le_bytes(bytes[24..28].try_into().expect("slice length checked")),
            flags: u32::from_le_bytes(bytes[28..32].try_into().expect("slice length checked")),
            generation: u64::from_le_bytes(bytes[32..40].try_into().expect("slice length checked")),
        }
    }
}

/// Device-tree information for a registered vmshm memory window.
#[derive(Clone, Debug)]
pub struct VmshmFdtInfo {
    /// FDT node name.
    pub node_name: String,
    /// FDT compatible string.
    pub compatible: String,
    /// Guest physical base address.
    pub guest_phys_addr: u64,
    /// Window size in bytes.
    pub size: u64,
    /// Optional interrupt notification information.
    pub notify: Option<VmshmNotifyFdtInfo>,
}

/// Device-tree information for vmshm ioeventfd/irqfd notification.
#[derive(Clone, Debug)]
pub struct VmshmNotifyFdtInfo {
    /// Doorbell MMIO base address.
    pub doorbell_addr: u64,
    /// Doorbell MMIO size.
    pub doorbell_size: u64,
    /// KVM GSI/FDT interrupt number.
    pub irq: u32,
}

#[derive(Debug)]
pub(crate) struct VmshmRegion {
    config: VmshmDeviceConfig,
    mmap: MmapRegion<()>,
    window_size: u64,
    flags: u32,
    generation: u64,
    notify: Option<VmshmNotifyRegion>,
}

#[derive(Debug)]
struct VmshmNotifyRegion {
    kick_evt: EventFd,
    irq_evt: EventFd,
}

impl VmshmRegion {
    pub(crate) fn fdt_info(&self) -> VmshmFdtInfo {
        VmshmFdtInfo {
            node_name: fdt_node_name(&self.config),
            compatible: fdt_compatible(&self.config),
            guest_phys_addr: self.config.guest_phys_addr,
            size: self.window_size,
            notify: self
                .config
                .notify
                .as_ref()
                .map(|notify| VmshmNotifyFdtInfo {
                    doorbell_addr: notify.doorbell_addr,
                    doorbell_size: notify.doorbell_size,
                    irq: notify.irq,
                }),
        }
    }
}

/// Errors returned while attaching vmshm broker-backed memory.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmshmError {
    /// vmshm participant name must not be empty
    EmptyName,
    /// vmshm participant name is too long: {0} bytes
    NameTooLong(usize),
    /// vmshm FDT node name must not be empty
    EmptyFdtNodeName,
    /// vmshm FDT compatible string must not be empty
    EmptyFdtCompatible,
    /// cannot connect to vmshm broker socket {socket_path}: {source}
    Connect {
        /// Broker socket path.
        socket_path: String,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// cannot write vmshm broker handshake request: {0}
    WriteRequest(io::Error),
    /// cannot receive vmshm broker handshake reply: {0}
    RecvReply(io::Error),
    /// short vmshm broker reply: expected 40 bytes, got {0}
    ShortReply(usize),
    /// vmshm broker reply did not include a memfd
    MissingFd,
    /// vmshm broker returned bad magic: {0:#x}
    BadMagic(u32),
    /// vmshm broker returned unsupported version: {0}
    BadVersion(u16),
    /// vmshm broker rejected the handshake with status {0}
    BrokerStatus(u16),
    /// vmshm broker returned an empty memory window
    EmptyWindow,
    /// vmshm window size {0} is not guest-page aligned
    WindowSizeNotAligned(u64),
    /// vmshm guest physical address {0:#x} is not guest-page aligned
    GuestAddressNotAligned(u64),
    /// vmshm broker window is too small: expected at least {expected}, got {actual}
    SizeMismatch {
        /// Expected minimum window size.
        expected: u64,
        /// Actual broker window size.
        actual: u64,
    },
    /// vmshm memory window {base:#x}..{end:#x} overlaps guest RAM
    OverlapsGuestMemory {
        /// Window base.
        base: u64,
        /// Exclusive window end.
        end: u64,
    },
    /// vmshm memory window {base:#x}..{end:#x} overlaps another vmshm window {other_base:#x}..{other_end:#x}
    OverlapsVmshmMemory {
        /// Window base.
        base: u64,
        /// Exclusive window end.
        end: u64,
        /// Other window base.
        other_base: u64,
        /// Other exclusive window end.
        other_end: u64,
    },
    /// vmshm KVM slot {0} collides with guest RAM slots
    SlotCollidesWithGuestMemory(u32),
    /// duplicate vmshm KVM slot {0}
    DuplicateSlot(u32),
    /// duplicate vmshm FDT node name {0}
    DuplicateFdtNodeName(String),
    /// vmshm memory window overflows the guest physical address space
    AddressOverflow,
    /// vmshm memory window is too large to mmap on this host: {0}
    WindowTooLarge(u64),
    /// cannot mmap vmshm memfd: {0}
    Mmap(vm_memory::mmap::MmapRegionError),
    /// KVM rejected vmshm memory slot: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// cannot create vmshm notify eventfd: {0}
    EventFd(io::Error),
    /// vmshm notify doorbell address {0:#x} is not guest-page aligned
    DoorbellAddressNotAligned(u64),
    /// vmshm notify doorbell size {0:#x} is invalid
    InvalidDoorbellSize(u64),
    /// vmshm notify IRQ {0} is outside the supported GSI range
    InvalidNotifyIrq(u32),
    /// vmshm notify doorbell {base:#x}..{end:#x} overlaps guest RAM
    DoorbellOverlapsGuestMemory {
        /// Doorbell base.
        base: u64,
        /// Exclusive doorbell end.
        end: u64,
    },
    /// vmshm notify doorbell {base:#x}..{end:#x} overlaps another vmshm range {other_base:#x}..{other_end:#x}
    DoorbellOverlapsVmshmRange {
        /// Doorbell base.
        base: u64,
        /// Exclusive doorbell end.
        end: u64,
        /// Other range base.
        other_base: u64,
        /// Other exclusive range end.
        other_end: u64,
    },
    /// KVM rejected vmshm notify ioeventfd: {0}
    RegisterIoEvent(kvm_ioctls::Error),
    /// KVM rejected vmshm notify irqfd: {0}
    RegisterIrqFd(kvm_ioctls::Error),
}

pub(crate) fn attach_vmshm_regions(
    vmm: &mut Vmm,
    configs: &[VmshmDeviceConfig],
) -> Result<(), VmshmError> {
    let mut used_slots: Vec<u32> = vmm
        .vmshm_regions
        .iter()
        .map(|region| region.config.slot)
        .collect();
    let mut used_ranges: Vec<(u64, u64)> = vmm
        .vmshm_regions
        .iter()
        .map(|region| {
            let base = region.config.guest_phys_addr;
            (base, base.saturating_add(region.window_size))
        })
        .collect();
    let mut used_fdt_node_names: Vec<String> = vmm
        .vmshm_regions
        .iter()
        .map(|region| fdt_node_name(&region.config))
        .collect();

    for config in configs {
        validate_fdt_config(config, &used_fdt_node_names)?;
        let region = connect_and_map_region(config)?;
        validate_region(&vmm.guest_memory, &region, &used_slots, &used_ranges)?;
        register_region(vmm, &region)?;
        register_notify(vmm, &region)?;
        info!(
            "registered vmshm window name={} socket={} fdt_node={} fdt_compatible={} gpa={:#x} size={:#x} slot={} flags={:#x} generation={}",
            region.config.name,
            region.config.socket_path,
            fdt_node_name(&region.config),
            fdt_compatible(&region.config),
            region.config.guest_phys_addr,
            region.window_size,
            region.config.slot,
            region.flags,
            region.generation
        );
        used_slots.push(region.config.slot);
        used_ranges.push((
            region.config.guest_phys_addr,
            region
                .config
                .guest_phys_addr
                .checked_add(region.window_size)
                .ok_or(VmshmError::AddressOverflow)?,
        ));
        if let Some(notify) = region.config.notify.as_ref() {
            let doorbell_end = notify
                .doorbell_addr
                .checked_add(notify.doorbell_size)
                .ok_or(VmshmError::AddressOverflow)?;
            used_ranges.push((notify.doorbell_addr, doorbell_end));
            info!(
                "registered vmshm notify name={} doorbell={:#x} size={:#x} irq={}",
                region.config.name, notify.doorbell_addr, notify.doorbell_size, notify.irq
            );
        }
        used_fdt_node_names.push(fdt_node_name(&region.config));
        vmm.vmshm_regions.push(region);
    }

    Ok(())
}

fn validate_fdt_config(
    config: &VmshmDeviceConfig,
    used_fdt_node_names: &[String],
) -> Result<(), VmshmError> {
    let node_name = fdt_node_name(config);
    if node_name.is_empty() {
        return Err(VmshmError::EmptyFdtNodeName);
    }
    if used_fdt_node_names.contains(&node_name) {
        return Err(VmshmError::DuplicateFdtNodeName(node_name));
    }
    if fdt_compatible(config).is_empty() {
        return Err(VmshmError::EmptyFdtCompatible);
    }

    Ok(())
}

fn fdt_node_name(config: &VmshmDeviceConfig) -> String {
    config
        .fdt_node_name
        .clone()
        .unwrap_or_else(|| format!("vmshm@{:x}", config.guest_phys_addr))
}

fn fdt_compatible(config: &VmshmDeviceConfig) -> String {
    config
        .fdt_compatible
        .clone()
        .unwrap_or_else(|| "vmshm".to_string())
}

fn connect_and_map_region(config: &VmshmDeviceConfig) -> Result<VmshmRegion, VmshmError> {
    if config.name.is_empty() {
        return Err(VmshmError::EmptyName);
    }
    if config.name.len() > u16::MAX as usize {
        return Err(VmshmError::NameTooLong(config.name.len()));
    }

    let notify = create_notify_region(config)?;
    let mut stream =
        UnixStream::connect(&config.socket_path).map_err(|source| VmshmError::Connect {
            socket_path: config.socket_path.clone(),
            source,
        })?;
    let request = build_request(config);
    send_request(&mut stream, &request, notify.as_ref())?;

    let (reply, file) = recv_reply_with_fd(stream.as_raw_fd())?;
    let mapped_window_size = validate_reply(config, &reply)?;
    if reply.guest_phys_addr != 0 || reply.slot != 0 {
        info!(
            "ignoring vmshm broker-suggested gpa={:#x} slot={}; Firecracker config uses gpa={:#x} slot={}",
            reply.guest_phys_addr,
            reply.slot,
            config.guest_phys_addr,
            config.slot
        );
    }
    if mapped_window_size < reply.window_size {
        info!(
            "mapping vmshm window name={} socket={} with configured size {:#x}; broker provided larger window {:#x}",
            config.name,
            config.socket_path,
            mapped_window_size,
            reply.window_size
        );
    }
    let window_size = usize::try_from(mapped_window_size)
        .map_err(|_| VmshmError::WindowTooLarge(mapped_window_size))?;

    let mmap = MmapRegionBuilder::new(window_size)
        .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
        .with_mmap_flags(libc::MAP_SHARED)
        .with_file_offset(FileOffset::new(file, 0))
        .build()
        .map_err(VmshmError::Mmap)?;

    Ok(VmshmRegion {
        config: config.clone(),
        mmap,
        window_size: mapped_window_size,
        flags: reply.flags,
        generation: reply.generation,
        notify,
    })
}

fn build_request(config: &VmshmDeviceConfig) -> Vec<u8> {
    let name = config.name.as_bytes();
    let notify_len = if config.notify.is_some() {
        REQUEST_NOTIFY_LEN
    } else {
        0
    };
    let mut request = Vec::with_capacity(REQUEST_HEADER_LEN + name.len() + notify_len);
    request.extend_from_slice(&VMSHM_MAGIC.to_le_bytes());
    request.extend_from_slice(&VMSHM_VERSION.to_le_bytes());
    request.extend_from_slice(&config.role.as_wire().to_le_bytes());
    let name_len = u16::try_from(name.len()).expect("vmshm participant name length checked");
    request.extend_from_slice(&name_len.to_le_bytes());
    let flags = if config.notify.is_some() {
        REQUEST_FLAG_NOTIFY
    } else {
        0
    };
    request.extend_from_slice(&flags.to_le_bytes());
    request.extend_from_slice(name);
    if let Some(notify) = config.notify.as_ref() {
        request.extend_from_slice(&notify.irq.to_le_bytes());
        request.extend_from_slice(&0u32.to_le_bytes());
        request.extend_from_slice(&notify.doorbell_addr.to_le_bytes());
        request.extend_from_slice(&notify.doorbell_size.to_le_bytes());
    }
    request
}

fn validate_reply(
    config: &VmshmDeviceConfig,
    reply: &VmshmHandshakeReply,
) -> Result<u64, VmshmError> {
    if reply.magic != VMSHM_MAGIC {
        return Err(VmshmError::BadMagic(reply.magic));
    }
    if reply.version != VMSHM_VERSION {
        return Err(VmshmError::BadVersion(reply.version));
    }
    if reply.status != STATUS_OK {
        return Err(VmshmError::BrokerStatus(reply.status));
    }
    if reply.window_size == 0 {
        return Err(VmshmError::EmptyWindow);
    }
    let guest_page_size = u64::try_from(GUEST_PAGE_SIZE).expect("guest page size fits in u64");
    if reply.window_size % guest_page_size != 0 {
        return Err(VmshmError::WindowSizeNotAligned(reply.window_size));
    }
    if config.guest_phys_addr % guest_page_size != 0 {
        return Err(VmshmError::GuestAddressNotAligned(config.guest_phys_addr));
    }
    if let Some(expected) = config.expected_size {
        if expected == 0 {
            return Err(VmshmError::EmptyWindow);
        }
        if expected % guest_page_size != 0 {
            return Err(VmshmError::WindowSizeNotAligned(expected));
        }
        if expected > reply.window_size {
            return Err(VmshmError::SizeMismatch {
                expected,
                actual: reply.window_size,
            });
        }
        return Ok(expected);
    }

    Ok(reply.window_size)
}

fn validate_region(
    guest_memory: &GuestMemoryMmap,
    region: &VmshmRegion,
    used_slots: &[u32],
    used_ranges: &[(u64, u64)],
) -> Result<(), VmshmError> {
    let base = region.config.guest_phys_addr;
    let end = base
        .checked_add(region.window_size)
        .ok_or(VmshmError::AddressOverflow)?;
    let guest_memory_slots = u32::try_from(guest_memory.iter().count()).unwrap_or(u32::MAX);

    if region.config.slot < guest_memory_slots {
        return Err(VmshmError::SlotCollidesWithGuestMemory(region.config.slot));
    }
    if used_slots.contains(&region.config.slot) {
        return Err(VmshmError::DuplicateSlot(region.config.slot));
    }

    for guest_region in guest_memory.iter() {
        let guest_base = guest_region.start_addr().raw_value();
        let guest_end = guest_base
            .checked_add(guest_region.len())
            .ok_or(VmshmError::AddressOverflow)?;
        if ranges_overlap(base, end, guest_base, guest_end) {
            return Err(VmshmError::OverlapsGuestMemory { base, end });
        }
    }

    for (other_base, other_end) in used_ranges {
        if ranges_overlap(base, end, *other_base, *other_end) {
            return Err(VmshmError::OverlapsVmshmMemory {
                base,
                end,
                other_base: *other_base,
                other_end: *other_end,
            });
        }
    }

    if let Some(notify) = region.config.notify.as_ref() {
        let guest_page_size = u64::try_from(GUEST_PAGE_SIZE).expect("guest page size fits in u64");
        let doorbell_base = notify.doorbell_addr;
        let doorbell_size = notify.doorbell_size;
        let doorbell_end = doorbell_base
            .checked_add(doorbell_size)
            .ok_or(VmshmError::AddressOverflow)?;

        if doorbell_base % guest_page_size != 0 {
            return Err(VmshmError::DoorbellAddressNotAligned(doorbell_base));
        }
        if doorbell_size == 0 || doorbell_size % guest_page_size != 0 {
            return Err(VmshmError::InvalidDoorbellSize(doorbell_size));
        }
        if notify.irq < crate::arch::IRQ_BASE || notify.irq > crate::arch::IRQ_MAX {
            return Err(VmshmError::InvalidNotifyIrq(notify.irq));
        }

        for guest_region in guest_memory.iter() {
            let guest_base = guest_region.start_addr().raw_value();
            let guest_end = guest_base
                .checked_add(guest_region.len())
                .ok_or(VmshmError::AddressOverflow)?;
            if ranges_overlap(doorbell_base, doorbell_end, guest_base, guest_end) {
                return Err(VmshmError::DoorbellOverlapsGuestMemory {
                    base: doorbell_base,
                    end: doorbell_end,
                });
            }
        }

        if ranges_overlap(doorbell_base, doorbell_end, base, end) {
            return Err(VmshmError::DoorbellOverlapsVmshmRange {
                base: doorbell_base,
                end: doorbell_end,
                other_base: base,
                other_end: end,
            });
        }

        for (other_base, other_end) in used_ranges {
            if ranges_overlap(doorbell_base, doorbell_end, *other_base, *other_end) {
                return Err(VmshmError::DoorbellOverlapsVmshmRange {
                    base: doorbell_base,
                    end: doorbell_end,
                    other_base: *other_base,
                    other_end: *other_end,
                });
            }
        }
    }

    Ok(())
}

fn ranges_overlap(left_base: u64, left_end: u64, right_base: u64, right_end: u64) -> bool {
    left_base < right_end && right_base < left_end
}

fn register_region(vmm: &Vmm, region: &VmshmRegion) -> Result<(), VmshmError> {
    let memory_region = kvm_userspace_memory_region2 {
        slot: region.config.slot,
        guest_phys_addr: region.config.guest_phys_addr,
        memory_size: region.window_size,
        userspace_addr: region.mmap.as_ptr() as u64,
        flags: 0,
        ..Default::default()
    };

    // SAFETY: The KVM fd belongs to this VM, and the mmap backing the userspace address is kept
    // alive in `Vmm::vmshm_regions` until VM teardown.
    unsafe { vmm.vm.fd().set_user_memory_region2(memory_region) }
        .map_err(VmshmError::SetUserMemoryRegion)
}

fn create_notify_region(
    config: &VmshmDeviceConfig,
) -> Result<Option<VmshmNotifyRegion>, VmshmError> {
    if config.notify.is_none() {
        return Ok(None);
    }

    Ok(Some(VmshmNotifyRegion {
        kick_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VmshmError::EventFd)?,
        irq_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VmshmError::EventFd)?,
    }))
}

fn register_notify(vmm: &Vmm, region: &VmshmRegion) -> Result<(), VmshmError> {
    let Some(notify_config) = region.config.notify.as_ref() else {
        return Ok(());
    };
    let Some(notify) = region.notify.as_ref() else {
        return Ok(());
    };

    let io_addr = IoEventAddress::Mmio(notify_config.doorbell_addr);
    vmm.vm
        .fd()
        .register_ioevent(&notify.kick_evt, &io_addr, NoDatamatch)
        .map_err(VmshmError::RegisterIoEvent)?;
    vmm.vm
        .fd()
        .register_irqfd(&notify.irq_evt, notify_config.irq)
        .map_err(VmshmError::RegisterIrqFd)?;

    Ok(())
}

fn send_request(
    stream: &mut UnixStream,
    request: &[u8],
    notify: Option<&VmshmNotifyRegion>,
) -> Result<(), VmshmError> {
    if let Some(notify) = notify {
        send_request_with_fds(
            stream.as_raw_fd(),
            request,
            &[notify.kick_evt.as_raw_fd(), notify.irq_evt.as_raw_fd()],
        )
        .map_err(VmshmError::WriteRequest)
    } else {
        stream.write_all(request).map_err(VmshmError::WriteRequest)
    }
}

fn send_request_with_fds(socket_fd: RawFd, request: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: request.as_ptr().cast_mut().cast(),
        iov_len: request.len(),
    };
    let mut control = vec![0u8; cmsg_space_for_fds(fds.len())];
    let msg_controllen = control.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCM_RIGHTS control buffer is too large",
        )
    })?;
    let cmsg_len = cmsg_len_for_fds(fds.len()).try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SCM_RIGHTS control message is too large",
        )
    })?;

    // SAFETY: Zero is a valid initialized state for `msghdr`; all used pointers are set below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = msg_controllen;

    // SAFETY: `message` owns a writable control buffer large enough for the fd array.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failed to allocate SCM_RIGHTS control message",
        ));
    }

    // SAFETY: `cmsg` points into `control`, which remains alive through sendmsg.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
            fds.len(),
        );
    }

    // SAFETY: `message` points to valid iovec/control buffers for the duration of this call.
    let sent = unsafe { libc::sendmsg(socket_fd, &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(sent).unwrap_or_default() != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short sendmsg while writing vmshm request",
        ));
    }

    Ok(())
}

fn cmsg_space_for_fds(fd_count: usize) -> usize {
    // SAFETY: CMSG_SPACE is a pure size calculation.
    unsafe { libc::CMSG_SPACE((fd_count * mem::size_of::<RawFd>()) as u32) as usize }
}

fn cmsg_len_for_fds(fd_count: usize) -> usize {
    // SAFETY: CMSG_LEN is a pure size calculation.
    unsafe { libc::CMSG_LEN((fd_count * mem::size_of::<RawFd>()) as u32) as usize }
}

#[repr(C)]
union CmsgBuffer {
    header: libc::cmsghdr,
    bytes: [u8; 64],
}

fn recv_reply_with_fd(socket_fd: RawFd) -> Result<(VmshmHandshakeReply, File), VmshmError> {
    let mut reply_bytes = [0u8; REPLY_LEN];
    let mut iov = libc::iovec {
        iov_base: reply_bytes.as_mut_ptr().cast(),
        iov_len: reply_bytes.len(),
    };
    let mut control = CmsgBuffer { bytes: [0u8; 64] };
    // SAFETY: Zero is a valid initialized state for `msghdr`; all used pointers are set below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    // SAFETY: Accessing the bytes member is safe here because we initialized the union with it.
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = mem::size_of::<CmsgBuffer>()
        .try_into()
        .expect("vmshm control buffer size fits msg_controllen");

    // SAFETY: `message` points to valid iovec/control buffers for the duration of this call.
    let read_len = unsafe { libc::recvmsg(socket_fd, &mut message, 0) };
    if read_len < 0 {
        return Err(VmshmError::RecvReply(io::Error::last_os_error()));
    }

    let read_len = usize::try_from(read_len).map_err(|_| {
        VmshmError::RecvReply(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg returned an invalid byte count",
        ))
    })?;
    if read_len != REPLY_LEN {
        return Err(VmshmError::ShortReply(read_len));
    }

    let file = extract_file_from_cmsg(&message)?;
    Ok((VmshmHandshakeReply::from_bytes(&reply_bytes), file))
}

fn extract_file_from_cmsg(message: &libc::msghdr) -> Result<File, VmshmError> {
    // SAFETY: `message` was filled by recvmsg and has a valid control buffer.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is yielded by the libc CMSG iterator helpers.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let cmsg_header_len = mem::size_of::<libc::cmsghdr>()
                .try_into()
                .expect("cmsghdr size fits cmsg_len");
            let raw_fd_len = mem::size_of::<RawFd>()
                .try_into()
                .expect("RawFd size fits cmsg_len");
            if header.cmsg_len < cmsg_header_len {
                return Err(VmshmError::MissingFd);
            }
            if header.cmsg_len.saturating_sub(cmsg_header_len) < raw_fd_len {
                return Err(VmshmError::MissingFd);
            }
            // SAFETY: This control message is SCM_RIGHTS and contains at least one fd-sized item
            // when the broker follows the vmshm protocol.
            let data = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>() };
            // SAFETY: We take ownership of the fd received via SCM_RIGHTS exactly once.
            let file = unsafe { File::from_raw_fd(*data) };
            return Ok(file);
        }
        // SAFETY: `cmsg` and `message` are from the same recvmsg result.
        let message_ptr = std::ptr::from_ref(message).cast_mut();
        cmsg = unsafe { libc::CMSG_NXTHDR(message_ptr, cmsg) };
    }

    Err(VmshmError::MissingFd)
}
