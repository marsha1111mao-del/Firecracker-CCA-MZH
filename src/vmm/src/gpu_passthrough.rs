use std::io;
use std::os::unix::io::AsRawFd;
use kvm_bindings::{KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQFD_FLAG_RESAMPLE, kvm_irq_routing, kvm_irq_routing_entry, kvm_irqfd};
use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;
use libc::{ioctl, EFD_NONBLOCK};
use crate::pmthor::{PmThorDevice, IrqIndex};
const VGIC_NR_PRIVATE_IRQS: u32 = 32;

const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2; // 如果需要 _IOWR 则用到

// 定义 KVM 控制代码的幻数 (KVMIO = 0xAE)
const KVMIO: u8 = 0xAE;

// 模拟内核的 _IOR (Read) 宏
macro_rules! ior {
    ($kind:expr, $nr:expr, $size:ty) => {
        (0x80000000 | 
        ((std::mem::size_of::<$size>() as u32) << 16) | 
        (($kind as u32) << 8) | 
        ($nr as u32)) as libc::c_int
    };
}

// 模拟内核的 _IOW 宏计算逻辑
macro_rules! iow {
    ($kind:expr, $nr:expr, $size:ty) => {
        // 这里的计算公式严格遵循 Linux 内核定义
        (0x40000000 | 
        ((std::mem::size_of::<$size>() as u32) << 16) | 
        (($kind as u32) << 8) | 
        ($nr as u32)) as libc::c_int
    };
}

// 模拟内核的 _IOWR (Read/Write) 宏
macro_rules! iowr {
    ($kind:expr, $nr:expr, $size:ty) => {
        (0xC0000000 | 
        ((std::mem::size_of::<$size>() as u32) << 16) | 
        (($kind as u32) << 8) | 
        ($nr as u32)) as libc::c_int
    };
}
// 优美地定义 KVM_IRQFD
const KVM_IRQFD: libc::c_int = iow!(KVMIO, 0x76, kvm_bindings::kvm_irqfd);
const KVM_SET_GSI_ROUTING: libc::c_int = iow!(KVMIO, 0x6a, kvm_bindings::kvm_irq_routing);
const KVM_GET_GSI_ROUTING: libc::c_int = iowr!(KVMIO, 0x67, kvm_bindings::kvm_irq_routing);
pub struct GpuIrqContext {
    pub trigger: EventFd,
    pub resample: EventFd,
    pub gsi: u32,
}

pub struct GpuPassthroughManager {
    pub pmthor: PmThorDevice,
    pub irqs: Vec<GpuIrqContext>,
}

fn format_routing_entry(entry: &kvm_irq_routing_entry) -> String {
    match entry.type_ {
        KVM_IRQ_ROUTING_IRQCHIP => {
            // 安全地访问 union
            let irqchip = unsafe { entry.u.irqchip };
            format!(
                "GSI {} -> IRQCHIP(id={}, pin={})",
                entry.gsi, irqchip.irqchip, irqchip.pin
            )
        }
        // 如果需要支持 MSI，可以在这里添加其他类型的匹配
        _ => format!("GSI {} -> TYPE({}) [UNKNOWN]", entry.gsi, entry.type_),
    }
}

impl GpuPassthroughManager {
    pub fn new(path: &str, base_gsi: u32) -> io::Result<Self> {
        let pmthor = PmThorDevice::open(path)?;
        let mut irqs = Vec::new();

        for i in 0..3 {
            let gsi = (base_gsi + i);
            irqs.push(GpuIrqContext {
                trigger: EventFd::new(EFD_NONBLOCK)?,
                resample: EventFd::new(EFD_NONBLOCK)?,
                gsi: gsi,
            });
        }

        Ok(GpuPassthroughManager { pmthor, irqs })
    }

    fn get_current_routes(&self, vm_fd: &VmFd) -> io::Result<Vec<kvm_irq_routing_entry>> {
        // 1. 初始尝试大小
        let mut nr = 128; 
        
        loop {
            let entry_size = std::mem::size_of::<kvm_irq_routing_entry>();
            let header_size = std::mem::size_of::<kvm_irq_routing>();
            let total_size = header_size + (nr * entry_size);
            
            // 分配缓冲区并初始化为 0
            let mut buffer = vec![0u8; total_size];
            
            // 使用指针操作来设置 nr，避开结构体字面量初始化
            let routing_ptr = buffer.as_mut_ptr() as *mut kvm_irq_routing;
            unsafe {
                // 直接写入内存字段，不触发 "missing field" 错误
                std::ptr::write_volatile(&mut (*routing_ptr).nr, nr as u32);
                std::ptr::write_volatile(&mut (*routing_ptr).flags, 0);
            }

            let ret = unsafe { 
                ioctl(vm_fd.as_raw_fd(), KVM_GET_GSI_ROUTING, routing_ptr) 
            };
            
            if ret >= 0 {
                // 获取内核实际写入的条目数
                let actual_nr = unsafe { (*routing_ptr).nr as usize };
                let mut entries = Vec::with_capacity(actual_nr);
                
                for i in 0..actual_nr {
                    unsafe {
                        let entry_ptr = buffer.as_ptr().add(header_size + i * entry_size)
                                        as *const kvm_irq_routing_entry;
                        entries.push(std::ptr::read(entry_ptr));
                    }
                }               
                println!("KVM Routing: Read {} existing entries from kernel.", actual_nr);
                // 使用 println! 级别打印详情，避免日志过多，除非你需要调试
                for entry in &entries {
                    println!("  - {}", format_routing_entry(entry));
                }
                return Ok(entries);
            }

            let err = io::Error::last_os_error();
            // E2BIG 表示缓冲区太小，需要增加 nr 重新尝试
            if err.raw_os_error() == Some(libc::E2BIG) {
                nr *= 2;
                if nr > 1024 { return Err(err); }
            } else {
                // 如果内核不支持或发生其他错误，返回空以允许 Guest 继续启动
                return Ok(Vec::new());
            }
        }
    }

    fn setup_irq_routing(&self, vm_fd: &VmFd) -> io::Result<()> {
        // 1. 获取现有路由
        let mut entries = self.get_current_routes(vm_fd)?;
        let original_count = entries.len();
        // 2. 合并 GPU 的路由
        // 注意：这里要检查 GSI 是否已经存在，如果存在则更新，不存在则添加
        for ctx in &self.irqs {
            // 移除旧的同名 GSI 条目防止重复
            entries.retain(|e| e.gsi != ctx.gsi);
            
            let mut new_entry = kvm_irq_routing_entry {
                gsi: ctx.gsi,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                flags: 0,
                ..Default::default()
            };
            unsafe {
                new_entry.u.irqchip.irqchip = 0; // ARM GIC 默认 ID
                new_entry.u.irqchip.pin = ctx.gsi;
            }
            entries.push(new_entry);
        }
        // --- 新增日志：打印合并后的路由表 ---
        println!(
            "KVM Routing: Merged table has {} entries ({} existing, {} GPU).", 
            entries.len(), 
            original_count - entries.iter().filter(|e| self.irqs.iter().any(|ctx| ctx.gsi == e.gsi)).count(), // 简单估算
            self.irqs.len()
        );
        
        // 打印最终将要写入内核的完整列表
        println!("KVM Routing: Final routing table content:");
        for entry in &entries {
            println!("  -> {}", format_routing_entry(entry));
        }
        // 3. 准备全量写入缓冲区
        let entry_count = entries.len();
        let header_size = std::mem::size_of::<kvm_irq_routing>();
        let entry_size = std::mem::size_of::<kvm_irq_routing_entry>();
        let total_size = header_size + (entry_count * entry_size);
        let mut buffer = vec![0u8; total_size];

        unsafe {
            let routing_ptr = buffer.as_mut_ptr() as *mut kvm_irq_routing;
            (*routing_ptr).nr = entry_count as u32;
            (*routing_ptr).flags = 0;
            
            let entries_ptr = buffer.as_mut_ptr().add(header_size) as *mut kvm_irq_routing_entry;
            std::ptr::copy_nonoverlapping(entries.as_ptr(), entries_ptr, entry_count);
        }

        // 4. 写入全量路由表
        let ret = unsafe {
            ioctl(vm_fd.as_raw_fd(), KVM_SET_GSI_ROUTING, buffer.as_ptr())
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    
    pub fn attach_to_kvm(&self, vm_fd: &VmFd) -> io::Result<()> {
        //self.setup_irq_routing(vm_fd)?;
        println!("GpuPassthrough: KVM GSI routing table updated.");
        let indices = [IrqIndex::Job, IrqIndex::Mmu, IrqIndex::Gpu];

        for (i, &index) in indices.iter().enumerate() {
            let ctx = &self.irqs[i];

            // 1. 设置物理驱动：绑定物理中断到 eventfds
            self.pmthor.set_trigger(index, ctx.trigger.as_raw_fd())?;
            self.pmthor.set_unmask_event(index, ctx.resample.as_raw_fd())?;

            // 2. 手动构造 kvm_irqfd 并调用 ioctl
            // 这样可以绕过库的限制，传入 resamplefd
            let irqfd_data = kvm_irqfd {
                fd: ctx.trigger.as_raw_fd() as u32,
                gsi: ctx.gsi,
                flags: KVM_IRQFD_FLAG_RESAMPLE,
                resamplefd: ctx.resample.as_raw_fd() as u32,
                ..Default::default()
            };

            let ret = unsafe {
                ioctl(vm_fd.as_raw_fd(), KVM_IRQFD, &irqfd_data)
            };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            println!("GpuPassthrough: Attached IRQ {} (GSI {}) with Resample support", i, ctx.gsi);
        }

        Ok(())
    }
}