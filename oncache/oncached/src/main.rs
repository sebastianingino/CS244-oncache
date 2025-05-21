use anyhow::anyhow;
use aya::{
    Ebpf, EbpfLoader,
    programs::{SchedClassifier, TcAttachType, tc},
};
use clap::{Parser, Subcommand};
use tracing::{debug, info};

#[derive(Debug, Parser)]
struct Opt {
    object: String,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ListPrograms,
    Attach {
        #[clap(short, long)]
        iface: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    // Load EBPF object file

    let mut loader = EbpfLoader::new();
    let mut ebpf = loader.load_file(&opt.object).unwrap();

    match &opt.command {
        Command::ListPrograms => {
            let prog_count = ebpf.programs().count();
            info!("Found {} programs in {}", prog_count, opt.object);
            for (name, program) in ebpf.programs() {
                info!("found program `{}` of type {:?}", name, program.prog_type());
            }
        }
        Command::Attach { iface } => {
            tc::qdisc_add_clsact(iface)?;
            attach_programs(&mut ebpf, iface, &opt.object)?;
        }
    }

    Ok(())
}

/// Attach the programs to the specified interface. `object` is only used for debugging output.
fn attach_programs(ebpf: &mut Ebpf, iface: &str, object: &str) -> anyhow::Result<()> {
    let mut attach = |name: &str, attach_type: TcAttachType| -> anyhow::Result<()> {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("no program `{name}` in {object}"))?
            .try_into()?;
        prog.load()?;
        prog.attach(iface, attach_type)?;

        debug!("attached `{name}`");

        Ok(())
    };

    info!("attaching programs from {}", object);

    attach("egress_init_prog", TcAttachType::Egress)?;
    attach("egress_prog", TcAttachType::Egress)?;
    attach("ingress_init_prog", TcAttachType::Ingress)?;
    attach("ingress_prog", TcAttachType::Ingress)?;

    info!("attaching programs from {}: done", object);

    Ok(())
}

/// Data structures from the C-side.
#[allow(dead_code)]
mod data {
    use std::net::Ipv4Addr;

    use network_types::{eth::EthHdr, ip::IpHdr, udp::UdpHdr};

    pub const VXLAN_HEADER_LEN: usize = 8;

    /// from: `outer_headers_t` in `common/common.h`
    #[repr(C, packed)]
    struct OuterHeaders {
        eth: EthHdr,
        ip: IpHdr,
        udphdr: UdpHdr,
        vxlan: [u8; VXLAN_HEADER_LEN],
    }

    /// from: `inner_headers_t` in `common/common.h`
    #[repr(C, packed)]
    pub struct InnerHeaders {
        eth: EthHdr,
        ip: IpHdr,
    }

    /// from: `encap_headers_t` in `common/common.h`
    #[repr(C, packed)]
    pub struct EncapHeaders {
        outer: OuterHeaders,
        inner: InnerHeaders,
    }

    /// from: `struct egress_data` in `kernel/ebpf_plugin.h`
    #[repr(C)]
    pub struct EgressData {
        outer: OuterHeaders,
        inner: EthHdr,
        ifindex: u32,
    }

    /// from: `struct ingress_data` in `kernel/ebpf_plugin.h`
    #[repr(C)]
    pub struct IngressData {
        eth: EthHdr,
        vindex: u32,
    }

    /// from: `struct flow_key` in `kernel/ebpf_plugin.h`
    #[repr(C)]
    pub struct FlowKey {
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: u8,
    }

    // XXX: bitfield! inlines to a `#[repr(transparent)]`
    proc_bitfield::bitfield! {
        /// from: `struct filter_action` in `kernel/ebpf_plugin.h`
        #[derive(Copy, Clone)]
        pub struct FilterAction(u8): Debug, IntoStorage, FromStorage, DerefStorage {
            allow_ingress: bool @ 0,
            allow_egress: bool @ 1,
        }
    }

    /// from: `struct interface_data` in `kernel/ebpf_plugin.h`
    #[repr(C)]
    pub struct InterfaceData {
        mac: [u8; libc::ETH_ALEN as usize],
        ip: Ipv4Addr,
    }
}
