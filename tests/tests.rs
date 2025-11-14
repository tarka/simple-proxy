use std::net::SocketAddr;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use procfs::{
    process::{FDTarget, Process},
    net::{tcp as tcp_table, tcp6 as tcp6_table}
};
use test_context::{TestContext, test_context};
use tracing_log::log::warn;


fn run_proxy() -> Result<Child> {
    let exe = env!("CARGO_BIN_EXE_simple-proxy");

    let child = Command::new(exe)
        .spawn()?;
    Ok(child)
}

fn stop_child(child: &Child) -> Result<()> {
    let pid = Pid::from_raw(child.id().try_into()?);
    kill(pid, Signal::SIGTERM)?;
    Ok(())
}

fn get_proc_port(child: &Child) -> Result<Option<u16>> {
    let proc = Process::new(child.id() as i32)?;
    let stat = proc.stat()?;
    let inodes = proc.fd()?
        .filter_map(|fd| match fd.unwrap().target {
            FDTarget::Socket(inode) => Some(inode),
            _ => None
        })
        .collect::<Vec<u64>>();
    let inode = if inodes.len() == 1 {
        inodes[0]
    } else {
        warn!("Wrong number of socket inodes: {}", inodes.len());
        return Ok(None);
    };

    let addrs = tcp_table()?.into_iter()
        .chain(tcp6_table()?)
        .filter_map(|t| if t.inode == inode {
            Some(t.local_address)
        } else {
            None
        })
        .collect::<Vec<SocketAddr>>();
    let addr = if addrs.len() == 1 {
        addrs[0]
    } else {
        warn!("Unexpected number of addresses returned");
        return Ok(None)
    };

    Ok(Some(addr.port()))
}

fn wait_port(child: &Child) -> Result<u16> {
    const WAIT_MS: u64 = 10;
    const WAIT_SECS: u64 = 20;
    const WAIT_TIMES: u64 = WAIT_SECS / WAIT_MS;
    for _ in 0.. {
        thread::sleep(Duration::from_millis(WAIT_MS));
        if let Some(port) = get_proc_port(child)? {
            return Ok(port)
        }
    }
    bail!("Failed to find process port");
}

struct IntegrationTest {
    proxy: Child,
    proxy_port: u16,
}

impl TestContext for IntegrationTest {
    fn setup() -> Self {
        let proxy = run_proxy().expect("Failed to start proxy");
        let proxy_port = wait_port(&proxy).expect("Failed to find proxy port");
        Self {
            proxy,
            proxy_port,
        }
    }

    fn teardown(self) {
    }
}

#[test_context(IntegrationTest)]
#[test]
fn test_fetch_port(ctx: &IntegrationTest) -> Result<()> {
    println!("Port is {}", ctx.proxy_port);

    stop_child(&ctx.proxy)?;
    Ok(())
}
