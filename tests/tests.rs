use std::process::{Child, Command};

use anyhow::Result;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use test_context::{TestContext, test_context};


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


struct IntegrationTest {
    proxy: Child,
}

impl TestContext for IntegrationTest {
    fn setup() -> Self {
        let proxy = run_proxy().expect("Failed to start proxy");
        let pid = proxy.id();
        Self {
            proxy
        }
    }

    fn teardown(self) {
    }
}

#[test_context(IntegrationTest)]
#[test]
fn test_fetch_port(ctx: &IntegrationTest) -> Result<()> {

    stop_child(&ctx.proxy)?;
    Ok(())
}
