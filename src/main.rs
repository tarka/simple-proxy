
mod certificates;
mod errors;
mod server;

use std::{net::SocketAddr, str::FromStr};

use anyhow::Result;
use async_lock::OnceCell;
use smol::net::TcpListener;
use tracing::level_filters::LevelFilter;
use tracing_log::log::info;
use tracing_subscriber::util::SubscriberInitExt;

use crate::server::start_server;

fn init_logging(level: u8) -> Result<()> {
    let log_level = match level {
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        3 => LevelFilter::TRACE,
        _ => LevelFilter::WARN,
    };

    let _fmt = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();
    // fmt.init();

    // // FIXME: Do we need this to log hyper, etc?
    // tracing::subscriber::set_global_default(fmt)
    //     .expect("Unable to set global logger");

    info!("Logging initialised");
    Ok(())
}



fn main() -> Result<()> {
    init_logging(2)?;

    smol::block_on(start_server())?;
    Ok(())
}
