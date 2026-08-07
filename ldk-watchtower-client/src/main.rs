use std::time::Duration;

use structopt::StructOpt;

use ldk_watchtower_client::config::{Config, Opt};
use ldk_watchtower_client::poller::WatchtowerClient;

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();

    let opt = Opt::from_args();
    let cfg = match Config::from_opt(opt) {
        Ok(cfg) => cfg,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(1);
        }
    };

    let client = match WatchtowerClient::new(cfg.clone()) {
        Ok(client) => client,
        Err(e) => {
            log::error!("Cannot start the watchtower client: {e}");
            std::process::exit(1);
        }
    };

    let poll_interval = Duration::from_secs(cfg.poll_interval_secs);
    let (_trigger, listener) = triggered::trigger();
    log::info!(
        "ldk-watchtower-client started. Polling {} every {}s",
        cfg.ldk_server_url,
        cfg.poll_interval_secs
    );

    loop {
        client.tick();
        // Sleep until the next tick, waking up periodically to check for
        // Ctrl-C / SIGTERM (triggered 0.1 has no timed wait on `Listener`).
        let mut slept = Duration::ZERO;
        while slept < poll_interval && !listener.is_triggered() {
            let step = poll_interval
                .checked_sub(slept)
                .unwrap_or_default()
                .min(Duration::from_secs(1));
            std::thread::sleep(step);
            slept += step;
        }
        if listener.is_triggered() {
            log::info!("Shutting down");
            break;
        }
    }
}
