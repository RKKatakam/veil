//! `veil-bench sftp-shim --rtt-ms N -- CMD…`: run CMD (an `sftp-server`)
//! and relay our stdin to it and its stdout to ours, each chunk delivered
//! half the RTT after it was produced. Deadlines are absolute, so
//! pipelined traffic is delayed, not serialised (as in
//! `crates/veil-core/tests/sftp_support`).

use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};

fn relay(mut from: impl Read + Send + 'static, mut to: impl Write + Send + 'static, delay: Duration) -> std::thread::JoinHandle<()> {
    let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    std::thread::spawn(move || {
        let mut b = vec![0u8; 256 * 1024];
        loop {
            match from.read(&mut b) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send((Instant::now() + delay, b[..n].to_vec())).is_err() {
                        return;
                    }
                }
            }
        }
    });
    std::thread::spawn(move || {
        while let Ok((due, data)) = rx.recv() {
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
            if to.write_all(&data).and_then(|()| to.flush()).is_err() {
                return;
            }
        }
    })
}

pub fn run(one_way: Duration, cmd: &[String]) -> Result<()> {
    let (prog, args) = cmd.split_first().ok_or_else(|| anyhow!("sftp-shim: no command"))?;
    let mut child = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let cin = child.stdin.take().unwrap();
    let cout = child.stdout.take().unwrap();
    let _up = relay(std::io::stdin(), cin, one_way);
    let down = relay(cout, std::io::stdout(), one_way);
    let _ = down.join();
    let st = child.wait()?;
    std::process::exit(st.code().unwrap_or(1));
}
