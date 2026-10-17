//! Simple blocking client that sends requests to the service over a named pipe.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;

use router_common::{Request, Response, PIPE_NAME};

const ERROR_PIPE_BUSY: i32 = 231;

pub fn request(req: &Request) -> io::Result<Response> {
    let pipe = open()?;
    let mut msg = serde_json::to_vec(req).map_err(io::Error::other)?;
    msg.push(b'\n');
    (&pipe).write_all(&msg)?;

    let mut line = String::new();
    BufReader::new(&pipe).read_line(&mut line)?;
    match serde_json::from_str(&line).map_err(io::Error::other)? {
        Response::Error(e) => Err(io::Error::other(e)),
        resp => Ok(resp),
    }
}

fn open() -> io::Result<File> {
    let mut attempts = 0;
    loop {
        match OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            // If all pipe instances are busy, retry shortly.
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}
