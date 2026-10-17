//! Named pipe server the UI uses to talk to the service (one JSON message per line).

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::Arc;

use anyhow::Result;
use router_common::{Request, Response, PIPE_NAME};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use tracing::{debug, info};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::rules::RuleStore;

/// SYSTEM and Administrators: full access. Signed-in (interactive) users: read/write.
/// Lets a normal user's UI connect while the service runs as SYSTEM.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Upper bound for one request line, so a broken client cannot exhaust the service's memory.
const MAX_LINE: usize = 64 * 1024;

pub struct State {
    pub rules: Arc<RuleStore>,
}

pub async fn serve(state: Arc<State>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    // first_pipe_instance: fail if another process already created a pipe with this name.
    let mut server = create_pipe(true)?;
    info!(pipe = PIPE_NAME, "IPC listening");
    loop {
        tokio::select! {
            res = server.connect() => res?,
            _ = shutdown.changed() => return Ok(()),
        }
        let client = std::mem::replace(&mut server, create_pipe(false)?);
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(client, &state).await {
                debug!("client connection closed: {e}");
            }
        });
    }
}

async fn handle_client(pipe: NamedPipeServer, state: &State) -> io::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_LINE {
            // The rest of the line was not read; closing the connection is the only safe option.
            return send(&mut writer, &Response::Error("request too large".into())).await;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(req, state).await,
            Err(e) => Response::Error(format!("invalid request: {e}")),
        };
        send(&mut writer, &response).await?;
    }
}

async fn send(writer: &mut (impl AsyncWriteExt + Unpin), response: &Response) -> io::Result<()> {
    let mut out = serde_json::to_vec(response).map_err(io::Error::other)?;
    out.push(b'\n');
    writer.write_all(&out).await?;
    writer.flush().await
}

async fn dispatch(req: Request, state: &State) -> Response {
    match req {
        Request::Ping => Response::Pong { version: env!("CARGO_PKG_VERSION").into() },
        Request::ListAdapters => blocking(router_sys::adapters::list_adapters, Response::Adapters).await,
        Request::ListApps => blocking(router_sys::processes::network_apps, Response::Apps).await,
        Request::GetRules => Response::Rules(state.rules.list()),
        Request::SetRule { exe, adapter_guid } => {
            info!(%exe, ?adapter_guid, "updating rule");
            match state.rules.set(&exe, adapter_guid) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(format!("{e:#}")),
            }
        }
    }
}

/// Runs blocking Windows API calls without stalling the tokio worker threads.
async fn blocking<T: Send + 'static>(
    f: fn() -> io::Result<T>,
    wrap: fn(T) -> Response,
) -> Response {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => wrap(v),
        Ok(Err(e)) => Response::Error(e.to_string()),
        Err(e) => Response::Error(format!("internal error: {e}")),
    }
}

fn create_pipe(first: bool) -> io::Result<NamedPipeServer> {
    let sddl = router_sys::to_wide(PIPE_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(PIPE_NAME, &mut sa as *mut _ as *mut c_void)
    };
    unsafe { LocalFree(sd) };
    result
}
