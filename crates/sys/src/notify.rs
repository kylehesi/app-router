//! Network change notifications (IP Helper): interfaces coming and going,
//! address changes (e.g. a new DHCP lease) and route/gateway changes.

use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::util::win32_err;

type Callback = Box<dyn Fn() + Send + Sync>;

/// Keeps the notifications registered; dropping it unregisters them.
pub struct ChangeWatcher {
    handles: Vec<HANDLE>,
    // Boxed twice so the pointer handed to Windows stays stable for the watcher's lifetime.
    _callback: Box<Callback>,
}

// SAFETY: the handles are only passed to CancelMibChangeNotify2, which may be
// called from any thread; the callback itself is Send + Sync.
unsafe impl Send for ChangeWatcher {}
unsafe impl Sync for ChangeWatcher {}

/// Calls `callback` whenever an interface, unicast address or route changes.
/// Windows fires several notifications per real change, so callers should
/// debounce. The callback runs on a system thread and must return quickly.
pub fn watch_changes(callback: impl Fn() + Send + Sync + 'static) -> io::Result<ChangeWatcher> {
    let callback: Box<Callback> = Box::new(Box::new(callback));
    let ctx = &*callback as *const Callback as *const c_void;
    let mut watcher = ChangeWatcher { handles: Vec::with_capacity(3), _callback: callback };

    let mut handle: HANDLE = ptr::null_mut();
    check(unsafe { NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), ctx, 0, &mut handle) })?;
    watcher.handles.push(handle);

    let mut handle: HANDLE = ptr::null_mut();
    check(unsafe { NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), ctx, 0, &mut handle) })?;
    watcher.handles.push(handle);

    let mut handle: HANDLE = ptr::null_mut();
    check(unsafe { NotifyRouteChange2(AF_UNSPEC, Some(on_route), ctx, 0, &mut handle) })?;
    watcher.handles.push(handle);

    Ok(watcher)
}

fn check(ret: u32) -> io::Result<()> {
    if ret == NO_ERROR {
        Ok(())
    } else {
        Err(win32_err(ret))
    }
}

/// # Safety
/// `ctx` is the `Callback` pointer registered in `watch_changes`; it outlives
/// the registration because `ChangeWatcher` cancels before freeing it.
unsafe fn fire(ctx: *const c_void) {
    (*(ctx as *const Callback))();
}

unsafe extern "system" fn on_interface(ctx: *const c_void, _: *const MIB_IPINTERFACE_ROW, _: MIB_NOTIFICATION_TYPE) {
    fire(ctx);
}

unsafe extern "system" fn on_address(ctx: *const c_void, _: *const MIB_UNICASTIPADDRESS_ROW, _: MIB_NOTIFICATION_TYPE) {
    fire(ctx);
}

unsafe extern "system" fn on_route(ctx: *const c_void, _: *const MIB_IPFORWARD_ROW2, _: MIB_NOTIFICATION_TYPE) {
    fire(ctx);
}

impl Drop for ChangeWatcher {
    fn drop(&mut self) {
        // CancelMibChangeNotify2 waits for running callbacks to finish, so the
        // callback box can be freed safely afterwards (field drop order).
        for &handle in &self.handles {
            unsafe { CancelMibChangeNotify2(handle) };
        }
    }
}
