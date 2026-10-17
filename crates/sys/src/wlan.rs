//! Native Wi-Fi API: bağlı olunan ağın adı (SSID) ve sinyal kalitesi.

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WiFi::{
    wlan_interface_state_connected, wlan_intf_opcode_current_connection, WlanCloseHandle,
    WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST,
};

pub struct WlanLink {
    pub ssid: String,
    /// 0-100
    pub signal_quality: u32,
}

/// Bağlı Wi-Fi arayüzleri: anahtar, adaptör GUID'inin büyük harfli hali ("{...}").
/// WLAN servisi çalışmıyorsa (Wi-Fi kartı yoksa) boş döner.
pub fn current_connections() -> HashMap<String, WlanLink> {
    let mut map = HashMap::new();
    let mut version = 0u32;
    let mut handle: HANDLE = ptr::null_mut();
    if unsafe { WlanOpenHandle(2, ptr::null(), &mut version, &mut handle) } != ERROR_SUCCESS {
        return map;
    }

    let mut list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
    if unsafe { WlanEnumInterfaces(handle, ptr::null(), &mut list) } == ERROR_SUCCESS
        && !list.is_null()
    {
        let items = unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*list).InterfaceInfo) as *const WLAN_INTERFACE_INFO,
                (*list).dwNumberOfItems as usize,
            )
        };
        for item in items {
            if item.isState != wlan_interface_state_connected {
                continue;
            }
            if let Some(link) = query_connection(handle, &item.InterfaceGuid) {
                map.insert(guid_to_string(&item.InterfaceGuid), link);
            }
        }
        unsafe { WlanFreeMemory(list as *const c_void) };
    }

    unsafe { WlanCloseHandle(handle, ptr::null()) };
    map
}

fn query_connection(handle: HANDLE, guid: &GUID) -> Option<WlanLink> {
    let mut size = 0u32;
    let mut data: *mut WLAN_CONNECTION_ATTRIBUTES = ptr::null_mut();
    let ret = unsafe {
        WlanQueryInterface(
            handle,
            guid,
            wlan_intf_opcode_current_connection,
            ptr::null(),
            &mut size,
            &mut data as *mut _ as *mut *mut c_void,
            ptr::null_mut(),
        )
    };
    if ret != ERROR_SUCCESS || data.is_null() {
        return None;
    }
    let assoc = unsafe { &(*data).wlanAssociationAttributes };
    let len = (assoc.dot11Ssid.uSSIDLength as usize).min(assoc.dot11Ssid.ucSSID.len());
    let link = WlanLink {
        ssid: String::from_utf8_lossy(&assoc.dot11Ssid.ucSSID[..len]).into_owned(),
        signal_quality: assoc.wlanSignalQuality,
    };
    unsafe { WlanFreeMemory(data as *const c_void) };
    Some(link)
}

/// GetAdaptersAddresses'taki AdapterName biçimi: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
fn guid_to_string(g: &GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}
