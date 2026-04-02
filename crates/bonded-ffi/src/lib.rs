#[cfg(any(target_os = "android", test))]
use bonded_client::{establish_naive_tcp_session, establish_transport_paths};
#[cfg(any(target_os = "android", test))]
use bonded_core::config::ClientConfig;
#[cfg(any(target_os = "android", test))]
use bonded_core::config::SocketProtectFn;
use bonded_core::session::SessionFrame;
#[cfg(any(target_os = "android", test))]
use bonded_core::session::SessionState;
#[cfg(any(target_os = "android", test))]
use bytes::Bytes;
#[cfg(any(target_os = "android", test))]
use std::collections::VecDeque;
#[cfg(any(target_os = "android", test))]
use std::path::PathBuf;
use std::slice;
#[cfg(any(target_os = "android", test))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(target_os = "android", test))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(target_os = "android", test))]
use std::thread::{self, JoinHandle};
#[cfg(any(target_os = "android", test))]
use std::time::Duration;
#[cfg(any(target_os = "android", test))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "android", test))]
const ANDROID_PATH_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(12);

// ── JVM / VPN-service globals (Android only) ────────────────────────────────

/// The JavaVM singleton stored once in JNI_OnLoad so threads can attach later.
#[cfg(target_os = "android")]
static ANDROID_JVM: OnceLock<jni::JavaVM> = OnceLock::new();

/// A global reference to the currently active BondedVpnService instance, used
/// to call `protect(fd)` on session sockets before they connect.
#[cfg(target_os = "android")]
static ANDROID_VPN_SERVICE: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);

/// Called by the JVM when the native library is first loaded.  We grab the
/// JavaVM here so we can attach arbitrary threads later.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jni::sys::jint {
    let _ = ANDROID_JVM.set(vm);
    jni::sys::JNI_VERSION_1_6
}

/// Ask the stored VpnService to protect `fd` so the socket bypasses the VPN.
#[cfg(target_os = "android")]
fn protect_fd(fd: i32) -> bool {
    let Some(jvm) = ANDROID_JVM.get() else {
        return false;
    };
    let mut guard = match jvm.attach_current_thread_as_daemon() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let service = match ANDROID_VPN_SERVICE.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(r) => r.clone(),
            None => return false,
        },
        Err(_) => return false,
    };
    guard
        .call_method(
            &service,
            "protect",
            "(I)Z",
            &[jni::objects::JValue::Int(fd)],
        )
        .ok()
        .and_then(|v| v.z().ok())
        .unwrap_or(false)
}

#[cfg(any(target_os = "android", test))]
struct AndroidSessionHandle {
    outbound_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    inbound_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    snapshot: Arc<Mutex<AndroidSessionSnapshot>>,
    stop_flag: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Debug)]
struct AndroidSessionSnapshot {
    state: String,
    server_address: String,
    outbound_packets: u64,
    inbound_packets: u64,
    outbound_bytes: u64,
    inbound_bytes: u64,
    /// Unix timestamp in milliseconds when the session reached "connected".
    connected_at_ms: u64,
    last_error: Option<String>,
}

#[cfg(any(target_os = "android", test))]
static ANDROID_SESSION: OnceLock<Mutex<Option<AndroidSessionHandle>>> = OnceLock::new();

const BONDED_FFI_OK: i32 = 0;
const BONDED_FFI_ERR_NULL_POINTER: i32 = 1;
const BONDED_FFI_ERR_DECODE: i32 = 2;

#[repr(C)]
pub struct BondedFrameMetadata {
    pub connection_id: u32,
    pub sequence: u64,
    pub flags: u32,
    pub payload_len: usize,
}

fn decode_frame_metadata(raw: &[u8]) -> Result<BondedFrameMetadata, i32> {
    let frame = SessionFrame::decode(raw).map_err(|_| BONDED_FFI_ERR_DECODE)?;
    Ok(BondedFrameMetadata {
        connection_id: frame.header.connection_id,
        sequence: frame.header.sequence,
        flags: frame.header.flags,
        payload_len: frame.payload.len(),
    })
}

#[cfg(any(target_os = "android", test))]
fn android_session_slot() -> &'static Mutex<Option<AndroidSessionHandle>> {
    ANDROID_SESSION.get_or_init(|| Mutex::new(None))
}

#[cfg(any(target_os = "android", test))]
fn android_client_config(server_address: &str, storage_dir: &str) -> ClientConfig {
    let mut config = ClientConfig::default();
    let storage_root = PathBuf::from(storage_dir);
    config.client.device_name = "android-client".to_owned();
    config.client.server_public_address = server_address.to_owned();
    config.client.server_websocket_address = server_address.to_owned();
    config.client.private_key_path = storage_root
        .join("bonded-device-key.pem")
        .display()
        .to_string();
    config.client.public_key_path = storage_root
        .join("bonded-device-key.pub")
        .display()
        .to_string();
    config
}

#[cfg(any(target_os = "android", test))]
fn parse_protocol_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "android", test))]
fn parse_bind_address_list(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw)
        .unwrap_or_default()
        .into_iter()
        .map(|address| address.trim().to_owned())
        .filter(|address| !address.is_empty())
        .collect()
}

#[cfg(any(target_os = "android", test))]
fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(any(target_os = "android", test))]
fn snapshot_json(snapshot: &AndroidSessionSnapshot) -> String {
    let last_error = snapshot
        .last_error
        .as_ref()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_owned());

    format!(
        "{{\"state\":\"{}\",\"serverAddress\":\"{}\",\"outboundPackets\":{},\"inboundPackets\":{},\"outboundBytes\":{},\"inboundBytes\":{},\"connectedAtMs\":{},\"lastError\":{}}}",
        escape_json(&snapshot.state),
        escape_json(&snapshot.server_address),
        snapshot.outbound_packets,
        snapshot.inbound_packets,
        snapshot.outbound_bytes,
        snapshot.inbound_bytes,
        snapshot.connected_at_ms,
        last_error,
    )
}

#[cfg(any(target_os = "android", test))]
fn update_snapshot(
    snapshot: &Arc<Mutex<AndroidSessionSnapshot>>,
    update: impl FnOnce(&mut AndroidSessionSnapshot),
) {
    let mut guard = snapshot
        .lock()
        .expect("android session snapshot lock poisoned");
    update(&mut guard);
}

#[cfg(any(target_os = "android", test))]
fn stop_android_session() {
    let handle = {
        let mut slot = android_session_slot()
            .lock()
            .expect("android session slot lock poisoned");
        slot.take()
    };

    if let Some(mut handle) = handle {
        update_snapshot(&handle.snapshot, |snapshot| {
            snapshot.state = "stopped".to_owned();
            snapshot.last_error = None;
        });
        handle.stop_flag.store(true, Ordering::SeqCst);
        let _ = handle.outbound_tx.send(Vec::new());
        if let Some(worker) = handle.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(any(target_os = "android", test))]
fn start_android_session(
    server_address: &str,
    protocol_csv: &str,
    path_count: usize,
    bind_addresses_json: &str,
    storage_dir: &str,
) -> anyhow::Result<()> {
    eprintln!(
        "[bonded-ffi] Starting Android session to {}",
        server_address
    );
    eprintln!(
        "[bonded-ffi] Protocols: {}, Paths: {}, Bind addresses: {}",
        protocol_csv, path_count, bind_addresses_json
    );

    stop_android_session();

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let inbound_queue = Arc::new(Mutex::new(VecDeque::new()));
    let worker_inbound_queue = Arc::clone(&inbound_queue);
    let snapshot = Arc::new(Mutex::new(AndroidSessionSnapshot {
        state: "connecting".to_owned(),
        server_address: server_address.to_owned(),
        outbound_packets: 0,
        inbound_packets: 0,
        outbound_bytes: 0,
        inbound_bytes: 0,
        connected_at_ms: 0,
        last_error: None,
    }));
    let worker_snapshot = Arc::clone(&snapshot);
    let stop_flag = Arc::new(AtomicBool::new(false));
    let worker_stop_flag = Arc::clone(&stop_flag);
    let mut config = android_client_config(server_address, storage_dir);
    let protocols = parse_protocol_list(protocol_csv);
    let bind_addresses = parse_bind_address_list(bind_addresses_json);
    if !protocols.is_empty() {
        config.client.preferred_protocols = protocols;
    }
    if !bind_addresses.is_empty() {
        config.client.path_bind_addresses = bind_addresses;
    }
    // Wire in the socket protect callback so session sockets bypass the VPN.
    #[cfg(target_os = "android")]
    {
        config.socket_protect = Some(SocketProtectFn(Arc::new(|fd| protect_fd(fd))));
    }

    let worker = thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("[bonded-ffi] Failed to create tokio runtime: {}", err);
                update_snapshot(&worker_snapshot, |session_snapshot| {
                    session_snapshot.state = "error".to_owned();
                    session_snapshot.last_error = Some(format!(
                        "failed to create tokio runtime: {err}"
                    ));
                });
                return;
            }
        };

        runtime.block_on(async move {
            eprintln!("[bonded-ffi] Worker thread: establishing transport paths");
            let mut transports = match tokio::time::timeout(
                ANDROID_PATH_ESTABLISH_TIMEOUT,
                establish_transport_paths(&config, path_count.max(1)),
            )
            .await
            {
                Ok(Ok(transports)) => {
                    eprintln!(
                        "[bonded-ffi] Transport paths established, count: {}",
                        transports.len()
                    );
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "connected".to_owned();
                        session_snapshot.connected_at_ms = now_ms;
                        session_snapshot.last_error = None;
                    });
                    transports
                }
                Ok(Err(err)) => {
                    eprintln!("[bonded-ffi] Failed to establish transport paths: {}", err);
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "error".to_owned();
                        session_snapshot.last_error = Some(err.to_string());
                    });
                    return;
                }
                Err(_) => {
                    let message = format!(
                        "timed out after {}s while establishing transport paths",
                        ANDROID_PATH_ESTABLISH_TIMEOUT.as_secs()
                    );
                    eprintln!("[bonded-ffi] {}", message);
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "error".to_owned();
                        session_snapshot.last_error = Some(message.clone());
                    });
                    return;
                }
            };
            let mut active_index = 0_usize;
            let mut session = SessionState::new(1);
            let mut select_cycle = 0u64;

            while !worker_stop_flag.load(Ordering::SeqCst) {
                tokio::select! {
                    maybe_packet = outbound_rx.recv() => {
                        match maybe_packet {
                            Some(packet) => {
                                if packet.is_empty() && worker_stop_flag.load(Ordering::SeqCst) {
                                    eprintln!("[bonded-ffi] Stop signal received");
                                    break;
                                }

                                let packet_len = packet.len() as u64;
                                eprintln!("[bonded-ffi] Worker: sending {} byte outbound packet via transport index {}", packet_len, active_index);
                                let frame = session.create_outbound_frame(Bytes::from(packet), 0);
                                if let Err(err) = transports[active_index].send(frame).await {
                                    eprintln!("[bonded-ffi] Worker: send on transport {} failed: {}", active_index, err);
                                    if transports.len() == 1 {
                                        update_snapshot(&worker_snapshot, |session_snapshot| {
                                            session_snapshot.state = "error".to_owned();
                                            session_snapshot.last_error = Some(err.to_string());
                                        });
                                        break;
                                    }

                                    transports.remove(active_index);
                                    if active_index >= transports.len() {
                                        active_index = 0;
                                    }
                                    eprintln!("[bonded-ffi] Worker: failover to transport index {}", active_index);
                                    continue;
                                }
                                update_snapshot(&worker_snapshot, |session_snapshot| {
                                    session_snapshot.outbound_packets = session_snapshot.outbound_packets.saturating_add(1);
                                    session_snapshot.outbound_bytes = session_snapshot.outbound_bytes.saturating_add(packet_len);
                                });
                            }
                            None => {
                                eprintln!("[bonded-ffi] Outbound channel closed");
                                break;
                            }
                        }
                    }
                    frame_result = transports[active_index].recv() => {
                        match frame_result {
                            Ok(frame) => {
                                eprintln!("[bonded-ffi] Worker: received frame from transport {}", active_index);
                                let ready = match session.ingest_inbound(frame) {
                                    Ok(ready) => ready,
                                    Err(err) => {
                                        eprintln!("[bonded-ffi] Worker: failed to ingest inbound frame: {}", err);
                                        update_snapshot(&worker_snapshot, |session_snapshot| {
                                            session_snapshot.state = "error".to_owned();
                                            session_snapshot.last_error = Some(err.to_string());
                                        });
                                        break;
                                    }
                                };

                                if !ready.is_empty() {
                                    let ready_len = ready.len() as u64;
                                    let total_bytes = ready.iter().map(|f| f.payload.len() as u64).sum::<u64>();
                                    eprintln!("[bonded-ffi] Worker: ingested {} packets, {} bytes total", ready_len, total_bytes);
                                    let mut queue = worker_inbound_queue
                                        .lock()
                                        .expect("android inbound queue lock poisoned");
                                    for packet in ready {
                                        queue.push_back(packet.payload.to_vec());
                                    }
                                    update_snapshot(&worker_snapshot, |session_snapshot| {
                                        session_snapshot.inbound_packets = session_snapshot.inbound_packets.saturating_add(ready_len);
                                        session_snapshot.inbound_bytes = session_snapshot.inbound_bytes.saturating_add(total_bytes);
                                    });
                                }
                            }
                            Err(err) => {
                                eprintln!("[bonded-ffi] Worker: recv on transport {} failed: {}", active_index, err);
                                if transports.len() == 1 {
                                    update_snapshot(&worker_snapshot, |session_snapshot| {
                                        session_snapshot.state = "error".to_owned();
                                        session_snapshot.last_error = Some(err.to_string());
                                    });
                                    break;
                                }

                                transports.remove(active_index);
                                if active_index >= transports.len() {
                                    active_index = 0;
                                }
                                eprintln!("[bonded-ffi] Worker: failover to transport index {}", active_index);
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        select_cycle += 1;
                        if select_cycle % 200 == 0 {  // Every ~10 seconds
                            eprintln!("[bonded-ffi] Worker: heartbeat - {} select cycles", select_cycle);
                        }
                    }
                }
            }
            eprintln!("[bonded-ffi] Worker thread: exiting main loop");
        });
    });

    let handle = AndroidSessionHandle {
        outbound_tx,
        inbound_queue,
        snapshot,
        stop_flag,
        worker: Some(worker),
    };

    let mut slot = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned");
    *slot = Some(handle);
    eprintln!("[bonded-ffi] Android session started successfully");
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn get_session_snapshot_json() -> Option<String> {
    android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| {
            let snapshot = handle
                .snapshot
                .lock()
                .expect("android session snapshot lock poisoned")
                .clone();
            snapshot_json(&snapshot)
        })
}

#[cfg(any(target_os = "android", test))]
fn queue_outbound_packet(packet: Vec<u8>) {
    if let Some(handle) = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
    {
        let packet_len = packet.len();
        eprintln!("[bonded-ffi] Queuing {} byte outbound packet", packet_len);
        let result = handle.outbound_tx.send(packet);
        if let Err(_) = result {
            let message = "Failed to queue outbound packet: channel closed";
            eprintln!("[bonded-ffi] {}", message);
            update_snapshot(&handle.snapshot, |session_snapshot| {
                session_snapshot.state = "error".to_owned();
                session_snapshot.last_error = Some(message.to_owned());
            });
        }
    } else {
        eprintln!("[bonded-ffi] Cannot queue outbound packet: no active session");
    }
}

#[cfg(any(target_os = "android", test))]
fn poll_inbound_packet() -> Option<Vec<u8>> {
    let result = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .and_then(|handle| {
            handle
                .inbound_queue
                .lock()
                .expect("android inbound queue lock poisoned")
                .pop_front()
        });

    if let Some(ref packet) = result {
        eprintln!("[bonded-ffi] Polled {} byte inbound packet", packet.len());
    }
    result
}

#[cfg(any(target_os = "android", test))]
fn redeem_invite_token(
    server_address: &str,
    _server_public_key: &str,
    invite_token: &str,
    storage_dir: &str,
) -> anyhow::Result<()> {
    let mut config = android_client_config(server_address, storage_dir);
    config.client.invite_token = invite_token.to_owned();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let stream = establish_naive_tcp_session(&config).await?;
        drop(stream);
        Ok::<(), anyhow::Error>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bonded_ffi_api_version() -> u32 {
    1
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_MainActivity_nativeApiVersion(
    _env: *mut jni_sys::JNIEnv,
    _clazz: jni_sys::jclass,
) -> jni_sys::jint {
    bonded_ffi_api_version() as jni_sys::jint
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_MainActivity_nativeRedeemInviteToken(
    mut env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    server_address: jni::objects::JString,
    server_public_key: jni::objects::JString,
    invite_token: jni::objects::JString,
    storage_dir: jni::objects::JString,
) -> jni::sys::jboolean {
    let server_address: String = match env.get_string(&server_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let server_public_key: String = match env.get_string(&server_public_key) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let invite_token: String = match env.get_string(&invite_token) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let storage_dir: String = match env.get_string(&storage_dir) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };

    if redeem_invite_token(
        &server_address,
        &server_public_key,
        &invite_token,
        &storage_dir,
    )
    .is_ok()
    {
        1
    } else {
        0
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeStartSession(
    mut env: jni::JNIEnv,
    obj: jni::objects::JObject,
    server_address: jni::objects::JString,
    protocol_csv: jni::objects::JString,
    path_count: jni::sys::jint,
    bind_addresses_json: jni::objects::JString,
    storage_dir: jni::objects::JString,
) -> jni::sys::jboolean {
    // Store global ref to the service so protect_fd can call back into Java.
    if let Ok(global_ref) = env.new_global_ref(&obj) {
        if let Ok(mut guard) = ANDROID_VPN_SERVICE.lock() {
            *guard = Some(global_ref);
        }
    }

    let server_address: String = match env.get_string(&server_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let protocol_csv: String = match env.get_string(&protocol_csv) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let bind_addresses_json: String = match env.get_string(&bind_addresses_json) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let storage_dir: String = match env.get_string(&storage_dir) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };

    if start_android_session(
        &server_address,
        &protocol_csv,
        path_count.max(1) as usize,
        &bind_addresses_json,
        &storage_dir,
    )
    .is_ok()
    {
        1
    } else {
        0
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeStopSession(
    _env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) {
    stop_android_session();
    // Release the VPN service global ref now that the session is stopped.
    if let Ok(mut guard) = ANDROID_VPN_SERVICE.lock() {
        *guard = None;
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeHandleTunOutbound(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    packet: jni::objects::JByteArray,
) {
    if let Ok(packet) = env.convert_byte_array(&packet) {
        queue_outbound_packet(packet);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativePollTunInbound(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) -> jni::sys::jbyteArray {
    match poll_inbound_packet() {
        Some(packet) => match env.byte_array_from_slice(&packet) {
            Ok(out) => out.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeGetSessionSnapshot(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) -> jni::sys::jstring {
    match get_session_snapshot_json() {
        Some(snapshot) => match env.new_string(snapshot) {
            Ok(value) => value.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `raw_ptr` must point to `raw_len` bytes of readable memory.
/// `out_metadata` must point to writable memory for one `BondedFrameMetadata`.
pub unsafe extern "C" fn bonded_ffi_decode_frame_metadata(
    raw_ptr: *const u8,
    raw_len: usize,
    out_metadata: *mut BondedFrameMetadata,
) -> i32 {
    if raw_ptr.is_null() || out_metadata.is_null() {
        return BONDED_FFI_ERR_NULL_POINTER;
    }

    // Safety: caller guarantees `raw_ptr` is valid for `raw_len` bytes.
    let raw = unsafe { slice::from_raw_parts(raw_ptr, raw_len) };
    match decode_frame_metadata(raw) {
        Ok(metadata) => {
            // Safety: caller guarantees `out_metadata` points to writable memory.
            unsafe {
                *out_metadata = metadata;
            }
            BONDED_FFI_OK
        }
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bonded_ffi_api_version, decode_frame_metadata, get_session_snapshot_json,
        poll_inbound_packet, queue_outbound_packet, redeem_invite_token, start_android_session,
        stop_android_session,
    };
    use bonded_core::auth::{create_auth_challenge, verify_auth_challenge};
    use bonded_core::session::{SessionFrame, SessionHeader};
    use bonded_core::transport::{NaiveTcpTransport, Transport};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn temp_dir_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-ffi-{name}-{stamp}"))
    }

    async fn handshake_server_connection(
        stream: TcpStream,
        expected_public_key: Option<&str>,
        expected_invite_token: &str,
    ) -> (String, TcpStream) {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let mut hello_line = String::new();
        reader
            .read_line(&mut hello_line)
            .await
            .expect("hello should be readable");
        let hello: serde_json::Value =
            serde_json::from_str(hello_line.trim_end()).expect("hello should parse");
        let public_key = hello["public_key_b64"]
            .as_str()
            .expect("public key should exist")
            .to_owned();
        if let Some(expected) = expected_public_key {
            assert_eq!(public_key, expected);
            assert_eq!(hello["invite_token"].as_str().unwrap_or_default(), "");
        } else {
            assert_eq!(
                hello["invite_token"].as_str().unwrap_or_default(),
                expected_invite_token
            );
        }

        let challenge_b64 = create_auth_challenge();
        let challenge = json!({ "challenge_b64": challenge_b64 });
        write_half
            .write_all(format!("{}\n", challenge).as_bytes())
            .await
            .expect("challenge should be written");

        let mut proof_line = String::new();
        reader
            .read_line(&mut proof_line)
            .await
            .expect("proof should be readable");
        let proof: serde_json::Value =
            serde_json::from_str(proof_line.trim_end()).expect("proof should parse");
        let signature_b64 = proof["signature_b64"]
            .as_str()
            .expect("signature should exist");
        verify_auth_challenge(&public_key, &challenge_b64, signature_b64)
            .expect("signature should verify");

        write_half
            .write_all(b"{\"status\":\"ok\"}\n")
            .await
            .expect("result should be written");

        let stream = reader
            .into_inner()
            .reunite(write_half)
            .expect("stream should reunite");
        (public_key, stream)
    }

    #[test]
    fn ffi_api_version_is_stable() {
        assert_eq!(bonded_ffi_api_version(), 1);
    }

    #[test]
    fn decode_frame_metadata_reads_session_headers() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 42,
                sequence: 9,
                flags: 7,
            },
            payload: b"hello".to_vec().into(),
        };

        let decoded = decode_frame_metadata(&frame.encode()).expect("decode should succeed");
        assert_eq!(decoded.connection_id, 42);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.flags, 7);
        assert_eq!(decoded.payload_len, 5);
    }

    #[test]
    fn decode_frame_metadata_rejects_short_buffers() {
        let result = decode_frame_metadata(b"tiny");
        assert!(result.is_err());
    }

    #[test]
    fn android_session_runtime_can_pair_and_exchange_packets() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let storage_dir = temp_dir_path("android-session-runtime");
        fs::create_dir_all(&storage_dir).expect("storage dir should be created");

        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let server_task = runtime.spawn(async move {
            let (pair_stream, _) = listener.accept().await.expect("pair accept should succeed");
            let (public_key, _) =
                handshake_server_connection(pair_stream, None, "android-invite").await;

            let (session_stream, session_peer_addr) = listener
                .accept()
                .await
                .expect("session accept should succeed");
            assert_eq!(session_peer_addr.ip().to_string(), "127.0.0.2");
            let (_, session_stream) =
                handshake_server_connection(session_stream, Some(&public_key), "").await;
            let mut transport = NaiveTcpTransport::from_stream(session_stream);
            let frame = transport.recv().await.expect("session frame should arrive");
            transport.send(frame).await.expect("echo should send");
        });

        redeem_invite_token(
            &addr.to_string(),
            "server-pub",
            "android-invite",
            storage_dir.to_string_lossy().as_ref(),
        )
        .expect("invite redemption should succeed");

        start_android_session(
            &addr.to_string(),
            "naive_tcp",
            1,
            "[\"127.0.0.2\"]",
            storage_dir.to_string_lossy().as_ref(),
        )
        .expect("android session should start");

        let connected = (0..20).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            get_session_snapshot_json()
                .map(|snapshot| snapshot.contains("\"state\":\"connected\""))
                .unwrap_or(false)
        });
        assert!(connected, "session should report connected state");

        queue_outbound_packet(b"android-smoke".to_vec());

        let echoed = (0..30)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(100));
                poll_inbound_packet()
            })
            .expect("inbound packet should be echoed back");
        assert_eq!(echoed, b"android-smoke");

        stop_android_session();
        runtime
            .block_on(server_task)
            .expect("server task should join");
        let _ = fs::remove_dir_all(storage_dir);
    }
}
