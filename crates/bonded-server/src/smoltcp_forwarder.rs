//! Network packet forwarder backed by smoltcp for TCP and raw OS sockets for UDP/ICMP.
//!
//! Architecture
//! ─────────────
//!
//! TCP (via smoltcp)
//! ─────────────────
//! Client raw-IPv4 packets arrive via `SmoltcpForwarder::ingest_packet()`.
//! Before feeding them to smoltcp the destination IP is rewritten from the
//! real internet address (e.g. 93.184.216.34) to the virtual NIC address
//! (SMOLTCP_IP = 10.200.0.1) so smoltcp accepts the traffic. A reverse
//! rewrite restores the original source IP in packets smoltcp emits.
//!
//! smoltcp runs a TCP state machine on a dedicated OS thread (non-Tokio so its
//! synchronous poll() never blocks async tasks). Established connections are
//! bridged to real OS `TcpStream`s via per-connection async Tokio tasks.
//!
//! UDP (direct)
//! ─────────────
//! One OS `UdpSocket` per flow, driven by per-flow Tokio tasks. No smoltcp
//! involvement; the existing proven pattern from frame_forwarder is kept.
//!
//! ICMP (direct)
//! ─────────────
//! One shared async ICMP socket per session, same pattern as before.

use bonded_core::session::{SessionFrame, SessionHeader};
use bytes::Bytes;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp as stcp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// The virtual NIC address smoltcp is configured with.  All inbound TCP/UDP
/// destination IPs are rewritten to this before being fed to smoltcp; outbound
/// source IPs are rewritten back to the original destination.
const SMOLTCP_IP_ARRAY: [u8; 4] = [10, 200, 0, 1];
const SMOLTCP_GW: Ipv4Address = Ipv4Address([10, 200, 0, 2]);
const MTU: usize = 1500;
const TCP_SOCKET_RX_BUF: usize = 65536;
const TCP_SOCKET_TX_BUF: usize = 65536;

// ── Public snapshot types (mirror frame_forwarder types for status.rs) ────────

#[derive(Debug, Clone)]
pub struct TcpFlowSnapshot {
    pub session_id: u64,
    pub client_src: String,
    pub client_dst: String,
    pub created_ago: String,
    pub last_activity_ago: String,
    pub client_to_remote_packets: u64,
    pub remote_to_client_packets: u64,
    pub bridge_read_chunks: u64,
    pub bridge_read_bytes: u64,
    pub bridge_read_avg_bytes: u64,
    pub bridge_to_smoltcp_chunks: u64,
    pub bridge_to_smoltcp_bytes: u64,
    pub bridge_to_smoltcp_avg_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct UdpFlowSnapshot {
    pub session_id: u64,
    pub client_src: String,
    pub client_dst: String,
    pub bound_socket: String,
    pub created_ago: String,
    pub last_client_ago: String,
    pub last_remote_ago: Option<String>,
    pub client_to_remote_packets: u64,
    pub remote_to_client_packets: u64,
}

#[derive(Debug, Clone)]
pub struct IcmpProbeSnapshot {
    pub session_id: u64,
    pub client_src: String,
    pub client_dst: String,
    pub echo_identifier: u16,
    pub echo_sequence: u16,
    pub outcome: String,
    pub observed_ago: String,
}

#[derive(Debug, Clone, Default)]
pub struct ForwarderSnapshot {
    pub tcp_flows: Vec<TcpFlowSnapshot>,
    pub udp_flows: Vec<UdpFlowSnapshot>,
    pub icmp_probes: Vec<IcmpProbeSnapshot>,
}

// ── Internal stats (written by smoltcp thread, read by status) ────────────────

#[derive(Debug)]
struct TcpFlowRecord {
    conn_id: u32,
    session_id: u64,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    created_at: SystemTime,
    last_activity_at: SystemTime,
    client_to_remote: u64,
    remote_to_client: u64,
    bridge_read_chunks: u64,
    bridge_read_bytes: u64,
    bridge_to_smoltcp_chunks: u64,
    bridge_to_smoltcp_bytes: u64,
}

#[derive(Debug, Default)]
struct TcpStats {
    flows: HashMap<SocketHandle, TcpFlowRecord>,
}

// ── Public API ─────────────────────────────────────────────────────────────────

pub struct SmoltcpForwarder {
    /// Command channel into the smoltcp poll thread.
    cmd_tx: std::sync::mpsc::SyncSender<PollCommand>,
    /// Wake-up condvar for the poll thread.
    work: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// Snapshot data shared with the status endpoint.
    tcp_stats: Arc<std::sync::RwLock<TcpStats>>,
    udp_tracker: UdpSessionTracker,
    icmp_tracker: IcmpSessionTracker,
    /// Active UDP flows keyed by (src_ip, src_port, dst_ip, dst_port).
    /// Shared with per-flow Tokio tasks so sockets are reused across packets.
    udp_flow_map: Arc<TokioMutex<HashMap<UdpFlowKey, UdpFlowHandle>>>,
    /// Outbound channel so UDP/ICMP handlers can send frames directly.
    outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    session_id: u64,
}

impl SmoltcpForwarder {
    /// Create the forwarder and start the smoltcp poll thread.
    pub fn new(session_id: u64, outbound_tx: mpsc::UnboundedSender<SessionFrame>) -> Self {
        let work = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let tcp_stats = Arc::new(std::sync::RwLock::new(TcpStats::default()));
        let udp_tracker = UdpSessionTracker::default();
        let icmp_tracker = IcmpSessionTracker::default();

        let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<PollCommand>(8192);

        let work_thread = work.clone();
        let tcp_stats_thread = tcp_stats.clone();
        let outbound_thread = outbound_tx.clone();
        let tokio_handle = tokio::runtime::Handle::current();

        std::thread::Builder::new()
            .name(format!("smoltcp-{session_id}"))
            .spawn(move || {
                smoltcp_poll_thread(
                    session_id,
                    cmd_rx,
                    work_thread,
                    outbound_thread,
                    tokio_handle,
                    tcp_stats_thread,
                );
            })
            .expect("smoltcp poll thread should spawn");

        Self {
            cmd_tx,
            work,
            tcp_stats,
            udp_tracker,
            icmp_tracker,
            udp_flow_map: Arc::new(TokioMutex::new(HashMap::new())),
            outbound_tx,
            session_id,
        }
    }

    /// Ingest one raw IPv4 frame from the client.
    ///
    /// TCP is dispatched to the smoltcp poll thread.
    /// UDP is handled inline via per-flow Tokio tasks.
    /// ICMP is handled inline via the shared ICMP socket.
    pub fn ingest_packet(&self, frame: SessionFrame) {
        let payload = frame.payload.as_ref();
        if payload.len() < 20 {
            return;
        }

        let protocol = payload[9];
        match protocol {
            6 => self.dispatch_tcp(frame),
            17 => self.dispatch_udp(frame),
            1 => self.dispatch_icmp(frame),
            _ => {} // unsupported protocol, drop
        }
    }

    /// Clear all state for this session (called on session teardown).
    pub fn clear_session(&self) {
        self.udp_tracker.clear_session(self.session_id);
        self.icmp_tracker.clear_session(self.session_id);
        // The smoltcp thread exits when cmd_tx is dropped (Self is dropped).
    }

    /// Return a snapshot for the /status endpoint.
    pub fn snapshot(&self) -> ForwarderSnapshot {
        let tcp_flows = {
            let now = SystemTime::now();
            self.tcp_stats
                .read()
                .expect("tcp stats read lock should not be poisoned")
                .flows
                .values()
                .map(|r| TcpFlowSnapshot {
                    session_id: r.session_id,
                    client_src: format!("{}:{}", r.src_ip, r.src_port),
                    client_dst: format!("{}:{}", r.dst_ip, r.dst_port),
                    created_ago: format_elapsed(now, r.created_at),
                    last_activity_ago: format_elapsed(now, r.last_activity_at),
                    client_to_remote_packets: r.client_to_remote,
                    remote_to_client_packets: r.remote_to_client,
                    bridge_read_chunks: r.bridge_read_chunks,
                    bridge_read_bytes: r.bridge_read_bytes,
                    bridge_read_avg_bytes: if r.bridge_read_chunks == 0 {
                        0
                    } else {
                        r.bridge_read_bytes / r.bridge_read_chunks
                    },
                    bridge_to_smoltcp_chunks: r.bridge_to_smoltcp_chunks,
                    bridge_to_smoltcp_bytes: r.bridge_to_smoltcp_bytes,
                    bridge_to_smoltcp_avg_bytes: if r.bridge_to_smoltcp_chunks == 0 {
                        0
                    } else {
                        r.bridge_to_smoltcp_bytes / r.bridge_to_smoltcp_chunks
                    },
                })
                .collect()
        };

        ForwarderSnapshot {
            tcp_flows,
            udp_flows: self.udp_tracker.snapshot(),
            icmp_probes: self.icmp_tracker.snapshot(),
        }
    }

    // ── TCP dispatch ──────────────────────────────────────────────────────────

    fn dispatch_tcp(&self, frame: SessionFrame) {
        let payload = frame.payload.as_ref();

        // Detect SYN to pre-create the smoltcp listening socket.
        let is_syn =
            if let Some((src_ip, src_port, dst_ip, dst_port, is_syn)) = parse_tcp_header(payload) {
                if is_syn {
                    let _ = self.cmd_tx.try_send(PollCommand::CreateTcpSocket {
                        listen_port: dst_port,
                        original_dst_ip: dst_ip,
                        client_src_ip: src_ip,
                        client_src_port: src_port,
                    });
                }
                is_syn
            } else {
                false
            };
        let _ = is_syn; // suppress unused warning

        // Rewrite dst_ip → SMOLTCP_IP (no checksum fix needed; smoltcp configured
        // to skip Rx checksum verification).
        if let Some(rewritten) = rewrite_dst_ip_inbound(payload) {
            let _ = self.cmd_tx.try_send(PollCommand::InjectPacket(rewritten));
            let (lock, cvar) = &*self.work;
            let mut flag = lock.lock().expect("work lock should not be poisoned");
            *flag = true;
            cvar.notify_one();
        }
    }

    // ── UDP dispatch ──────────────────────────────────────────────────────────

    fn dispatch_udp(&self, frame: SessionFrame) {
        let Some(udp_pkt) = parse_ipv4_udp_packet(&frame.payload) else {
            return;
        };
        let udp_manager = UdpSessionManager {
            session_id: self.session_id,
            outbound_tx: self.outbound_tx.clone(),
            tracker: self.udp_tracker.clone(),
            flow_map: self.udp_flow_map.clone(),
        };
        tokio::spawn(async move {
            if let Err(err) = udp_manager.forward_udp_packet(frame.header, udp_pkt).await {
                debug!(error = %err, "UDP forward error");
            }
        });
    }

    // ── ICMP dispatch ─────────────────────────────────────────────────────────

    fn dispatch_icmp(&self, frame: SessionFrame) {
        let Some(icmp_pkt) = parse_ipv4_icmp_echo_packet(&frame.payload) else {
            return;
        };
        let tracker = self.icmp_tracker.clone();
        let outbound_tx = self.outbound_tx.clone();
        let session_id = self.session_id;
        tokio::spawn(async move {
            match forward_icmp(icmp_pkt, frame.header, tracker, session_id).await {
                Ok(Some(response_frame)) => {
                    let _ = outbound_tx.send(response_frame);
                }
                Ok(None) => {}
                Err(err) => {
                    debug!(session_id, error = %err, "ICMP forward error");
                }
            }
        });
    }
}

// ── smoltcp Device implementation ─────────────────────────────────────────────

/// A simple in-process virtual NIC: rx/tx as `VecDeque<Vec<u8>>`.
struct RingDevice {
    rx: VecDeque<Vec<u8>>,
    /// Shared with tokens so both RxToken and TxToken can push to tx on the
    /// same single-threaded poll call.
    tx: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

struct OwnedRxToken(Vec<u8>);
impl RxToken for OwnedRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

struct OwnedTxToken(Rc<RefCell<VecDeque<Vec<u8>>>>);
impl TxToken for OwnedTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.borrow_mut().push_back(buf);
        r
    }
}

impl Device for RingDevice {
    type RxToken<'a>
        = OwnedRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = OwnedTxToken
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmoltcpInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx
            .pop_front()
            .map(|pkt| (OwnedRxToken(pkt), OwnedTxToken(self.tx.clone())))
    }

    fn transmit(&mut self, _ts: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        Some(OwnedTxToken(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        // Skip Rx checksum verification — we rewrite dst_ip inbound without
        // fixing checksums, so they would fail verification.
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

// ── Poll thread commands ───────────────────────────────────────────────────────

enum PollCommand {
    /// Raw (inbound-rewritten) IPv4 packet to inject into smoltcp.
    InjectPacket(Vec<u8>),
    /// Pre-create a TCP socket listening on `listen_port` before the SYN arrives.
    CreateTcpSocket {
        listen_port: u16,
        original_dst_ip: Ipv4Addr,
        client_src_ip: Ipv4Addr,
        client_src_port: u16,
    },
}

// ── Pending / established connection state ─────────────────────────────────────

struct PendingTcpConn {
    handle: SocketHandle,
    original_dst_ip: Ipv4Addr,
    dst_port: u16,
    client_src_ip: Ipv4Addr,
    client_src_port: u16,
}

struct ActiveTcpConn {
    original_dst_ip: Ipv4Addr,
    dst_port: u16,
    client_src_ip: Ipv4Addr,
    client_src_port: u16,
    /// Bytes from smoltcp → bridge task (to forward to real server).
    to_bridge: tokio::sync::mpsc::UnboundedSender<Bytes>,
    /// Bytes from bridge task (real server) → smoltcp.
    from_bridge: std::sync::mpsc::Receiver<Bytes>,
}

// ── smoltcp poll thread ────────────────────────────────────────────────────────

fn smoltcp_now() -> SmoltcpInstant {
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    SmoltcpInstant::from_micros(micros as i64)
}

fn smoltcp_poll_thread(
    session_id: u64,
    cmd_rx: std::sync::mpsc::Receiver<PollCommand>,
    work: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    tokio_handle: tokio::runtime::Handle,
    tcp_stats: Arc<std::sync::RwLock<TcpStats>>,
) {
    let tx_ring: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::new(RefCell::new(VecDeque::new()));
    let mut device = RingDevice {
        rx: VecDeque::new(),
        tx: tx_ring.clone(),
    };

    let iface_config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(iface_config, &mut device, smoltcp_now());

    iface.update_ip_addrs(|addrs| {
        // /8 covers the typical VPN client range (10.8.0.x etc.)
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address(SMOLTCP_IP_ARRAY)),
                8,
            ))
            .ok();
    });

    // Default route so smoltcp can respond to clients outside the /8.
    iface.routes_mut().add_default_ipv4_route(SMOLTCP_GW).ok();

    let mut sockets = SocketSet::new(vec![]);

    // Sockets waiting to transition from Listen → Established.
    // Key: SocketHandle.  Using a Vec to avoid HashMap overhead for few conns.
    let mut pending: Vec<PendingTcpConn> = Vec::new();
    // Established connections.
    let mut active: HashMap<SocketHandle, ActiveTcpConn> = HashMap::new();
    // Track which handles have been moved to active (to skip in pending scan).
    let mut promoted: HashSet<SocketHandle> = HashSet::new();

    let mut next_conn_id: u32 = 1;
    let mut global_seq: u64 = 0;

    loop {
        // ── Wait for work or 10 ms TCP-timer tick ────────────────────────────
        {
            let (lock, cvar) = &*work;
            let guard = lock.lock().expect("work lock should not be poisoned");
            if !*guard {
                let _ = cvar.wait_timeout(guard, Duration::from_millis(10));
            } else {
                let mut g = guard;
                *g = false;
            }
        }

        // ── Drain commands ────────────────────────────────────────────────────
        loop {
            match cmd_rx.try_recv() {
                Ok(PollCommand::InjectPacket(pkt)) => {
                    device.rx.push_back(pkt);
                }
                Ok(PollCommand::CreateTcpSocket {
                    listen_port,
                    original_dst_ip,
                    client_src_ip,
                    client_src_port,
                }) => {
                    let rx_buf = stcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_RX_BUF]);
                    let tx_buf = stcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_TX_BUF]);
                    let mut socket = stcp::Socket::new(rx_buf, tx_buf);
                    if socket.listen(listen_port).is_ok() {
                        let handle = sockets.add(socket);
                        pending.push(PendingTcpConn {
                            handle,
                            original_dst_ip,
                            dst_port: listen_port,
                            client_src_ip,
                            client_src_port,
                        });
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Session dropped; exit the thread.
                    return;
                }
            }
        }

        // ── smoltcp poll ──────────────────────────────────────────────────────
        let ts = smoltcp_now();
        iface.poll(ts, &mut device, &mut sockets);

        // ── Drain TX ring: rewrite src_ip and send to client ─────────────────
        {
            let mut tx_pkts = tx_ring.borrow_mut();
            while let Some(mut pkt) = tx_pkts.pop_front() {
                // src_ip in smoltcp-generated packet = SMOLTCP_IP.
                // Look up the original dst_ip for this flow.
                if pkt.len() < 20 || pkt[0] >> 4 != 4 {
                    continue;
                }
                let smoltcp_dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                let smoltcp_src_port_at = 20u16; // TCP/UDP src port offset in transport header
                let smoltcp_dst_port = if pkt.len() >= 24 {
                    u16::from_be_bytes([pkt[22], pkt[23]])
                } else {
                    continue;
                };

                // Find the original dst IP: match active conn by (dst_ip=client, dst_port=client_src_port, src_port=conn_port)
                // smoltcp emits: src=SMOLTCP_IP:listen_port, dst=client_src_ip:client_src_port
                let original_src_ip = active.values().find_map(|c| {
                    if c.client_src_ip == smoltcp_dst_ip
                        && c.client_src_port == smoltcp_dst_port
                        && c.dst_port
                            == u16::from_be_bytes([
                                pkt[smoltcp_src_port_at as usize],
                                pkt[smoltcp_src_port_at as usize + 1],
                            ])
                    {
                        Some(c.original_dst_ip)
                    } else {
                        None
                    }
                });

                let Some(original_src) = original_src_ip else {
                    // Could not find matching connection (e.g. SYN-ACK before
                    // we moved to active).  Look in pending too.
                    let original_src_pending = pending.iter().find_map(|p| {
                        if p.client_src_ip == smoltcp_dst_ip
                            && p.client_src_port == smoltcp_dst_port
                            && p.dst_port
                                == u16::from_be_bytes([
                                    pkt[smoltcp_src_port_at as usize],
                                    pkt[smoltcp_src_port_at as usize + 1],
                                ])
                        {
                            Some(p.original_dst_ip)
                        } else {
                            None
                        }
                    });
                    let Some(original_src) = original_src_pending else {
                        continue;
                    };
                    rewrite_src_ip_outbound(&mut pkt, original_src);
                    let frame = SessionFrame {
                        header: SessionHeader {
                            connection_id: 0,
                            sequence: global_seq,
                            flags: 0,
                        },
                        payload: Bytes::from(pkt),
                    };
                    global_seq = global_seq.wrapping_add(1);
                    let _ = outbound_tx.send(frame);
                    continue;
                };

                rewrite_src_ip_outbound(&mut pkt, original_src);
                let frame = SessionFrame {
                    header: SessionHeader {
                        connection_id: 0,
                        sequence: global_seq,
                        flags: 0,
                    },
                    payload: Bytes::from(pkt),
                };
                global_seq = global_seq.wrapping_add(1);
                let _ = outbound_tx.send(frame);
            }
        }

        // ── Promote newly-established connections ─────────────────────────────
        let mut newly_established: Vec<usize> = Vec::new();
        for (idx, p) in pending.iter().enumerate() {
            if promoted.contains(&p.handle) {
                continue;
            }
            let socket = sockets.get::<stcp::Socket>(p.handle);
            if socket.state() == stcp::State::Established {
                newly_established.push(idx);
            }
        }

        for &idx in newly_established.iter().rev() {
            let p = pending.remove(idx);
            promoted.insert(p.handle);

            let (to_bridge_tx, to_bridge_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
            let (from_bridge_tx, from_bridge_rx) = std::sync::mpsc::channel::<Bytes>();

            let conn_id = next_conn_id;
            next_conn_id = next_conn_id.wrapping_add(1).max(1);

            let dst = SocketAddrV4::new(p.original_dst_ip, p.dst_port);
            let work_notify = work.clone();
            let outbound_bridge = outbound_tx.clone();
            let session_id_copy = session_id;
            let conn_id_copy = conn_id;
            let tcp_stats_bridge = tcp_stats.clone();

            tokio_handle.spawn(async move {
                tcp_bridge_task(
                    session_id_copy,
                    conn_id_copy,
                    dst,
                    to_bridge_rx,
                    from_bridge_tx,
                    work_notify,
                    tcp_stats_bridge,
                    outbound_bridge,
                )
                .await;
            });

            let now = SystemTime::now();
            if let Ok(mut stats) = tcp_stats.write() {
                stats.flows.insert(
                    p.handle,
                    TcpFlowRecord {
                        conn_id,
                        session_id,
                        src_ip: p.client_src_ip,
                        src_port: p.client_src_port,
                        dst_ip: p.original_dst_ip,
                        dst_port: p.dst_port,
                        created_at: now,
                        last_activity_at: now,
                        client_to_remote: 0,
                        remote_to_client: 0,
                        bridge_read_chunks: 0,
                        bridge_read_bytes: 0,
                        bridge_to_smoltcp_chunks: 0,
                        bridge_to_smoltcp_bytes: 0,
                    },
                );
            }

            active.insert(
                p.handle,
                ActiveTcpConn {
                    original_dst_ip: p.original_dst_ip,
                    dst_port: p.dst_port,
                    client_src_ip: p.client_src_ip,
                    client_src_port: p.client_src_port,
                    to_bridge: to_bridge_tx,
                    from_bridge: from_bridge_rx,
                },
            );
        }

        // ── Service active TCP connections ─────────────────────────────────────
        let active_handles: Vec<SocketHandle> = active.keys().copied().collect();
        for handle in active_handles {
            let socket = sockets.get_mut::<stcp::Socket>(handle);
            let conn = active.get_mut(&handle).unwrap();

            // Data smoltcp received from client → send to bridge task for
            // forwarding to the real server.
            if socket.can_recv() {
                let _ = socket.recv(|data| {
                    if !data.is_empty() {
                        let bytes = Bytes::copy_from_slice(data);
                        let _ = conn.to_bridge.send(bytes);
                        if let Ok(mut stats) = tcp_stats.write() {
                            if let Some(r) = stats.flows.get_mut(&handle) {
                                r.client_to_remote = r.client_to_remote.saturating_add(1);
                                r.last_activity_at = SystemTime::now();
                            }
                        }
                    }
                    (data.len(), ())
                });
            }

            // Data from bridge task (real server) → write into smoltcp socket.
            while socket.can_send() {
                match conn.from_bridge.try_recv() {
                    Ok(bytes) => {
                        let _ = socket.send_slice(&bytes);
                        if let Ok(mut stats) = tcp_stats.write() {
                            if let Some(r) = stats.flows.get_mut(&handle) {
                                r.remote_to_client = r.remote_to_client.saturating_add(1);
                                r.bridge_to_smoltcp_chunks =
                                    r.bridge_to_smoltcp_chunks.saturating_add(1);
                                r.bridge_to_smoltcp_bytes =
                                    r.bridge_to_smoltcp_bytes.saturating_add(bytes.len() as u64);
                                r.last_activity_at = SystemTime::now();
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // ── Remove closed connections ─────────────────────────────────────────
        let closed: Vec<SocketHandle> = active
            .keys()
            .copied()
            .filter(|h| {
                let s = sockets.get::<stcp::Socket>(*h);
                !s.is_active() && s.state() != stcp::State::Listen
            })
            .collect();
        for h in closed {
            active.remove(&h);
            promoted.remove(&h);
            sockets.remove(h);
            if let Ok(mut stats) = tcp_stats.write() {
                stats.flows.remove(&h);
            }
        }

        // Clean up promoted handles that are no longer in pending.
        promoted.retain(|h| active.contains_key(h));
    }
}

// ── TCP bridge task (Tokio) ────────────────────────────────────────────────────
//
// Bridges a smoltcp TCP socket (via channels) to a real OS TcpStream.

async fn tcp_bridge_task(
    session_id: u64,
    conn_id: u32,
    dst: SocketAddrV4,
    mut from_smoltcp: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    to_smoltcp: std::sync::mpsc::Sender<Bytes>,
    work: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    tcp_stats: Arc<std::sync::RwLock<TcpStats>>,
    _outbound_tx: mpsc::UnboundedSender<SessionFrame>,
) {
    let stream = match TcpStream::connect(dst).await {
        Ok(s) => s,
        Err(err) => {
            warn!(session_id, %dst, error = %err, "TCP bridge: connect failed");
            return;
        }
    };
    if let Err(err) = stream.set_nodelay(true) {
        warn!(session_id, %dst, error = %err, "TCP bridge: failed to enable TCP_NODELAY");
    }
    debug!(session_id, %dst, "TCP bridge: connected");

    let (mut reader, mut writer) = stream.into_split();
    let to_smoltcp_read = to_smoltcp.clone();
    let work_read = work.clone();
    let tcp_stats_read = tcp_stats.clone();

    // Spawn a separate task to pump data from the real server → smoltcp.
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let bytes = Bytes::copy_from_slice(&buf[..n]);
                    if let Ok(mut stats) = tcp_stats_read.write() {
                        if let Some(record) =
                            stats.flows.values_mut().find(|r| r.conn_id == conn_id)
                        {
                            record.bridge_read_chunks = record.bridge_read_chunks.saturating_add(1);
                            record.bridge_read_bytes =
                                record.bridge_read_bytes.saturating_add(n as u64);
                            record.last_activity_at = SystemTime::now();
                        }
                    }
                    if to_smoltcp_read.send(bytes).is_err() {
                        break;
                    }
                    // Wake smoltcp poll thread so it picks up the new data.
                    let (lock, cvar) = &*work_read;
                    if let Ok(mut flag) = lock.lock() {
                        *flag = true;
                        cvar.notify_one();
                    }
                }
                Err(err) => {
                    debug!(session_id, conn_id, error = %err, "TCP bridge: read error");
                    break;
                }
            }
        }
    });

    // Pump data from smoltcp → real server.
    while let Some(bytes) = from_smoltcp.recv().await {
        if let Err(err) = writer.write_all(&bytes).await {
            debug!(session_id, conn_id, error = %err, "TCP bridge: write error");
            break;
        }
    }

    read_task.abort();
    debug!(session_id, conn_id, %dst, "TCP bridge: closed");
}

// ── IP rewriting helpers ───────────────────────────────────────────────────────

/// Rewrite `dst_ip` of an inbound IPv4 packet to SMOLTCP_IP.
/// Does NOT recompute checksums — smoltcp is configured to skip Rx verification.
fn rewrite_dst_ip_inbound(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let mut pkt = packet.to_vec();
    pkt[16..20].copy_from_slice(&SMOLTCP_IP_ARRAY);
    // Recompute IP header checksum (TCP/UDP checksums are intentionally left stale).
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    pkt[10..12].copy_from_slice(&[0, 0]);
    let cksum = ipv4_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
    Some(pkt)
}

/// Rewrite `src_ip` in an outbound IPv4 packet back to the original destination
/// and recompute both the IP header checksum and the transport (TCP/UDP) checksum.
fn rewrite_src_ip_outbound(pkt: &mut [u8], original_src: Ipv4Addr) {
    if pkt.len() < 20 {
        return;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    pkt[12..16].copy_from_slice(&original_src.octets());
    // Recompute IP header checksum.
    pkt[10..12].copy_from_slice(&[0, 0]);
    let cksum = ipv4_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
    // Recompute TCP/UDP checksum (pseudo-header includes src_ip).
    let protocol = pkt[9];
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len > pkt.len() || total_len < ihl {
        return;
    }
    let transport = &mut pkt[ihl..total_len];
    match protocol {
        6 if transport.len() >= 20 => {
            transport[16..18].copy_from_slice(&[0, 0]);
            let cksum = tcp_udp_checksum_ipv4(src_ip, dst_ip, 6, transport);
            transport[16..18].copy_from_slice(&cksum.to_be_bytes());
        }
        17 if transport.len() >= 8 => {
            transport[6..8].copy_from_slice(&[0, 0]);
            let cksum = tcp_udp_checksum_ipv4(src_ip, dst_ip, 17, transport);
            transport[6..8].copy_from_slice(&cksum.to_be_bytes());
        }
        _ => {}
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    ones_complement_sum(header)
}

fn tcp_udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let len = segment.len();
    let mut pseudo = Vec::with_capacity(12 + len + (len % 2));
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(len as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    if len % 2 == 1 {
        pseudo.push(0);
    }
    let ck = ones_complement_sum(&pseudo);
    if ck == 0 {
        0xffff
    } else {
        ck
    }
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ── TCP header parser (minimal — only extracts the fields we need) ─────────────

/// Returns `(src_ip, src_port, dst_ip, dst_port, is_syn)` or None.
fn parse_tcp_header(packet: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16, bool)> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 || packet[9] != 6 {
        return None;
    }
    let ihl_bytes = ihl * 4;
    if packet.len() < ihl_bytes + 20 {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl_bytes..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let is_syn = flags & 0x02 != 0 && flags & 0x10 == 0; // SYN set, ACK clear
    Some((src_ip, src_port, dst_ip, dst_port, is_syn))
}

// ── UDP handling (direct OS sockets, same pattern as original frame_forwarder) ─

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    identification: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct UdpFlowKey {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug)]
struct UdpFlowState {
    connection_id: u32,
    next_sequence: u64,
    identification: u16,
    last_client_at: Instant,
}

#[derive(Debug, Clone)]
struct UdpFlowHandle {
    socket: Arc<UdpSocket>,
    state: Arc<TokioMutex<UdpFlowState>>,
}

#[derive(Debug, Clone)]
struct UdpFlowStatus {
    session_id: u64,
    key: UdpFlowKey,
    bound_socket: String,
    created_at: SystemTime,
    last_client_packet_at: SystemTime,
    last_remote_packet_at: Option<SystemTime>,
    client_to_remote_packets: u64,
    remote_to_client_packets: u64,
}

#[derive(Debug, Default, Clone)]
pub struct UdpSessionTracker {
    inner: Arc<RwLock<HashMap<(u64, UdpFlowKey), UdpFlowStatus>>>,
}

impl UdpSessionTracker {
    fn register_flow(&self, session_id: u64, key: UdpFlowKey, bound_socket: String) {
        let now = SystemTime::now();
        self.inner.write().expect("udp tracker write lock").insert(
            (session_id, key.clone()),
            UdpFlowStatus {
                session_id,
                key,
                bound_socket,
                created_at: now,
                last_client_packet_at: now,
                last_remote_packet_at: None,
                client_to_remote_packets: 0,
                remote_to_client_packets: 0,
            },
        );
    }

    fn touch_client(&self, session_id: u64, key: &UdpFlowKey) {
        if let Some(e) = self
            .inner
            .write()
            .expect("udp tracker write lock")
            .get_mut(&(session_id, key.clone()))
        {
            e.last_client_packet_at = SystemTime::now();
            e.client_to_remote_packets = e.client_to_remote_packets.saturating_add(1);
        }
    }

    fn touch_remote(&self, session_id: u64, key: &UdpFlowKey) {
        if let Some(e) = self
            .inner
            .write()
            .expect("udp tracker write lock")
            .get_mut(&(session_id, key.clone()))
        {
            e.last_remote_packet_at = Some(SystemTime::now());
            e.remote_to_client_packets = e.remote_to_client_packets.saturating_add(1);
        }
    }

    fn remove_flow(&self, session_id: u64, key: &UdpFlowKey) {
        self.inner
            .write()
            .expect("udp tracker write lock")
            .remove(&(session_id, key.clone()));
    }

    pub fn clear_session(&self, session_id: u64) {
        self.inner
            .write()
            .expect("udp tracker write lock")
            .retain(|(sid, _), _| *sid != session_id);
    }

    pub fn snapshot(&self) -> Vec<UdpFlowSnapshot> {
        let now = SystemTime::now();
        let guard = self.inner.read().expect("udp tracker read lock");
        let mut rows: Vec<UdpFlowSnapshot> = guard
            .values()
            .map(|e| UdpFlowSnapshot {
                session_id: e.session_id,
                client_src: format!("{}:{}", e.key.src_ip, e.key.src_port),
                client_dst: format!("{}:{}", e.key.dst_ip, e.key.dst_port),
                bound_socket: e.bound_socket.clone(),
                created_ago: format_elapsed(now, e.created_at),
                last_client_ago: format_elapsed(now, e.last_client_packet_at),
                last_remote_ago: e.last_remote_packet_at.map(|t| format_elapsed(now, t)),
                client_to_remote_packets: e.client_to_remote_packets,
                remote_to_client_packets: e.remote_to_client_packets,
            })
            .collect();
        rows.sort_by(|a, b| {
            a.session_id
                .cmp(&b.session_id)
                .then(a.client_src.cmp(&b.client_src))
        });
        rows
    }
}

struct UdpSessionManager {
    session_id: u64,
    outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    tracker: UdpSessionTracker,
    /// Shared per-session flow map so each 4-tuple reuses one OS socket.
    flow_map: Arc<TokioMutex<HashMap<UdpFlowKey, UdpFlowHandle>>>,
}

impl UdpSessionManager {
    async fn forward_udp_packet(
        &self,
        frame_header: SessionHeader,
        pkt: Ipv4UdpPacket,
    ) -> anyhow::Result<()> {
        let key = UdpFlowKey {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        };
        let handle = self.ensure_flow(&key, &pkt, frame_header).await?;

        {
            let mut state = handle.state.lock().await;
            state.identification = pkt.identification;
            state.last_client_at = Instant::now();
            // Keep the connection_id aligned to the latest request.
            state.connection_id = frame_header.connection_id;
            if frame_header.sequence > state.next_sequence {
                state.next_sequence = frame_header.sequence;
            }
        }
        self.tracker.touch_client(self.session_id, &key);
        handle.socket.send(&pkt.payload).await?;
        Ok(())
    }

    async fn ensure_flow(
        &self,
        key: &UdpFlowKey,
        pkt: &Ipv4UdpPacket,
        frame_header: SessionHeader,
    ) -> anyhow::Result<UdpFlowHandle> {
        // Fast path: return existing socket for this 4-tuple.
        {
            let map = self.flow_map.lock().await;
            if let Some(handle) = map.get(key) {
                return Ok(handle.clone());
            }
        }

        // Slow path: create a new connected UDP socket for this flow.
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket
            .connect(SocketAddrV4::new(pkt.dst_ip, pkt.dst_port))
            .await?;
        let bound = socket.local_addr()?.to_string();

        let handle = UdpFlowHandle {
            socket: socket.clone(),
            state: Arc::new(TokioMutex::new(UdpFlowState {
                connection_id: frame_header.connection_id,
                next_sequence: frame_header.sequence,
                identification: pkt.identification,
                last_client_at: Instant::now(),
            })),
        };

        // Insert, but check again under the lock to avoid duplicate sockets.
        {
            let mut map = self.flow_map.lock().await;
            if let Some(existing) = map.get(key) {
                // Another task raced us; drop our socket and use theirs.
                return Ok(existing.clone());
            }
            map.insert(key.clone(), handle.clone());
        }

        self.tracker
            .register_flow(self.session_id, key.clone(), bound);

        // Spawn a task to pump responses back to the client.
        let outbound_tx = self.outbound_tx.clone();
        let tracker = self.tracker.clone();
        let flow_map = self.flow_map.clone();
        let key_task = key.clone();
        let state_task = handle.state.clone();
        let session_id = self.session_id;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let idle = {
                    let g = state_task.lock().await;
                    g.last_client_at.elapsed() >= Duration::from_secs(240)
                };
                if idle {
                    break;
                }
                let n = match timeout(Duration::from_secs(1), socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                };
                if n == 0 {
                    continue;
                }
                let (header, identification) = {
                    let mut g = state_task.lock().await;
                    let h = SessionHeader {
                        connection_id: g.connection_id,
                        sequence: g.next_sequence,
                        flags: 0,
                    };
                    g.next_sequence = g.next_sequence.wrapping_add(1);
                    (h, g.identification)
                };

                let Ok(response_pkt) = build_ipv4_udp_packet(
                    key_task.dst_ip,
                    key_task.src_ip,
                    key_task.dst_port,
                    key_task.src_port,
                    identification,
                    &buf[..n],
                ) else {
                    continue;
                };

                tracker.touch_remote(session_id, &key_task);
                if outbound_tx
                    .send(SessionFrame {
                        header,
                        payload: response_pkt.into(),
                    })
                    .is_err()
                {
                    break;
                }
            }
            flow_map.lock().await.remove(&key_task);
            tracker.remove_flow(session_id, &key_task);
        });

        Ok(handle)
    }
}

// ── ICMP handling (same pattern as original AsyncIcmpSocket) ───────────────────

#[derive(Debug, Clone)]
struct Ipv4IcmpEchoPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identification: u16,
    echo_identifier: u16,
    echo_sequence: u16,
    icmp_segment: Vec<u8>,
}

#[derive(Debug, Clone)]
struct IcmpProbeStatus {
    session_id: u64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    echo_identifier: u16,
    echo_sequence: u16,
    outcome: String,
    observed_at: SystemTime,
}

#[derive(Debug, Default, Clone)]
pub struct IcmpSessionTracker {
    inner: Arc<RwLock<VecDeque<IcmpProbeStatus>>>,
}

impl IcmpSessionTracker {
    const MAX_EVENTS: usize = 256;

    fn record_probe(&self, session_id: u64, pkt: &Ipv4IcmpEchoPacket, outcome: &str) {
        let mut g = self.inner.write().expect("icmp tracker write lock");
        g.push_front(IcmpProbeStatus {
            session_id,
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            echo_identifier: pkt.echo_identifier,
            echo_sequence: pkt.echo_sequence,
            outcome: outcome.to_owned(),
            observed_at: SystemTime::now(),
        });
        while g.len() > Self::MAX_EVENTS {
            g.pop_back();
        }
    }

    pub fn clear_session(&self, session_id: u64) {
        self.inner
            .write()
            .expect("icmp tracker write lock")
            .retain(|e| e.session_id != session_id);
    }

    pub fn snapshot(&self) -> Vec<IcmpProbeSnapshot> {
        let now = SystemTime::now();
        self.inner
            .read()
            .expect("icmp tracker read lock")
            .iter()
            .map(|e| IcmpProbeSnapshot {
                session_id: e.session_id,
                client_src: e.src_ip.to_string(),
                client_dst: e.dst_ip.to_string(),
                echo_identifier: e.echo_identifier,
                echo_sequence: e.echo_sequence,
                outcome: e.outcome.clone(),
                observed_ago: format_elapsed(now, e.observed_at),
            })
            .collect()
    }
}

async fn forward_icmp(
    pkt: Ipv4IcmpEchoPacket,
    header: SessionHeader,
    tracker: IcmpSessionTracker,
    session_id: u64,
) -> anyhow::Result<Option<SessionFrame>> {
    let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    raw.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = raw.into();
    let socket = tokio::net::UdpSocket::from_std(std_sock)?;

    let target = std::net::SocketAddrV4::new(pkt.dst_ip, 0);
    socket.send_to(&pkt.icmp_segment, target).await?;

    let mut buf = vec![0u8; 65535];
    let reply_seg = match timeout(Duration::from_millis(1200), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            if n < 8 || buf[0] != 0 {
                tracker.record_probe(session_id, &pkt, "no-echo-reply");
                return Ok(None);
            }
            let mut seg = buf[..n].to_vec();
            // Restore caller-supplied echo identifier and recompute checksum.
            seg[4..6].copy_from_slice(&pkt.echo_identifier.to_be_bytes());
            seg[2..4].copy_from_slice(&[0, 0]);
            let ck = ones_complement_sum(&seg);
            seg[2..4].copy_from_slice(&ck.to_be_bytes());
            seg
        }
        _ => {
            tracker.record_probe(session_id, &pkt, "timeout");
            return Ok(None);
        }
    };

    let response_pkt =
        build_ipv4_icmp_packet(pkt.dst_ip, pkt.src_ip, pkt.identification, &reply_seg)?;
    tracker.record_probe(session_id, &pkt, "reply");
    Ok(Some(SessionFrame {
        header,
        payload: response_pkt.into(),
    }))
}

// ── Packet parsers ─────────────────────────────────────────────────────────────

fn parse_ipv4_udp_packet(packet: &[u8]) -> Option<Ipv4UdpPacket> {
    if packet.len() < 28 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 || packet[9] != 17 {
        return None;
    }
    let hlen = ihl * 4;
    if packet.len() < hlen + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < hlen + 8 || total_len > packet.len() {
        return None;
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    if frag & 0x3fff != 0 {
        return None; // fragmented
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let udp = &packet[hlen..];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || hlen + udp_len > total_len {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = udp[8..udp_len].to_vec();
    Some(Ipv4UdpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
        identification,
    })
}

fn parse_ipv4_icmp_echo_packet(packet: &[u8]) -> Option<Ipv4IcmpEchoPacket> {
    if packet.len() < 28 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 || packet[9] != 1 {
        return None;
    }
    let hlen = ihl * 4;
    if packet.len() < hlen + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < hlen + 8 || total_len > packet.len() {
        return None;
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    let icmp = &packet[hlen..];
    if icmp[0] != 8 || icmp[1] != 0 {
        return None; // not echo request
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let identification = u16::from_be_bytes([packet[4], packet[5]]);
    let echo_identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let echo_sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some(Ipv4IcmpEchoPacket {
        src_ip,
        dst_ip,
        identification,
        echo_identifier,
        echo_sequence,
        icmp_segment: packet[hlen..total_len].to_vec(),
    })
}

// ── Packet builders ────────────────────────────────────────────────────────────

fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    identification: u16,
    udp_payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ip_hlen = 20usize;
    let total_len = ip_hlen + 8 + udp_payload.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("udp response too large");
    }
    let udp_len = (8 + udp_payload.len()) as u16;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&identification.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(udp_payload);
    let ip_cksum = ipv4_checksum(&pkt[..ip_hlen]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    let udp_cksum = tcp_udp_checksum_ipv4(src_ip, dst_ip, 17, &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_cksum.to_be_bytes());
    Ok(pkt)
}

fn build_ipv4_icmp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identification: u16,
    icmp_segment: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ip_hlen = 20usize;
    if icmp_segment.len() < 8 {
        anyhow::bail!("icmp segment too short");
    }
    let total_len = ip_hlen + icmp_segment.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("icmp response too large");
    }
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&identification.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    pkt[ip_hlen..].copy_from_slice(icmp_segment);
    pkt[ip_hlen + 2..ip_hlen + 4].copy_from_slice(&[0, 0]);
    let ck = ones_complement_sum(&pkt[ip_hlen..]);
    pkt[ip_hlen + 2..ip_hlen + 4].copy_from_slice(&ck.to_be_bytes());
    let ip_cksum = ipv4_checksum(&pkt[..ip_hlen]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    Ok(pkt)
}

// ── Formatting helpers ─────────────────────────────────────────────────────────

fn format_elapsed(now: SystemTime, value: SystemTime) -> String {
    match now.duration_since(value) {
        Ok(d) => {
            let s = d.as_secs();
            if s >= 60 {
                format!("{}m {}s ago", s / 60, s % 60)
            } else {
                format!("{s}s ago")
            }
        }
        Err(_) => "just now".to_owned(),
    }
}
