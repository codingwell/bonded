use crate::frame_forwarder::{
    IcmpProbeSnapshot, IcmpSessionTracker, TcpFlowSnapshot, TcpSessionTracker, UdpFlowSnapshot,
    UdpSessionTracker,
};
use crate::session_registry::SessionRegistry;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run_status_server(
    bind: &str,
    sessions: SessionRegistry,
    udp_tracker: UdpSessionTracker,
    tcp_tracker: TcpSessionTracker,
    icmp_tracker: IcmpSessionTracker,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "status listener bound");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(bind = %bind, error = %err, "failed to accept status connection");
                continue;
            }
        };

        let page = render_status_page(
            &sessions,
            &udp_tracker.snapshot(),
            &tcp_tracker.snapshot(),
            &icmp_tracker.snapshot(),
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            page.len(),
            page
        );

        if let Err(err) = stream.write_all(response.as_bytes()).await {
            error!(peer = %peer, error = %err, "failed to write status response");
        }
    }
}

fn render_status_page(
    sessions: &SessionRegistry,
    udp_flows: &[UdpFlowSnapshot],
    tcp_flows: &[TcpFlowSnapshot],
    icmp_probes: &[IcmpProbeSnapshot],
) -> String {
    let session_rows = sessions
        .snapshot()
        .into_iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&abbreviate_key(&entry.client_key))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let udp_rows = udp_flows
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.bound_socket),
                escape_html(&entry.created_ago),
                escape_html(&entry.last_client_ago),
                escape_html(entry.last_remote_ago.as_deref().unwrap_or("never"))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let tcp_rows = tcp_flows
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.created_ago),
                escape_html(&entry.last_activity_ago)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let icmp_rows = icmp_probes
        .iter()
        .take(64)
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.echo_identifier.to_string()),
                escape_html(&entry.echo_sequence.to_string()),
                escape_html(&entry.outcome),
                escape_html(&entry.observed_ago)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "<!doctype html>
<html>
<head>
<meta charset=\"utf-8\" />
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
<meta http-equiv=\"refresh\" content=\"2\" />
<title>Bonded Server Status</title>
<style>
body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 24px; background: #f8fafc; color: #111827; }}
h1 {{ margin-bottom: 8px; }}
.card {{ background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #e5e7eb; text-align: left; padding: 8px; vertical-align: top; }}
th {{ background: #f3f4f6; }}
small {{ color: #6b7280; }}
</style>
</head>
<body>
<h1>Bonded Server Status</h1>
<small>Auto-refreshes every 2 seconds.</small>
<div class=\"card\">
<h2>Authenticated Sessions ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Key</th></tr></thead>
<tbody>{}</tbody>
</table>
</div>
<div class=\"card\">
<h2>Active UDP Flows ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Server UDP Socket</th><th>Created</th><th>Last Client Packet</th><th>Last Remote Packet</th></tr></thead>
<tbody>{}</tbody>
</table>
</div>
<div class=\"card\">
<h2>Active TCP Flows ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Created</th><th>Last Activity</th></tr></thead>
<tbody>{}</tbody>
</table>
</div>
<div class=\"card\">
<h2>Recent ICMP Probes ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Echo ID</th><th>Seq</th><th>Outcome</th><th>Observed</th></tr></thead>
<tbody>{}</tbody>
</table>
</div>
</body>
</html>",
        sessions.active_sessions(),
        if session_rows.is_empty() {
            "<tr><td colspan=\"2\">No active authenticated sessions.</td></tr>".to_owned()
        } else {
            session_rows
        },
        udp_flows.len(),
        if udp_rows.is_empty() {
            "<tr><td colspan=\"7\">No active UDP flows.</td></tr>".to_owned()
        } else {
            udp_rows
        },
        tcp_flows.len(),
        if tcp_rows.is_empty() {
            "<tr><td colspan=\"5\">No active TCP flows.</td></tr>".to_owned()
        } else {
            tcp_rows
        },
        icmp_probes.len(),
        if icmp_rows.is_empty() {
            "<tr><td colspan=\"7\">No recent ICMP probes.</td></tr>".to_owned()
        } else {
            icmp_rows
        }
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn abbreviate_key(key: &str) -> String {
    if key.len() <= 24 {
        return key.to_owned();
    }

    format!("{}...{}", &key[..12], &key[key.len() - 8..])
}
