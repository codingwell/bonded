use anyhow::{anyhow, Context};
use bonded_core::config::ServerSection;
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;

pub struct NetworkRuntime {
    tun_name: String,
    original_ip_forward: Option<String>,
    masquerade_rule_installed: bool,
    forward_out_rule_installed: bool,
    forward_in_rule_installed: bool,
    forwarding_mode_tun: bool,
    _tun_device: Option<tun::AsyncDevice>,
    tun_subnet: Option<String>,
    egress_interface: Option<String>,
}

impl NetworkRuntime {
    pub fn setup(cfg: &ServerSection) -> anyhow::Result<Self> {
        let forwarding_mode_tun = cfg.forwarding_mode.eq_ignore_ascii_case("tun");
        if !forwarding_mode_tun {
            return Ok(Self {
                tun_name: cfg.tun_name.clone(),
                original_ip_forward: None,
                masquerade_rule_installed: false,
                forward_out_rule_installed: false,
                forward_in_rule_installed: false,
                forwarding_mode_tun: false,
                _tun_device: None,
                tun_subnet: None,
                egress_interface: None,
            });
        }

        if !cfg!(target_os = "linux") {
            anyhow::bail!("forwarding_mode=tun is currently supported only on Linux");
        }

        if !std::path::Path::new("/dev/net/tun").exists() {
            anyhow::bail!("/dev/net/tun not found. Run container with --device=/dev/net/tun");
        }

        let (tun_addr, prefix) = parse_cidr(&cfg.tun_cidr)?;
        let netmask = prefix_to_netmask(prefix);
        let subnet = cidr_network(tun_addr, prefix);
        let tun_subnet = format!("{subnet}/{prefix}");

        let mut tun_cfg = tun::Configuration::default();
        tun_cfg.tun_name(&cfg.tun_name).up();
        let tun_device = tun::create_as_async(&tun_cfg).context("failed to create TUN device")?;

        run_command(
            "ifconfig",
            &[
                &cfg.tun_name,
                &tun_addr.to_string(),
                "netmask",
                &netmask.to_string(),
                "mtu",
                &cfg.tun_mtu.to_string(),
                "up",
            ],
        )
        .with_context(|| format!("failed to configure TUN interface {}", cfg.tun_name))?;

        let egress_interface = if cfg.tun_egress_interface.trim().is_empty() {
            detect_default_egress_interface()?.ok_or_else(|| {
                anyhow!(
                    "could not detect default egress interface from /proc/net/route; set server.tun_egress_interface"
                )
            })?
        } else {
            cfg.tun_egress_interface.clone()
        };

        let original_ip_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .ok()
            .map(|value| value.trim().to_owned());

        fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
            .context("failed to enable net.ipv4.ip_forward; ensure NET_ADMIN capability")?;

        let mut runtime = Self {
            tun_name: cfg.tun_name.clone(),
            original_ip_forward,
            masquerade_rule_installed: false,
            forward_out_rule_installed: false,
            forward_in_rule_installed: false,
            forwarding_mode_tun: true,
            _tun_device: Some(tun_device),
            tun_subnet: Some(tun_subnet.clone()),
            egress_interface: Some(egress_interface.clone()),
        };

        runtime.ensure_iptables_rules(&tun_subnet, &egress_interface)?;
        Ok(runtime)
    }

    pub fn is_tun_mode(&self) -> bool {
        self.forwarding_mode_tun
    }

    pub fn take_tun_device(&mut self) -> Option<tun::AsyncDevice> {
        self._tun_device.take()
    }

    fn ensure_iptables_rules(
        &mut self,
        tun_subnet: &str,
        egress_interface: &str,
    ) -> anyhow::Result<()> {
        self.masquerade_rule_installed = ensure_rule(
            "nat",
            &[
                "POSTROUTING",
                "-s",
                tun_subnet,
                "-o",
                egress_interface,
                "-j",
                "MASQUERADE",
            ],
        )
        .context("failed to configure NAT masquerade rule")?;

        self.forward_out_rule_installed = ensure_rule(
            "filter",
            &[
                "FORWARD",
                "-i",
                &self.tun_name,
                "-o",
                egress_interface,
                "-j",
                "ACCEPT",
            ],
        )
        .context("failed to configure forward outbound rule")?;

        self.forward_in_rule_installed = ensure_rule(
            "filter",
            &[
                "FORWARD",
                "-i",
                egress_interface,
                "-o",
                &self.tun_name,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )
        .context("failed to configure forward inbound rule")?;

        Ok(())
    }
}

impl Drop for NetworkRuntime {
    fn drop(&mut self) {
        if !self.forwarding_mode_tun {
            return;
        }

        if let Some(egress) = &self.egress_interface {
            if self.forward_in_rule_installed {
                let _ = remove_rule(
                    "filter",
                    &[
                        "FORWARD",
                        "-i",
                        egress,
                        "-o",
                        &self.tun_name,
                        "-m",
                        "state",
                        "--state",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT",
                    ],
                );
            }

            if self.forward_out_rule_installed {
                let _ = remove_rule(
                    "filter",
                    &[
                        "FORWARD",
                        "-i",
                        &self.tun_name,
                        "-o",
                        egress,
                        "-j",
                        "ACCEPT",
                    ],
                );
            }
        }

        if self.masquerade_rule_installed {
            if let (Some(subnet), Some(egress)) = (&self.tun_subnet, &self.egress_interface) {
                let _ = remove_rule(
                    "nat",
                    &[
                        "POSTROUTING",
                        "-s",
                        subnet,
                        "-o",
                        egress,
                        "-j",
                        "MASQUERADE",
                    ],
                );
            }
        }

        if let Some(value) = &self.original_ip_forward {
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", format!("{}\n", value));
        }

        let _ = run_command("ifconfig", &[&self.tun_name, "down"]);
    }
}

fn run_command(command: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to launch command: {command} {}", args.join(" ")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Err(anyhow!(
        "command failed: {command} {} (status: {:?}, stdout: {stdout}, stderr: {stderr})",
        args.join(" "),
        output.status.code()
    ))
}

fn ensure_rule(table: &str, spec: &[&str]) -> anyhow::Result<bool> {
    if rule_exists(table, spec)? {
        return Ok(false);
    }

    iptables(table, "-A", spec)?;
    Ok(true)
}

fn remove_rule(table: &str, spec: &[&str]) -> anyhow::Result<()> {
    if !rule_exists(table, spec)? {
        return Ok(());
    }

    iptables(table, "-D", spec)
}

fn rule_exists(table: &str, spec: &[&str]) -> anyhow::Result<bool> {
    let mut args = vec!["-t", table, "-C"];
    args.extend_from_slice(spec);

    let output = Command::new("iptables")
        .args(&args)
        .output()
        .context("failed to execute iptables -C")?;

    Ok(output.status.success())
}

fn iptables(table: &str, action: &str, spec: &[&str]) -> anyhow::Result<()> {
    let mut args = vec!["-t", table, action];
    args.extend_from_slice(spec);
    run_command("iptables", &args)
}

fn parse_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR format: {cidr}"))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .with_context(|| format!("invalid IPv4 address in CIDR: {cidr}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .with_context(|| format!("invalid CIDR prefix length: {cidr}"))?;
    if prefix > 32 {
        anyhow::bail!("CIDR prefix must be between 0 and 32: {cidr}");
    }
    Ok((addr, prefix))
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }

    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(mask)
}

fn cidr_network(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn detect_default_egress_interface() -> anyhow::Result<Option<String>> {
    let contents = fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route while detecting egress interface")?;

    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        // Destination 00000000 is default route.
        if cols[1] == "00000000" {
            return Ok(Some(cols[0].to_owned()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{cidr_network, detect_default_egress_interface, parse_cidr, prefix_to_netmask};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_cidr_values() {
        let (addr, prefix) = parse_cidr("100.64.0.1/24").expect("cidr should parse");
        assert_eq!(addr, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn computes_netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn computes_network_address_from_cidr() {
        let network = cidr_network(Ipv4Addr::new(100, 64, 7, 9), 24);
        assert_eq!(network, Ipv4Addr::new(100, 64, 7, 0));
    }

    #[test]
    fn default_route_detection_parses_proc_file() {
        // Environment dependent; this validates code path does not panic.
        let _ = detect_default_egress_interface();
    }
}
