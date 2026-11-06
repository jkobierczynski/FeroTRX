use super::*;

/// A folder with a plan's profiles: clients.toml and server.toml play
/// examples/http.pcap, which sits one folder up (../captures).
fn lab(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferotrx-fleet-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("plans")).unwrap();
    std::fs::create_dir_all(d.join("captures")).unwrap();
    let pcap = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/http.pcap");
    std::fs::copy(pcap, d.join("captures/http.pcap")).unwrap();
    std::fs::write(
        d.join("plans/clients.toml"),
        "pcap = \"../captures/http.pcap\"\nconnect = \"${server}:80\"\ncps = 10\n\
         [client]\nip = \"${client_ip}/24\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("plans/server.toml"),
        "pcap = \"../captures/http.pcap\"\n[server]\nip = \"${server}/24\"\n",
    )
    .unwrap();
    std::fs::write(
        d.join("plans/plain.toml"),
        "pcap = \"../captures/http.pcap\"\n[server]\nip = \"10.9.0.80/24\"\n",
    )
    .unwrap();
    d
}

const PLAN: &str = r#"
format = 1
name = "Two Sites"
start_delay = "2s"
duration = "10s"

[vars]
server = "10.9.0.80"

[[agent]]
name = "east"
address = "10.0.0.11:4510"
token_env = "FEROTRX_TOKEN"
iface = "c0"
vars = { client_ip = "10.9.0.100" }

[[agent]]
name = "west"
address = "10.0.0.12:4510"
ca = "lab-ca.pem"
vars = { client_ip = "10.9.0.101" }

[[agent]]
name = "srv"
address = "10.0.0.13:4510"
iface = "s0"

[[run]]
name = "web server"
agent = "srv"
tcp = "server.toml"

[[run]]
name = "web clients"
agents = ["east", "west"]
tcp = "clients.toml"
iface = "d0"
cps = 25
delay = "500ms"
require = ["completed_pct == 100"]
require_each = ["completed > 0"]

[[run]]
name = "probe"
agent = "east"
rx_agent = "srv"
rx = "s0"
latency = true
rate = "1kpps"
[run.traffic]
[[run.traffic.stream]]
name = "ping"
packet = "eth/ipv4(src=${client_ip},dst=${server})/udp"

[require]
tcp = ["completed > 0"]
"#;

#[test]
fn reads_a_plan() {
    let d = lab("reads");
    let plan = FleetPlan::from_toml(PLAN, &d.join("plans"), &[]).unwrap();
    assert_eq!(plan.name, "Two Sites");
    assert_eq!(plan.deploy_dir, Path::new("fleet/two-sites"));
    assert_eq!(plan.start_delay, Duration::from_secs(2));
    assert_eq!(plan.agents.len(), 3);
    let west = plan.agent("west").unwrap();
    assert_eq!(
        west.tls.as_ref().unwrap().ca.as_deref(),
        Some(d.join("plans/lab-ca.pem").as_path())
    );
    assert_eq!(
        plan.agent("east").unwrap().token_env.as_deref(),
        Some("FEROTRX_TOKEN")
    );

    let clients = &plan.runs[1];
    assert_eq!(clients.kind, CheckKind::Tcp);
    assert_eq!(clients.slug(), "web-clients");
    assert_eq!(clients.delay, Duration::from_millis(500));
    assert_eq!(clients.settings.cps, Some(25.0));
    assert_eq!(clients.settings.duration, Some(Duration::from_secs(10)));
    assert_eq!(clients.require.len(), 1);
    assert_eq!(clients.require_each.len(), 1);
    // Each agent's own variables in its copy of the profile.
    let [east, west] = &clients.instances[..] else {
        panic!("two instances")
    };
    assert!(east.text.contains("10.9.0.100/24"), "{}", east.text);
    assert!(west.text.contains("10.9.0.101/24"));
    assert!(east.text.contains("10.9.0.80:80"));
    assert_eq!(east.iface.as_deref(), Some("d0"), "the run's iface wins");
    assert_eq!(east.files.len(), 1, "the pcap goes along");
    // The server's run takes its agent's interface.
    assert_eq!(plan.runs[0].instances[0].iface.as_deref(), Some("s0"));

    let probe = &plan.runs[2];
    assert_eq!(probe.kind, CheckKind::Traffic);
    assert_eq!(probe.source, "inline");
    assert_eq!(probe.instances[0].file_name, "probe.toml");
    assert!(probe.instances[0].text.contains("10.9.0.100"));
    assert_eq!(probe.settings.rx_agent.as_deref(), Some("srv"));
    assert_eq!(plan.require.len(), 1);
    assert!(plan
        .summary()
        .iter()
        .any(|l| l.contains("web clients: tcp clients.toml on east, west")));
}

#[test]
fn files_keep_their_places() {
    let d = lab("layout");
    let plan = FleetPlan::from_toml(PLAN, &d.join("plans"), &[]).unwrap();
    let run = &plan.runs[1];
    let dep = run.instances[0].deployment(&plan.deploy_dir.join(run.slug()));
    // The profile is in plans/, its pcap in ../captures: both go under the
    // run's folder, the same distance apart.
    let base = Path::new("fleet/two-sites/web-clients");
    assert_eq!(dep.base_dir, base.join("plans"));
    assert_eq!(dep.profile, base.join("plans/clients.toml"));
    assert_eq!(dep.files.len(), 1);
    assert_eq!(dep.files[0].1, base.join("captures/http.pcap"));
    assert!(dep.files[0].0.ends_with("captures/http.pcap"));
    // An inline profile without files goes in the run's folder.
    let probe = &plan.runs[2];
    let dep = probe.instances[0].deployment(Path::new("fleet/x/probe"));
    assert_eq!(dep.profile, Path::new("fleet/x/probe/probe.toml"));
    assert!(dep.files.is_empty());
}

#[test]
fn set_overrides_vars() {
    let d = lab("set");
    let plan = FleetPlan::from_toml(
        PLAN,
        &d.join("plans"),
        &[("server".into(), "10.9.0.99".into())],
    )
    .unwrap();
    assert!(plan.runs[0].instances[0].text.contains("10.9.0.99/24"));
}

#[test]
fn mistakes_are_named() {
    let d = lab("mistakes");
    let dir = d.join("plans");
    let err = |text: &str| {
        FleetPlan::from_toml(text, &dir, &[])
            .unwrap_err()
            .to_string()
    };
    let agent = "[[agent]]\nname = \"a\"\naddress = \"h:1\"\n";
    let tcp = "tcp = \"plain.toml\"\n";
    assert!(err("").contains("[[agent]]"));
    assert!(err(agent).contains("[[run]]"));
    assert!(err(&format!("{agent}[[run]]\nagent = \"b\"\n{tcp}")).contains("no agent called 'b'"));
    assert!(err(&format!("{agent}[[run]]\n{tcp}")).contains("agent or agents"));
    assert!(err(&format!("{agent}[[run]]\nagent = \"a\"\n")).contains("tcp, udp or traffic"));
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\n{tcp}rate = \"1kpps\"\n"
    ))
    .contains("rate is for"));
    assert!(
        err(&format!("{agent}[[run]]\nagent = \"a\"\n{tcp}rx = \"x\"\n"))
            .contains("rx is for traffic")
    );
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\n{tcp}require = [\"nope > 1\"]\n"
    ))
    .contains("no metric 'nope'"));
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\ntcp = \"clients.toml\"\n"
    ))
    .contains("is not set; add it to [vars]"));
    assert!(err("[[agent]]\naddress = \"nohost\"\n").contains("host:port"));
    assert!(err(&format!("{agent}{agent}")).contains("two agents"));
    assert!(err(&format!(
        "{agent}[[run]]\nname = \"A b\"\nagent = \"a\"\n{tcp}[[run]]\nname = \"a-b\"\nagent = \"a\"\n{tcp}"
    ))
    .contains("share a folder"));
    assert!(err(&format!(
        "deploy_dir = \"../x\"\n{agent}[[run]]\nagent = \"a\"\n{tcp}"
    ))
    .contains("deploy_dir"));
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\n[run.traffic]\n[[run.traffic.stream]]\npacket = \"eth/ipv4/udp\"\n"
    ))
    .contains("needs iface"));
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\nrx_agent = \"a\"\n[run.traffic]\n"
    ))
    .contains("rx_agent needs rx"));
    assert!(err(&format!(
        "{agent}[[run]]\nagent = \"a\"\n{tcp}\n[require]\nudp = [\"cps > 1\"]\n"
    ))
    .contains("no metric 'cps'"));
    assert!(err(&format!("format = 9\n{agent}[[run]]\nagent = \"a\"\n{tcp}")).contains("format"));
}

#[test]
fn slugs() {
    assert_eq!(slug("Web Clients #2"), "web-clients-2");
    assert_eq!(slug("--"), "run");
    assert_eq!(slug("a__b"), "a-b");
}

#[test]
fn known_vars_only() {
    let vars: BTreeMap<String, String> = [("a".to_string(), "1".to_string())].into();
    assert_eq!(substitute_known("${a}-${b}-${ a }", &vars), "1-${b}-1");
    assert_eq!(substitute_known("x ${a", &vars), "x ${a");
}
