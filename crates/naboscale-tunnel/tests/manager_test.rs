use naboscale_crypto::Keypair;
use naboscale_tunnel::{LoopbackDevice, ManagerConfig, PeerConfig, TunnelManager, UdpTransport};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [42u8; 32];

fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn make_ip_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + payload.len()];
    pkt[0] = 0x45;
    let total_len = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 16;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..].copy_from_slice(payload);
    pkt
}

fn make_node(
    local_keypair: Keypair,
    peer_cfgs: Vec<PeerConfig>,
    bind_port: u16,
    local_ip: Ipv4Addr,
    is_initiator_name: &str,
) -> (TunnelManager, LoopbackDevice) {
    let (kernel, user) = LoopbackDevice::new(is_initiator_name);
    let transport =
        UdpTransport::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port)).unwrap();
    let config = ManagerConfig {
        local_keypair,
        local_ip,
    };
    (TunnelManager::new(Box::new(kernel), transport, config, peer_cfgs).unwrap(), user)
}

fn make_peer_cfg(
    peer_pub: [u8; 32],
    local_sender_id: u32,
    is_initiator: bool,
    peer_endpoint_port: u16,
    peer_ip: Ipv4Addr,
) -> PeerConfig {
    PeerConfig {
        peer_pub,
        psk: PSK,
        local_sender_id,
        is_initiator,
        peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), peer_endpoint_port),
        peer_ip,
        via_relay: None,
    }
}

fn run_until_stop(
    mut node: TunnelManager,
    ready_tx: mpsc::Sender<()>,
    stop_rx: mpsc::Receiver<()>,
) {
    let mut signaled = false;
    loop {
        match stop_rx.recv_timeout(Duration::from_millis(1)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let _ = node.step();
        if !signaled && node.is_ready() {
            let _ = ready_tx.send(());
            signaled = true;
        }
    }
}

#[test]
fn two_nodes_complete_handshake_and_tunnel_a_packet() {
    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();

    let port_a = free_port();
    let port_b = free_port();

    let ip_a: Ipv4Addr = "100.100.0.1".parse().unwrap();
    let ip_b: Ipv4Addr = "100.100.0.2".parse().unwrap();

    let bob_cfgs = vec![make_peer_cfg(
        *alice_kp.public(),
        2,
        false,
        port_a,
        ip_a,
    )];
    let alice_cfgs = vec![make_peer_cfg(
        *bob_kp.public(),
        1,
        true,
        port_b,
        ip_b,
    )];

    let (bob, bob_user) = make_node(bob_kp.clone(), bob_cfgs, port_b, ip_b, "utun-resp");
    let (alice, alice_user) = make_node(alice_kp.clone(), alice_cfgs, port_a, ip_a, "utun-init");

    let (alice_ready_tx, alice_ready_rx) = mpsc::channel();
    let (bob_ready_tx, bob_ready_rx) = mpsc::channel();
    let (stop_a_tx, stop_a_rx) = mpsc::channel();
    let (stop_b_tx, stop_b_rx) = mpsc::channel();

    let alice_thread = std::thread::spawn(move || {
        run_until_stop(alice, alice_ready_tx, stop_a_rx);
    });
    let bob_thread = std::thread::spawn(move || {
        run_until_stop(bob, bob_ready_tx, stop_b_rx);
    });

    let wait_deadline = Instant::now() + Duration::from_secs(15);
    let wait_for = |label: &str, rx: &mpsc::Receiver<()>| {
        loop {
            if Instant::now() > wait_deadline {
                panic!("{label} never became ready");
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("{label} thread disconnected");
                }
            }
        }
    };
    wait_for("alice", &alice_ready_rx);
    wait_for("bob", &bob_ready_rx);

    let payload = b"hello over naboscale tunnel";
    let pkt = make_ip_packet(ip_a, ip_b, payload);
    alice_user.send_raw(pkt).expect("send from alice user");

    let recv_deadline = Instant::now() + Duration::from_secs(2);
    let mut received: Option<Vec<u8>> = None;
    while Instant::now() < recv_deadline {
        if let Some(p) = bob_user.try_recv_raw() {
            if p.len() >= 20 {
                received = Some(p[20..].to_vec());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = stop_a_tx.send(());
    let _ = stop_b_tx.send(());
    let _ = alice_thread.join();
    let _ = bob_thread.join();

    let received = received.expect("bob never received the tunneled packet");
    assert_eq!(received, payload);
}

#[test]
fn three_nodes_complete_handshakes_and_tunnel_packets_to_each_pair() {
    let a_kp = Keypair::generate();
    let b_kp = Keypair::generate();
    let c_kp = Keypair::generate();

    let port_a = free_port();
    let port_b = free_port();
    let port_c = free_port();

    let ip_a: Ipv4Addr = "100.100.0.1".parse().unwrap();
    let ip_b: Ipv4Addr = "100.100.0.2".parse().unwrap();
    let ip_c: Ipv4Addr = "100.100.0.3".parse().unwrap();

    let a_pub = *a_kp.public();
    let b_pub = *b_kp.public();
    let c_pub = *c_kp.public();

    let cfgs_a = vec![
        make_peer_cfg(b_pub, 1, true, port_b, ip_b),
        make_peer_cfg(c_pub, 2, true, port_c, ip_c),
    ];
    let cfgs_b = vec![
        make_peer_cfg(a_pub, 1, false, port_a, ip_a),
        make_peer_cfg(c_pub, 2, true, port_c, ip_c),
    ];
    let cfgs_c = vec![
        make_peer_cfg(a_pub, 1, false, port_a, ip_a),
        make_peer_cfg(b_pub, 2, false, port_b, ip_b),
    ];

    let (mgr_a, user_a) = make_node(a_kp.clone(), cfgs_a, port_a, ip_a, "utun-a");
    let (mgr_b, user_b) = make_node(b_kp.clone(), cfgs_b, port_b, ip_b, "utun-b");
    let (mgr_c, user_c) = make_node(c_kp.clone(), cfgs_c, port_c, ip_c, "utun-c");

    let (ra_tx, ra_rx) = mpsc::channel();
    let (rb_tx, rb_rx) = mpsc::channel();
    let (rc_tx, rc_rx) = mpsc::channel();
    let (sa_tx, sa_rx) = mpsc::channel();
    let (sb_tx, sb_rx) = mpsc::channel();
    let (sc_tx, sc_rx) = mpsc::channel();

    let ta = std::thread::spawn(move || run_until_stop(mgr_a, ra_tx, sa_rx));
    let tb = std::thread::spawn(move || run_until_stop(mgr_b, rb_tx, sb_rx));
    let tc = std::thread::spawn(move || run_until_stop(mgr_c, rc_tx, sc_rx));

    let deadline = Instant::now() + Duration::from_secs(20);
    let wait_for = |label: &str, rx: &mpsc::Receiver<()>| {
        loop {
            if Instant::now() > deadline {
                panic!("{label} never became ready");
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{label} thread died"),
            }
        }
    };
    wait_for("a", &ra_rx);
    wait_for("b", &rb_rx);
    wait_for("c", &rc_rx);

    let send_and_recv = |from_user: &LoopbackDevice, to_user: &LoopbackDevice,
                          from_ip: Ipv4Addr, to_ip: Ipv4Addr, label: &str| {
        let payload = format!("ping from {label}");
        let pkt = make_ip_packet(from_ip, to_ip, payload.as_bytes());
        from_user.send_raw(pkt).expect("send from user");
        let recv_deadline = Instant::now() + Duration::from_secs(3);
        let mut received: Option<Vec<u8>> = None;
        while Instant::now() < recv_deadline {
            if let Some(p) = to_user.try_recv_raw() {
                if p.len() >= 20 {
                    received = Some(p[20..].to_vec());
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let received = received.unwrap_or_else(|| panic!("{label}: packet never arrived"));
        assert_eq!(received, payload.as_bytes(), "{label}: payload mismatch");
    };

    send_and_recv(&user_a, &user_b, ip_a, ip_b, "A→B");
    send_and_recv(&user_a, &user_c, ip_a, ip_c, "A→C");
    send_and_recv(&user_b, &user_a, ip_b, ip_a, "B→A");
    send_and_recv(&user_b, &user_c, ip_b, ip_c, "B→C");
    send_and_recv(&user_c, &user_a, ip_c, ip_a, "C→A");
    send_and_recv(&user_c, &user_b, ip_c, ip_b, "C→B");

    let _ = sa_tx.send(());
    let _ = sb_tx.send(());
    let _ = sc_tx.send(());
    let _ = ta.join();
    let _ = tb.join();
    let _ = tc.join();
}

#[test]
fn three_nodes_with_relay_a_b_traffic_goes_via_r() {
    // A and B can't reach each other directly; R is a relay with a public IP.
    // We simulate "unreachable" by simply configuring A and B with via_relay=R
    // for all transport packets. The handshake still completes directly (so
    // A and B establish a shared session key), but data is forwarded by R.
    let a_kp = Keypair::generate();
    let b_kp = Keypair::generate();
    let r_kp = Keypair::generate();

    let port_a = free_port();
    let port_b = free_port();
    let port_r = free_port();

    let ip_a: Ipv4Addr = "100.100.0.1".parse().unwrap();
    let ip_b: Ipv4Addr = "100.100.0.2".parse().unwrap();
    let ip_r: Ipv4Addr = "100.100.0.3".parse().unwrap();

    let a_pub = *a_kp.public();
    let b_pub = *b_kp.public();
    let r_pub = *r_kp.public();

    let ep_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
    let ep_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
    let ep_r = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_r);

    let cfgs_a = vec![
        PeerConfig {
            peer_pub: b_pub,
            psk: PSK,
            local_sender_id: 1,
            is_initiator: a_pub > b_pub,
            peer_endpoint: ep_b,
            peer_ip: ip_b,
            via_relay: Some(ep_r),
        },
        PeerConfig {
            peer_pub: r_pub,
            psk: PSK,
            local_sender_id: 2,
            is_initiator: a_pub > r_pub,
            peer_endpoint: ep_r,
            peer_ip: ip_r,
            via_relay: None,
        },
    ];

    let cfgs_b = vec![
        PeerConfig {
            peer_pub: a_pub,
            psk: PSK,
            local_sender_id: 1,
            is_initiator: b_pub > a_pub,
            peer_endpoint: ep_a,
            peer_ip: ip_a,
            via_relay: Some(ep_r),
        },
        PeerConfig {
            peer_pub: r_pub,
            psk: PSK,
            local_sender_id: 2,
            is_initiator: b_pub > r_pub,
            peer_endpoint: ep_r,
            peer_ip: ip_r,
            via_relay: None,
        },
    ];

    let cfgs_r = vec![
        PeerConfig {
            peer_pub: a_pub,
            psk: PSK,
            local_sender_id: 1,
            is_initiator: r_pub > a_pub,
            peer_endpoint: ep_a,
            peer_ip: ip_a,
            via_relay: None,
        },
        PeerConfig {
            peer_pub: b_pub,
            psk: PSK,
            local_sender_id: 2,
            is_initiator: r_pub > b_pub,
            peer_endpoint: ep_b,
            peer_ip: ip_b,
            via_relay: None,
        },
    ];

    let (mgr_a, user_a) = make_node(a_kp.clone(), cfgs_a, port_a, ip_a, "utun-a");
    let (mgr_b, user_b) = make_node(b_kp.clone(), cfgs_b, port_b, ip_b, "utun-b");
    let (mgr_r, _user_r) = make_node(r_kp.clone(), cfgs_r, port_r, ip_r, "utun-r");

    let (ra_tx, ra_rx) = mpsc::channel();
    let (rb_tx, rb_rx) = mpsc::channel();
    let (rr_tx, rr_rx) = mpsc::channel();
    let (sa_tx, sa_rx) = mpsc::channel();
    let (sb_tx, sb_rx) = mpsc::channel();
    let (sr_tx, sr_rx) = mpsc::channel();

    let ta = std::thread::spawn(move || run_until_stop(mgr_a, ra_tx, sa_rx));
    let tb = std::thread::spawn(move || run_until_stop(mgr_b, rb_tx, sb_rx));
    let tr = std::thread::spawn(move || run_until_stop(mgr_r, rr_tx, sr_rx));

    let deadline = Instant::now() + Duration::from_secs(20);
    let wait_for = |label: &str, rx: &mpsc::Receiver<()>| {
        loop {
            if Instant::now() > deadline {
                panic!("{label} never became ready");
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(()) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{label} thread died"),
            }
        }
    };
    wait_for("a", &ra_rx);
    wait_for("b", &rb_rx);
    wait_for("r", &rr_rx);

    let send_and_recv = |from_user: &LoopbackDevice, to_user: &LoopbackDevice,
                          from_ip: Ipv4Addr, to_ip: Ipv4Addr, label: &str| {
        let payload = format!("via relay {label}");
        let pkt = make_ip_packet(from_ip, to_ip, payload.as_bytes());
        from_user.send_raw(pkt).expect("send from user");
        let recv_deadline = Instant::now() + Duration::from_secs(3);
        let mut received: Option<Vec<u8>> = None;
        while Instant::now() < recv_deadline {
            if let Some(p) = to_user.try_recv_raw() {
                if p.len() >= 20 {
                    received = Some(p[20..].to_vec());
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let received = received.unwrap_or_else(|| panic!("{label}: packet never arrived"));
        assert_eq!(received, payload.as_bytes(), "{label}: payload mismatch");
    };

    send_and_recv(&user_a, &user_b, ip_a, ip_b, "A→B-via-R");
    send_and_recv(&user_b, &user_a, ip_b, ip_a, "B→A-via-R");

    let _ = sa_tx.send(());
    let _ = sb_tx.send(());
    let _ = sr_tx.send(());
    let _ = ta.join();
    let _ = tb.join();
    let _ = tr.join();
}
