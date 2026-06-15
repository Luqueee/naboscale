use naboscale_crypto::Keypair;
use naboscale_tunnel::{LoopbackDevice, ManagerConfig, TunnelManager, UdpTransport};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [42u8; 32];

fn free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn make_node(
    is_initiator: bool,
    local_sender_id: u32,
    local_keypair: Keypair,
    peer_pub: [u8; 32],
    bind_port: u16,
    peer_port: u16,
) -> (TunnelManager, LoopbackDevice) {
    let (kernel, user) = LoopbackDevice::new(if is_initiator { "utun-init" } else { "utun-resp" });
    let transport = UdpTransport::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), peer_port),
    )
    .unwrap();
    let config = ManagerConfig {
        local_keypair,
        peer_pub,
        psk: PSK,
        local_sender_id,
        is_initiator,
    };
    (TunnelManager::new(Box::new(kernel), transport, config).unwrap(), user)
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
    let (alice, alice_user) = make_node(
        true,
        1,
        alice_kp.clone(),
        *bob_kp.public(),
        port_a,
        port_b,
    );
    let (bob, bob_user) = make_node(
        false,
        2,
        bob_kp.clone(),
        *alice_kp.public(),
        port_b,
        port_a,
    );

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
    alice_user.send_raw(payload.to_vec()).expect("send from alice user");

    let recv_deadline = Instant::now() + Duration::from_secs(2);
    let mut received: Option<Vec<u8>> = None;
    while Instant::now() < recv_deadline {
        if let Some(pkt) = bob_user.try_recv_raw() {
            received = Some(pkt);
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
