use naboscale_tunnel::{Device, TunDevice};

#[test]
#[ignore = "requires root/CAP_NET_ADMIN to create a utun device"]
fn can_create_tun_device() {
    let device = TunDevice::create("utun99").expect("create TUN device");
    assert!(!device.name().is_empty());
}
