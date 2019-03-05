extern crate nyan;

#[test]
fn test_termianl_generate() {
    let terminal = nyan::terminal::Terminal::generate("hello".to_string());
    assert_eq!(terminal.key_bits(), 2048);
}

#[test]
fn test_termianl_sign_message() {
    let terminal = nyan::terminal::Terminal::generate("hello".to_string());
    let msg = b"\x42\xF4\x97\xE0".to_vec();
    let signature = terminal.sign(&msg);
    let device = nyan::device::Device::import_from_der("hello".to_string(), terminal.export_public_key());
    assert_eq!(device.validate(&msg, &signature), true)
}

#[test]
fn test_termianl_sign_message_incorrect_signature() {
    let terminal = nyan::terminal::Terminal::generate("hello".to_string());
    let msg = b"\x42\xF4\x97\xE0".to_vec();
    let device = nyan::device::Device::import_from_der("hello".to_string(), terminal.export_public_key());
    assert_eq!(device.validate(&msg, &b"\00\00\00\00".to_vec()), false)
}
