pub mod device;
pub mod terminal;

pub extern "C" fn version() -> &'static str {
    "0.1.0"
}
