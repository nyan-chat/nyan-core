pub mod consts;
pub mod device;
pub mod terminal;

pub extern "C" fn version() -> &'static str {
   consts::Consts::VERSION
}
