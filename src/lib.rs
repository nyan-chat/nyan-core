pub mod consts;
pub mod device;
pub mod group;
pub mod operator;
pub mod terminal;
pub mod user;

pub extern "C" fn version() -> &'static str {
   consts::Consts::VERSION
}
