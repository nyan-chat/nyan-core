pub mod chat;
pub mod consts;
pub mod device;
pub mod errors;
pub mod group;
pub mod terminal;
pub mod user;

pub extern "C" fn version() -> &'static str {
   consts::Consts::VERSION
}

pub extern "C" fn openssl_version() -> &'static str {
   openssl::version::version()
}
