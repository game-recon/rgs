use std;

use errors;

use byteorder::{ByteOrder, ReadBytesExt};
use errors::Error;
use std::io::Cursor;

pub fn next_item<T, IT: Iterator<Item = T>>(iter: &mut IT) -> errors::Result<T> {
    iter.next().ok_or(errors::Error::InvalidPacketError {
        reason: "Early EOF while parsing packet".into(),
    })
}

pub fn next_items<T, IT: Iterator<Item = T>>(iter: &mut IT, n: usize) -> errors::Result<Vec<T>> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(next_item(iter)?)
    }
    Ok(v)
}

pub fn to_u16_dyn<T: ByteOrder>(slice: &[u8]) -> errors::Result<u16> {
    Ok(Cursor::new(slice)
        .read_u16::<T>()
        .map_err(|e| Error::IOError {
            reason: std::error::Error::description(&e).into(),
        })?)
}

pub fn to_u16<T: ByteOrder>(slice: &[u8; 2]) -> u16 {
    to_u16_dyn::<T>(slice).unwrap()
}

pub fn to_u32_dyn<T: ByteOrder>(slice: &[u8]) -> errors::Result<u32> {
    Ok(Cursor::new(slice)
        .read_u32::<T>()
        .map_err(|e| Error::IOError {
            reason: std::error::Error::description(&e).into(),
        })?)
}

pub fn to_u32<T: ByteOrder>(slice: &[u8; 4]) -> u32 {
    to_u32_dyn::<T>(slice).unwrap()
}

pub fn read_string<IT: Iterator<Item = u8>>(iter: &mut IT, end: u8) -> Result<String, Error> {
    let mut v = Vec::new();
    loop {
        let c = next_item(iter)?.clone();
        if c == end {
            break;
        }
        v.push(c);
    }
    Ok(String::from_utf8_lossy(&v).into_owned())
}

pub fn hex_str(v: &u8) -> String {
    match v / 16 == 0 {
        true => format!("0{:x}", v),
        false => format!("{:x}", v),
    }
}

pub trait LoggingService {
    fn debug(&self, msg: &str);
    fn info(&self, msg: &str);
}

#[derive(Clone)]
pub struct RealLogger;

impl LoggingService for RealLogger {
    fn debug(&self, msg: &str) {
        println!("DEBUG: {}", msg)
    }

    fn info(&self, msg: &str) {
        println!("INFO: {}", msg)
    }
}
