use futures;
use nom;
use std;
use std::io;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "null error: {}", reason)]
    NullError { reason: String },
    #[fail(display = "data parse error: {}", reason)]
    DataParseError { reason: String },
    #[fail(display = "network error: {}", reason)]
    NetworkError { reason: String },
    #[fail(display = "invalid packet: {}", reason)]
    InvalidPacketError { reason: String },
    #[fail(display = "IO error: {}", reason)]
    IOError { reason: String },
    #[fail(display = "pipe error: {}", reason)]
    PipeError { reason: String },
    #[fail(display = "operation timed out: {}", reason)]
    TimeoutError { reason: String },
}

impl<'a> From<nom::Err<&'a [u8]>> for Error {
    fn from(v: nom::Err<&'a [u8]>) -> Error {
        Error::DataParseError {
            reason: v.to_string(),
        }
    }
}

impl<T: 'static> From<futures::sync::mpsc::SendError<T>> for Error {
    fn from(v: futures::sync::mpsc::SendError<T>) -> Self {
        Error::PipeError {
            reason: std::error::Error::description(&v).into(),
        }
    }
}

impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Error::IOError {
            reason: v.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
