use failure;
use futures;
use std;
use tokio_timer;

use failure::Fail;

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

impl From<futures::channel::mpsc::SendError> for Error {
    fn from(v: futures::channel::mpsc::SendError) -> Self {
        Error::PipeError {
            reason: std::error::Error::description(&v).into(),
        }
    }
}

impl<T: std::fmt::Display + 'static> From<tokio_timer::DeadlineError<T>> for Error {
    fn from(v: tokio_timer::DeadlineError<T>) -> Self {
        Error::TimeoutError {
            reason: v.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
