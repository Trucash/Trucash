use std::{error::Error, fmt};

#[derive(Debug)]
pub struct SuperError {
	pub description: String,
	pub place: String
}

impl Error for SuperError {
	fn description(&self) -> &str {
		return &self.description;
	}

	fn cause(&self) -> Option<&Error> {
		return Some(self);
	}
}

impl fmt::Display for SuperError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		return write!(f, "Error");
	}
}