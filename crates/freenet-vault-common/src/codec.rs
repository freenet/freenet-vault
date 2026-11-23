//! Byte reader and writer for the v1 formats.
//!
//! Every integer is big-endian. A decoder must consume its input exactly:
//! trailing bytes, a short read or a length field that does not fit are all
//! [`Malformed`] (handover protocol 11: "Every length must match exactly").

/// The input is not a well-formed v1 frame, entry or record.
///
/// The string names the first check that failed. It is for logs and tests,
/// never for the wire: every malformed input gets the same answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl core::fmt::Display for Malformed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "malformed: {}", self.0)
    }
}

impl std::error::Error for Malformed {}

pub type Result<T> = core::result::Result<T, Malformed>;

/// Reads a byte slice front to back.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Malformed(what));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, what)?);
        Ok(out)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array(what)?))
    }

    pub fn u64(&mut self, what: &'static str) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array(what)?))
    }

    /// A flag byte that must be 0 or 1.
    pub fn bool(&mut self, what: &'static str) -> Result<bool> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Malformed(what)),
        }
    }

    /// `ext_len 2 ; ext`. Any extension whose length fits is accepted.
    pub fn ext(&mut self) -> Result<Vec<u8>> {
        let len = self.u16("ext_len")? as usize;
        Ok(self.take(len, "ext")?.to_vec())
    }

    /// Fails unless every byte was consumed.
    pub fn finish(self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Malformed("trailing bytes"))
        }
    }
}

/// Appends v1 fields to a buffer.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// `ext_len 2 ; ext`. Panics if `ext` exceeds 65,535 bytes, which no
    /// encoder in this crate produces.
    pub fn ext(&mut self, ext: &[u8]) -> &mut Self {
        let len = u16::try_from(ext.len()).expect("extension longer than 65535 bytes");
        self.u16(len).bytes(ext)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
