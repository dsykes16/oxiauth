use memchr::memchr_iter;

use crate::error::SplitError;

#[derive(Debug)]
pub struct SplitJwt<'a> {
    data: &'a [u8],
    hlen: usize,
    plen: usize,
}

impl<'a> TryFrom<&'a [u8]> for SplitJwt<'a> {
    type Error = SplitError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut it = memchr_iter(b'.', value);
        let hlen = it.next().ok_or(SplitError::Undersized)?;
        let plen = it.next().ok_or(SplitError::Undersized)?;
        it.next().map_or(Ok(()), |_| Err(SplitError::Oversized))?;
        Ok(SplitJwt {
            data: value,
            hlen,
            plen,
        })
    }
}

impl SplitJwt<'_> {
    #[must_use]
    pub fn b64_header(&self) -> &[u8] {
        &self.data[0..self.hlen]
    }

    #[must_use]
    pub fn b64_payload(&self) -> &[u8] {
        &self.data[self.hlen + 1..self.plen]
    }

    #[must_use]
    pub fn b64_message(&self) -> &[u8] {
        &self.data[0..self.plen]
    }

    #[must_use]
    pub fn b64_signature(&self) -> &[u8] {
        &self.data[self.plen + 1..]
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        SplitError,
        SplitJwt,
    };

    #[test]
    fn split_given_two_sections_returns_error() {
        let token = b"a.b";
        let err = SplitJwt::try_from(&token[..]).unwrap_err();
        assert_eq!(err, SplitError::Undersized);
    }

    #[test]
    fn split_given_three_sections_returns_ok() {
        let token = b"a.b.";
        SplitJwt::try_from(&token[..]).unwrap();
    }

    #[test]
    fn split_given_four_sections_returns_error() {
        let token = b"a.b.c.";
        let err = SplitJwt::try_from(&token[..]).unwrap_err();
        assert_eq!(err, SplitError::Oversized);
    }

    #[test]
    fn split_given_standard_input_returns_expected() {
        let token = b"header.claims.sig";
        let parts = SplitJwt::try_from(&token[..]).unwrap();
        assert_eq!(parts.b64_header(), b"header");
        assert_eq!(parts.b64_payload(), b"claims");
        assert_eq!(parts.b64_message(), b"header.claims");
        assert_eq!(parts.b64_signature(), b"sig");
    }

    #[test]
    fn split_given_three_empty_ok() {
        let token = b"..";
        let parts = SplitJwt::try_from(&token[..]).unwrap();
        assert_eq!(parts.b64_header(), b"");
        assert_eq!(parts.b64_payload(), b"");
        assert_eq!(parts.b64_signature(), b"");
    }

    #[test]
    fn split_given_two_empty_error() {
        let token = b".";
        let err = SplitJwt::try_from(&token[..]).unwrap_err();
        assert_eq!(err, SplitError::Undersized);
    }

    #[test]
    fn split_given_empty_slice_error() {
        let token = b"";
        let err = SplitJwt::try_from(&token[..]).unwrap_err();
        assert_eq!(err, SplitError::Undersized);
    }
}
