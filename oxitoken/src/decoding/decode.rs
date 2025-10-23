use base64_simd::URL_SAFE_NO_PAD as b64;

use crate::{
    JwtError,
    decoding::SplitJwt,
};

#[derive(Debug)]
pub struct DecodedJwtMessage {
    data: Vec<u8>,
    hlen: usize,
}

impl TryFrom<&SplitJwt<'_>> for DecodedJwtMessage {
    type Error = JwtError;
    fn try_from(parts: &SplitJwt) -> Result<Self, Self::Error> {
        let mut data = Vec::with_capacity(
            b64.estimated_decoded_length(parts.b64_header().len())
                + b64.estimated_decoded_length(parts.b64_payload().len()),
        );
        b64.decode_append(parts.b64_header(), &mut data)
            .map_err(|_| JwtError::InvalidEncoding)?;
        let hlen = data.len();
        b64.decode_append(parts.b64_payload(), &mut data)
            .map_err(|_| JwtError::InvalidEncoding)?;
        Ok(Self { data, hlen })
    }
}

impl DecodedJwtMessage {
    pub(crate) fn decoded_header(&self) -> &[u8] {
        &self.data[0..self.hlen]
    }

    pub(crate) fn decoded_claims(&self) -> &[u8] {
        &self.data[self.hlen..]
    }
}

#[derive(Debug)]
pub struct DecodedJwt {
    data: Vec<u8>,
    hlen: usize,
    mlen: usize,
}

impl TryFrom<&SplitJwt<'_>> for DecodedJwt {
    type Error = JwtError;
    fn try_from(parts: &SplitJwt) -> Result<Self, Self::Error> {
        let mut data = Vec::with_capacity(
            b64.estimated_decoded_length(parts.b64_header().len())
                + b64.estimated_decoded_length(parts.b64_payload().len())
                + b64.estimated_decoded_length(parts.b64_signature().len()),
        );
        b64.decode_append(parts.b64_header(), &mut data)
            .map_err(|_| JwtError::InvalidEncoding)?;
        let hlen = data.len();
        b64.decode_append(parts.b64_payload(), &mut data)
            .map_err(|_| JwtError::InvalidEncoding)?;
        let mlen = data.len();
        b64.decode_append(parts.b64_signature(), &mut data)
            .map_err(|_| JwtError::InvalidEncoding)?;
        Ok(Self { data, hlen, mlen })
    }
}

impl DecodedJwt {
    /// Returns decoded (not deserialized) header
    #[must_use]
    pub fn decoded_header(&self) -> &[u8] {
        &self.data[0..self.hlen]
    }

    /// Returns decoded (not deserialized) header
    #[must_use]
    pub fn decoded_claims(&self) -> &[u8] {
        &self.data[self.hlen..self.mlen]
    }

    /// Returns decoded signature
    #[must_use]
    pub fn decoded_signature(&self) -> &[u8] {
        &self.data[self.mlen..]
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        DecodedJwt,
        DecodedJwtMessage,
        JwtError,
        SplitJwt,
    };

    #[test]
    fn try_decode_valid_jwt_ok() {
        let jwt = b"e30.e30.U0lH";
        let parts: SplitJwt = jwt[..].try_into().unwrap();
        let decoded: DecodedJwt = (&parts).try_into().unwrap();
        assert_eq!(decoded.decoded_header(), b"{}");
        assert_eq!(decoded.decoded_claims(), b"{}");
        assert_eq!(decoded.decoded_signature(), b"SIG");

        let decoded: DecodedJwtMessage = (&parts).try_into().unwrap();
        assert_eq!(decoded.decoded_header(), b"{}");
        assert_eq!(decoded.decoded_claims(), b"{}");
    }

    #[test]
    fn invalid_header_base64() {
        let jwt = b"=.=.=";
        let parts: SplitJwt = jwt[..].try_into().unwrap();
        let err = DecodedJwt::try_from(&parts).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        let err = DecodedJwtMessage::try_from(&parts).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);
    }

    #[test]
    fn invalid_claims_base64() {
        let jwt = b"e30.=.=";
        let parts: SplitJwt = jwt[..].try_into().unwrap();
        let err = DecodedJwt::try_from(&parts).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        let err = DecodedJwtMessage::try_from(&parts).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);
    }

    #[test]
    fn invalid_signature_base64() {
        let jwt = b"e30.e30.=";
        let parts: SplitJwt = jwt[..].try_into().unwrap();
        let err = DecodedJwt::try_from(&parts).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        DecodedJwtMessage::try_from(&parts).unwrap();
    }
}
