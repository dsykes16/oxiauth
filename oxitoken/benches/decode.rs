#![allow(clippy::unwrap_used)]
use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use oxitoken::{
    Algorithm,
    dangerous::decode,
    decoding::{
        DecodedJwt,
        SplitJwt,
    },
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    alg: Algorithm,
    kid: String,
    typ: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BHeader<'a> {
    alg: Algorithm,
    kid: &'a str,
    typ: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BClaims<'a> {
    aud: Vec<&'a str>,
    exp: i64,
    iat: i64,
    sub: &'a str,
}

// most optimized deser possible for comparison with owned-value impl in public API
fn decode_borrow_deser(token: &[u8]) {
    let decoded = DecodedJwt::try_from(&SplitJwt::try_from(token).unwrap()).unwrap();
    let header: BHeader<'_> = serde_json::from_slice(decoded.decoded_header()).unwrap();
    let claims: BClaims<'_> = serde_json::from_slice(decoded.decoded_claims()).unwrap();
    black_box(header);
    black_box(claims);
}

fn decode_spiffe_header(c: &mut Criterion) {
    let token = b"eyJhbGciOiJSUzI1NiIsImtpZCI6IkRReWk2eEFmVVRPWmhJV2R5VWtKZTBFMUJmM1VXV05QIiwidHlwIjoiSldUIn0.eyJhdWQiOlsianNvbndlYnRva2VudGVzdCJdLCJleHAiOjE3NTk4MjYyMTcsImlhdCI6MTc1OTgyNTkxNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvdGVzdHNlcnZpY2UifQ.1qr1zmMM1hmF-sDZupGc7sT2zGQxl1hFfaUKFWz3UGUeJfUweZfFymGR4jIOJb9ywXmfaafGQbNypaHILPWpeXT8RB7GZ7APu09ZPFvLiKBqagCVWgwhXc30giYPfTq5iNct1ejdYgB1wLxtnrsDRoD_k3EMkB58pDz4H5ZFXc_3xB9TLGw2UdaZ7AloV1yFV6OC5PdleSKchb9E_WaBlbZWLjQNSLhN-YhCRLJ4K59lmL_Z2rnR2812kan8xicyxJAzZ6k0y6K8tpKxUhT--THz2ikUk_olOwDIMfjYe9xmAk-PVvIGwHUVR6fMYv74vhdpwVJACkI2U7HVUhRFkg";

    let mut group = c.benchmark_group("Decode_NoValidation");
    group.throughput(criterion::Throughput::Bytes(token.len() as u64));
    group.bench_function("decode_spiffe_maxopt", |b| {
        b.iter(|| {
            decode_borrow_deser(black_box(token));
        });
    });

    group.bench_function("decode_spiffe_owned", |b| {
        b.iter(|| {
            black_box(decode::<Header, Claims>(black_box(token)).unwrap());
        });
    });

    group.bench_function("jsonwebtoken_decode_spiffe", |b| {
        b.iter(|| {
            black_box(jsonwebtoken::dangerous::insecure_decode::<Claims>(token).unwrap());
        });
    });
    group.finish();
}

criterion_group!(benches, decode_spiffe_header);
criterion_main!(benches);
