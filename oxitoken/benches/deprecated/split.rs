use std::hint::black_box;

use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};

pub fn split(token: &[u8]) -> (&[u8], &[u8], &[u8]) {
    // a valid jwt only has 3, but we match on up to 4 so we can break early on invalid jwts
    let mut parts = token.splitn(4, |b| *b == b'.');
    let (header, claims, signature) = match (parts.next(), parts.next(), parts.next(), parts.next())
    {
        (Some(header), Some(claims), Some(sig), None) => (header, claims, sig),
        _ => todo!("invalid jwt error"),
    };
    (header, claims, signature)
}

fn bench_split(c: &mut Criterion) {
    // 573 bytes; real SPIFFE JWT-SVID
    let spiffe = b"eyJhbGciOiJSUzI1NiIsImtpZCI6IkRReWk2eEFmVVRPWmhJV2R5VWtKZTBFMUJmM1VXV05QIiwidHlwIjoiSldUIn0.eyJhdWQiOlsianNvbndlYnRva2VudGVzdCJdLCJleHAiOjE3NTk4MjYyMTcsImlhdCI6MTc1OTgyNTkxNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvdGVzdHNlcnZpY2UifQ.1qr1zmMM1hmF-sDZupGc7sT2zGQxl1hFfaUKFWz3UGUeJfUweZfFymGR4jIOJb9ywXmfaafGQbNypaHILPWpeXT8RB7GZ7APu09ZPFvLiKBqagCVWgwhXc30giYPfTq5iNct1ejdYgB1wLxtnrsDRoD_k3EMkB58pDz4H5ZFXc_3xB9TLGw2UdaZ7AloV1yFV6OC5PdleSKchb9E_WaBlbZWLjQNSLhN-YhCRLJ4K59lmL_Z2rnR2812kan8xicyxJAzZ6k0y6K8tpKxUhT--THz2ikUk_olOwDIMfjYe9xmAk-PVvIGwHUVR6fMYv74vhdpwVJACkI2U7HVUhRFkg";
    c.bench_function("bench_std_split_spiffe", |b| {
        b.iter(|| black_box(split(black_box(spiffe))));
    });

    c.bench_function("bench_memchr_split_spiffe", |b| {
        b.iter(|| {
            black_box(oxitoken::decoding::SplitJwt::try_from(black_box(&spiffe[..])).unwrap())
        })
    });
}

fn bench_split_16k(c: &mut Criterion) {
    let adversarial_16k = include_bytes!("adversarial_16k.jwt");
    c.bench_function("bench_std_split_adversarial_16k", |b| {
        b.iter(|| split(black_box(adversarial_16k)));
    });
    c.bench_function("bench_memchr_split_adversarial_16k", |b| {
        b.iter(|| {
            black_box(
                oxitoken::decoding::SplitJwt::try_from(black_box(&adversarial_16k[..])).unwrap(),
            )
        })
    });
}

fn bench_split_huge(c: &mut Criterion) {
    let adversarial_huge = include_bytes!("adversarial_huge.jwt");
    c.bench_function("bench_std_split_adversarial_huge", |b| {
        b.iter(|| split(black_box(adversarial_huge)));
    });
    c.bench_function("bench_memchr_split_adversarial_huge", |b| {
        b.iter(|| {
            black_box(
                oxitoken::decoding::SplitJwt::try_from(black_box(&adversarial_huge[..])).unwrap(),
            )
        })
    });
}

criterion_group!(benches, bench_split, bench_split_16k, bench_split_huge);
criterion_main!(benches);
