use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64_engine;
use base64_simd::URL_SAFE_NO_PAD as b64;
use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use std::hint::black_box;

fn decode(data: &[u8]) -> Vec<u8> {
    base64_engine.decode(data).unwrap()
}

fn decode_simd(data: &[u8]) -> Vec<u8> {
    b64.decode_to_vec(data).unwrap()
}

fn bench_spiffe(c: &mut Criterion) {
    // 573 bytes; real SPIFFE JWT-SVID
    let header = b"eyJhbGciOiJSUzI1NiIsImtpZCI6IkRReWk2eEFmVVRPWmhJV2R5VWtKZTBFMUJmM1VXV05QIiwidHlwIjoiSldUIn0";
    let claims = b"eyJhdWQiOlsianNvbndlYnRva2VudGVzdCJdLCJleHAiOjE3NTk4MjYyMTcsImlhdCI6MTc1OTgyNTkxNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvdGVzdHNlcnZpY2UifQ";
    let signature = b"1qr1zmMM1hmF-sDZupGc7sT2zGQxl1hFfaUKFWz3UGUeJfUweZfFymGR4jIOJb9ywXmfaafGQbNypaHILPWpeXT8RB7GZ7APu09ZPFvLiKBqagCVWgwhXc30giYPfTq5iNct1ejdYgB1wLxtnrsDRoD_k3EMkB58pDz4H5ZFXc_3xB9TLGw2UdaZ7AloV1yFV6OC5PdleSKchb9E_WaBlbZWLjQNSLhN-YhCRLJ4K59lmL_Z2rnR2812kan8xicyxJAzZ6k0y6K8tpKxUhT--THz2ikUk_olOwDIMfjYe9xmAk-PVvIGwHUVR6fMYv74vhdpwVJACkI2U7HVUhRFkg";

    c.bench_function("base64_spiffe", |b| {
        b.iter(|| {
            black_box(decode(black_box(header)));
            black_box(decode(black_box(claims)));
            black_box(decode(black_box(signature)));
        });
    });

    c.bench_function("base64_simd_spiffe", |b| {
        b.iter(|| {
            black_box(decode_simd(black_box(header)));
            black_box(decode_simd(black_box(claims)));
            black_box(decode_simd(black_box(signature)));
        });
    });
}

// TODO: generate new 16k jwt w/ valid claims
//fn bench_16k(c: &mut Criterion) {
//    let adversarial_16k = include_bytes!("adversarial_16k.jwt");
//    let parts = SplitJwt::try_from(&adversarial_16k[..]).unwrap();
//
//    c.bench_function("base64_16k_header", |b| {
//        b.iter(|| black_box(DecodedJwt::try_from(&parts).unwrap()));
//    });
//}

//fn bench_huge(c: &mut Criterion) {
//    let adversarial_huge = include_bytes!("adversarial_huge.jwt");
//    let parts = SplitJwt::try_from(&adversarial_huge[..]).unwrap();
//
//    c.bench_function("base64_huge_header", |b| {
//        b.iter(|| black_box(decode(black_box(parts.b64_header()))));
//    });
//}

criterion_group!(benches, bench_spiffe);
criterion_main!(benches);
