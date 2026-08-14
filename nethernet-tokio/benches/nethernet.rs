use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nethernet_tokio::protocol::packet::discovery::{
    MessagePacket, RequestPacket, ResponsePacket, marshal, unmarshal,
};
use nethernet_tokio::protocol::{Message, MessageSegment};
use std::hint::black_box;
use std::time::Duration;

const SENDER_ID: u64 = 0x1234567890abcdef;

fn bench_message_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encode");

    for size in [512, 1024, 4096] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let payload = vec![0u8; size];

            let segment = MessageSegment {
                remaining_segments: 0,
                data: Bytes::from(payload),
            };

            b.iter(|| {
                let encoded = segment.encode();
                black_box(encoded);
            });
        });
    }

    group.finish();
}

fn bench_message_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_decode");

    for size in [512, 1024, 4096] {
        let payload = vec![0u8; size];

        let segment = MessageSegment {
            remaining_segments: 0,
            data: Bytes::from(payload),
        };

        let encoded = segment.encode();

        group.throughput(Throughput::Bytes(encoded.len() as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &encoded, |b, encoded| {
            b.iter_batched(
                || encoded.clone(),
                |data| {
                    let decoded = MessageSegment::decode(black_box(data)).unwrap();
                    black_box(decoded);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_message_segmentation(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_segmentation");

    for size in [1024, 8192, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let payload = Bytes::from(vec![0u8; size]);

            b.iter_batched(
                || payload.clone(),
                |data| {
                    let segments = Message::split_into_segments(black_box(data)).unwrap();
                    black_box(segments);
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_discovery_marshal(c: &mut Criterion) {
    let mut group = c.benchmark_group("discovery_marshal");

    // Request packet
    group.bench_function("request_packet", |b| {
        let packet = RequestPacket;

        b.iter(|| {
            let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();
            black_box(marshaled);
        });
    });

    // Response packets
    for size in [128, 512, 2048] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("response_packet", size),
            &size,
            |b, &size| {
                let packet = ResponsePacket::new(vec![0u8; size]);

                b.iter(|| {
                    let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();

                    black_box(marshaled);
                });
            },
        );
    }

    // Message packets
    for size in [256, 1024] {
        let data = "x".repeat(size);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("message_packet", size),
            &data,
            |b, data| {
                let packet = MessagePacket::new(0x9876543210fedcba, data.clone());

                b.iter(|| {
                    let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();

                    black_box(marshaled);
                });
            },
        );
    }

    group.finish();
}

fn bench_discovery_unmarshal(c: &mut Criterion) {
    let mut group = c.benchmark_group("discovery_unmarshal");

    // Request packet
    group.bench_function("request_packet", |b| {
        let packet = RequestPacket;

        let marshaled = marshal(&packet, SENDER_ID).unwrap();

        b.iter(|| {
            let (pkt, _) = unmarshal(black_box(&marshaled)).unwrap();
            black_box(pkt);
        });
    });

    // Response packets
    for size in [128, 512, 2048] {
        let packet = ResponsePacket::new(vec![0u8; size]);

        let marshaled = marshal(&packet, SENDER_ID).unwrap();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("response_packet", size),
            &marshaled,
            |b, marshaled| {
                b.iter_batched(
                    || marshaled.clone(),
                    |data| {
                        let (pkt, _) = unmarshal(black_box(&data)).unwrap();
                        black_box(pkt);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // Message packets
    for size in [256, 1024] {
        let data = "x".repeat(size);

        let packet = MessagePacket::new(0x9876543210fedcba, data);

        let marshaled = marshal(&packet, SENDER_ID).unwrap();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("message_packet", size),
            &marshaled,
            |b, marshaled| {
                b.iter_batched(
                    || marshaled.clone(),
                    |data| {
                        let (pkt, _) = unmarshal(black_box(&data)).unwrap();
                        black_box(pkt);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_discovery_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("discovery_roundtrip");

    // Request
    group.bench_function("request_packet", |b| {
        let packet = RequestPacket;

        b.iter(|| {
            let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();

            let (pkt, _) = unmarshal(&marshaled).unwrap();

            black_box(pkt);
        });
    });

    // Response
    for size in [128, 512, 2048] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("response_packet", size),
            &size,
            |b, &size| {
                let packet = ResponsePacket::new(vec![0u8; size]);

                b.iter(|| {
                    let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();

                    let (pkt, _) = unmarshal(&marshaled).unwrap();

                    black_box(pkt);
                });
            },
        );
    }

    // Message
    for size in [256, 1024] {
        let data = "x".repeat(size);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("message_packet", size),
            &data,
            |b, data| {
                let packet = MessagePacket::new(0x9876543210fedcba, data.clone());

                b.iter(|| {
                    let marshaled = marshal(black_box(&packet), black_box(SENDER_ID)).unwrap();

                    let (pkt, _) = unmarshal(&marshaled).unwrap();

                    black_box(pkt);
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_message_encode,
        bench_message_decode,
        bench_message_segmentation,
        bench_discovery_marshal,
        bench_discovery_unmarshal,
        bench_discovery_roundtrip
}

criterion_main!(benches);
