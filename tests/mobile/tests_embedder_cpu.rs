// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — embedder CPU-path
// correctness on mobile.
//
// candle-core with no GPU features compiles down to plain CPU
// matmul; the risk on mobile is the `gemm` crate's SIMD-dispatch
// path picking a codepath that's wrong for ARM NEON or that
// silently falls back to scalar (correct but ~50x slower than the
// host benchmark). These tests are deliberately tiny — we don't run
// the full MiniLM model in CI (300MB+ weight download); we run the
// shape-only smoke that proves the candle stack initialises.

#[test]
fn embedder_shape_smoke_cpu_tensor() {
    use candle_core::{Device, Tensor};
    // Allocate a 1x4 tensor on CPU. If candle can't initialise its
    // CPU backend, this panics on alloc — that's the smoke we want.
    let device = Device::Cpu;
    let t = Tensor::new(&[1.0_f32, 2.0, 3.0, 4.0], &device)
        .expect("candle CPU tensor alloc must succeed on mobile");
    let shape = t.shape().dims().to_vec();
    assert_eq!(shape, vec![4_usize]);
    // Roundtrip back to a host Vec to verify no NaN/garbage from the
    // ARM NEON SIMD path.
    let back: Vec<f32> = t.to_vec1().expect("tensor to_vec1");
    assert_eq!(back, vec![1.0_f32, 2.0, 3.0, 4.0]);
}

#[test]
fn embedder_matmul_smoke_cpu() {
    use candle_core::{Device, Tensor};
    let device = Device::Cpu;
    // 2x3 * 3x2 -> 2x2 matmul. Verifies the gemm path.
    let a = Tensor::from_vec(vec![1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0], (2, 3), &device).unwrap();
    let b = Tensor::from_vec(vec![1.0_f32, 0.0, 0.0, 1.0, 1.0, 1.0], (3, 2), &device).unwrap();
    let c = a.matmul(&b).expect("matmul on CPU");
    let got: Vec<Vec<f32>> = c.to_vec2().unwrap();
    // Expected: [[1+0+3, 0+2+3], [4+0+6, 0+5+6]] = [[4,5],[10,11]]
    assert_eq!(got, vec![vec![4.0_f32, 5.0], vec![10.0, 11.0]]);
}

// TODO #1068 Layer 3 follow-up:
//   - MiniLM end-to-end embedding (with weight download from a CI
//     cache, NOT hf-hub on every run — that would burn CI minutes)
//   - Cosine similarity equivalence host vs. mobile (target_os gate)
//   - Memory-allocator behavior under iOS jetsam pressure
//   - Embedder cold-start latency budget (mobile slower than host)
