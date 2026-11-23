"""
Benchmark suite for cryptographic algorithm implementations.
"""

import csv
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Callable, List, Tuple

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.sha256 import sha256_bytes
from crypto_lab.aes128 import (
    aes_encrypt_cbc,
    aes_decrypt_cbc,
    pkcs7_pad,
)
from crypto_lab.ecc import (
    G,
    generate_keypair as ecc_generate_keypair,
    scalar_mul,
    ecdh_shared_secret,
)
from crypto_lab.elgamal import (
    DEFAULT_P,
    DEFAULT_G,
    generate_keypair as elgamal_generate_keypair,
    elgamal_sign,
    elgamal_verify,
)


def measure_execution_time(func: Callable, iterations: int = 10) -> Tuple[float, float, float]:
    """Measure mean execution time, standard deviation, and median over multiple iterations."""
    times = []
    func()  # Warm-up run

    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append(t1 - t0)

    mean_time = statistics.mean(times)
    stdev_time = statistics.stdev(times) if len(times) > 1 else 0.0
    median_time = statistics.median(times)
    return mean_time, stdev_time, median_time


def run_all_benchmarks(output_csv: Path) -> None:
    """Run performance benchmarks on all implemented algorithms and export results to CSV."""
    print("=" * 80)
    print(" STARTING CRYPTOGRAPHIC BENCHMARK SUITE ")
    print("=" * 80)
    print(f"[*] Python Version  : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"[*] Operating System: {platform.system()} {platform.release()} ({platform.platform()})")
    print(f"[*] Processor / CPU : {platform.processor() or platform.machine()}")
    print("=" * 80)

    results = []

    data_1kb = os.urandom(1024)
    data_1mb = os.urandom(1024 * 1024)
    key_16 = os.urandom(16)
    iv_16 = os.urandom(16)

    ct_1kb = aes_encrypt_cbc(data_1kb, key_16, iv_16)
    ct_1mb = aes_encrypt_cbc(data_1mb, key_16, iv_16)

    # 1. Benchmark SHA-256
    print("[*] Benchmarking SHA-256 (1 KB, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: sha256_bytes(data_1kb), iterations=50)
    throughput = (len(data_1kb) / (1024 * 1024)) / mean
    results.append(["SHA-256", "1 KB", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    print("[*] Benchmarking SHA-256 (1 MB, N=5)...")
    mean, stdev, median = measure_execution_time(lambda: sha256_bytes(data_1mb), iterations=5)
    throughput = (len(data_1mb) / (1024 * 1024)) / mean
    results.append(["SHA-256", "1 MB", 5, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    # 2. Benchmark AES-128
    print("[*] Benchmarking AES-128 CBC Encrypt (1 KB, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: aes_encrypt_cbc(data_1kb, key_16, iv_16), iterations=50)
    throughput = (len(data_1kb) / (1024 * 1024)) / mean
    results.append(["AES-128 Encrypt", "1 KB", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    print("[*] Benchmarking AES-128 CBC Decrypt (1 KB, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: aes_decrypt_cbc(ct_1kb, key_16, iv_16), iterations=50)
    throughput = (len(ct_1kb) / (1024 * 1024)) / mean
    results.append(["AES-128 Decrypt", "1 KB", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    print("[*] Benchmarking AES-128 CBC Encrypt (1 MB, N=5)...")
    mean, stdev, median = measure_execution_time(lambda: aes_encrypt_cbc(data_1mb, key_16, iv_16), iterations=5)
    throughput = (len(data_1mb) / (1024 * 1024)) / mean
    results.append(["AES-128 Encrypt", "1 MB", 5, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    print("[*] Benchmarking AES-128 CBC Decrypt (1 MB, N=5)...")
    mean, stdev, median = measure_execution_time(lambda: aes_decrypt_cbc(ct_1mb, key_16, iv_16), iterations=5)
    throughput = (len(ct_1mb) / (1024 * 1024)) / mean
    results.append(["AES-128 Decrypt", "1 MB", 5, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", f"{throughput:.3f}", f"{median*1000:.3f}"])

    # 3. Benchmark ECC (secp256k1 & ECDH)
    k_ecc = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    print("[*] Benchmarking ECC Scalar Multiplication (k*G, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: scalar_mul(k_ecc, G), iterations=50)
    results.append(["ECC Scalar Mul (k*G)", "256-bit", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", "N/A", f"{median*1000:.3f}"])

    alice_priv, alice_pub = ecc_generate_keypair()
    bob_priv, bob_pub = ecc_generate_keypair()
    print("[*] Benchmarking ECDH Key Exchange (N=50)...")
    mean, stdev, median = measure_execution_time(lambda: ecdh_shared_secret(alice_priv, bob_pub), iterations=50)
    results.append(["ECDH Key Exchange", "secp256k1", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", "N/A", f"{median*1000:.3f}"])

    # 4. Benchmark ElGamal Digital Signature (2048-bit)
    elg_priv, elg_pub = elgamal_generate_keypair()
    elg_msg = b"Benchmark payload for 2048-bit ElGamal digital signature."
    elg_sig = elgamal_sign(elg_msg, DEFAULT_P, DEFAULT_G, elg_priv)

    print("[*] Benchmarking ElGamal Signature Generation (Sign, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: elgamal_sign(elg_msg, DEFAULT_P, DEFAULT_G, elg_priv), iterations=50)
    results.append(["ElGamal Sign", "2048-bit", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", "N/A", f"{median*1000:.3f}"])

    print("[*] Benchmarking ElGamal Signature Verification (Verify, N=50)...")
    mean, stdev, median = measure_execution_time(lambda: elgamal_verify(elg_msg, DEFAULT_P, DEFAULT_G, elg_pub, elg_sig), iterations=50)
    results.append(["ElGamal Verify", "2048-bit", 50, f"{mean:.6f}", f"{mean*1000:.3f}", f"{stdev*1000:.3f}", "N/A", f"{median*1000:.3f}"])

    # Write CSV file with English headers matching notebook expectations
    headers = ["Operation", "Input_Size", "Iterations", "Mean_s", "Mean_ms", "Stdev_ms", "Throughput_MB_s", "Median_ms"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(results)

    # Print results table
    print("\n" + "=" * 96)
    print(f"{'Operation':<22} | {'Input Size':<10} | {'Mean (ms)':<10} | {'Median (ms)':<11} | {'Stdev (ms)':<10} | {'Throughput (MB/s)':<15}")
    print("-" * 96)
    for row in results:
        print(f"{row[0]:<22} | {row[1]:<10} | {row[4]:<10} | {row[7]:<11} | {row[5]:<10} | {row[6]:<15}")
    print("=" * 96)
    print(f"[+] Benchmark results successfully saved to: {output_csv.resolve()}")


if __name__ == "__main__":
    results_file = Path(__file__).resolve().parent / "results.csv"
    run_all_benchmarks(results_file)
