// nullsec-banshee — File Integrity Screamer (Rust)
// The banshee wails when files have been changed.
// Computes SHA-256 hashes, stores a baseline, and screams on mismatch.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

const VERSION: &str = "1.0.0";
const BASELINE_FILE: &str = ".banshee-baseline";

fn sha256_hex(data: &[u8]) -> String {
    // Pure Rust SHA-256 (no external crates)
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let k: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|v| format!("{:08x}", v)).collect::<String>()
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(sha256_hex(&buf))
}

fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if !name.starts_with('.') && name != "node_modules" && name != "target" {
                    files.extend(walk_dir(&path));
                }
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files
}

fn cmd_baseline(dir: &str) {
    let start = Instant::now();
    let path = Path::new(dir);
    let files = walk_dir(path);
    let baseline_path = path.join(BASELINE_FILE);

    println!("\n💀 BANSHEE — Creating integrity baseline");
    println!("   Directory: {}", dir);
    println!("   Files: {}\n", files.len());

    let mut out = fs::File::create(&baseline_path).expect("Cannot create baseline file");
    let mut count = 0;

    for f in &files {
        if f == &baseline_path { continue; }
        match hash_file(f) {
            Ok(hash) => {
                let rel = f.strip_prefix(path).unwrap_or(f);
                writeln!(out, "{}  {}", hash, rel.display()).unwrap();
                count += 1;
            }
            Err(_) => {
                eprintln!("  ⚠️  Cannot read: {}", f.display());
            }
        }
    }

    let elapsed = start.elapsed();
    println!("  ✅ Baseline created: {} files hashed in {:.1}s", count, elapsed.as_secs_f64());
    println!("  📄 Stored in: {}\n", baseline_path.display());
}

fn cmd_wail(dir: &str) {
    let start = Instant::now();
    let path = Path::new(dir);
    let baseline_path = path.join(BASELINE_FILE);

    if !baseline_path.exists() {
        eprintln!("\n❌ No baseline found. Run 'banshee baseline {}' first.\n", dir);
        std::process::exit(1);
    }

    println!("\n💀 BANSHEE — Integrity Check (The Wailing)");
    println!("   Directory: {}\n", dir);

    // Load baseline
    let file = fs::File::open(&baseline_path).expect("Cannot read baseline");
    let reader = BufReader::new(file);
    let mut baseline: HashMap<String, String> = HashMap::new();

    for line in reader.lines().flatten() {
        if let Some((hash, filepath)) = line.split_once("  ") {
            baseline.insert(filepath.to_string(), hash.to_string());
        }
    }

    let mut modified = 0;
    let mut missing = 0;
    let mut new_files = 0;
    let current_files = walk_dir(path);

    // Check existing files
    let mut seen = std::collections::HashSet::new();
    for f in &current_files {
        if f == &baseline_path { continue; }
        let rel = f.strip_prefix(path).unwrap_or(f).display().to_string();
        seen.insert(rel.clone());

        match (hash_file(f), baseline.get(&rel)) {
            (Ok(current_hash), Some(baseline_hash)) => {
                if current_hash != *baseline_hash {
                    println!("  🔴 MODIFIED: {}", rel);
                    println!("      was: {}", baseline_hash);
                    println!("      now: {}", current_hash);
                    modified += 1;
                }
            }
            (Ok(_), None) => {
                println!("  🟡 NEW FILE: {}", rel);
                new_files += 1;
            }
            (Err(e), _) => {
                eprintln!("  ⚠️  Cannot read: {} ({})", rel, e);
            }
        }
    }

    // Check for deleted files
    for path_str in baseline.keys() {
        if !seen.contains(path_str) {
            println!("  💨 DELETED: {}", path_str);
            missing += 1;
        }
    }

    let elapsed = start.elapsed();
    let total_issues = modified + missing + new_files;

    if total_issues == 0 {
        println!("  ✅ All {} files intact — the banshee is silent.\n", baseline.len());
    } else {
        println!("\n  💀 THE BANSHEE WAILS!");
        println!("     {} modified, {} deleted, {} new ({:.1}s)\n",
            modified, missing, new_files, elapsed.as_secs_f64());
    }
}

fn print_help() {
    println!(r#"
💀 nullsec-banshee v{} — File Integrity Screamer (Rust)
   Part of the nullsec freakshow suite.

Usage:
  banshee baseline <dir>    Create SHA-256 hash baseline of all files
  banshee wail <dir>        Check files against baseline (the wailing)
  banshee hash <file>       Hash a single file

Examples:
  banshee baseline /etc
  banshee wail /etc
  banshee hash /etc/passwd
"#, VERSION);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "baseline" => {
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".");
            cmd_baseline(dir);
        }
        "wail" => {
            let dir = args.get(2).map(|s| s.as_str()).unwrap_or(".");
            cmd_wail(dir);
        }
        "hash" => {
            if let Some(file) = args.get(2) {
                match hash_file(Path::new(file)) {
                    Ok(h) => println!("{}  {}", h, file),
                    Err(e) => eprintln!("Error: {}", e),
                }
            } else {
                eprintln!("Usage: banshee hash <file>");
            }
        }
        "--help" | "-h" => print_help(),
        _ => print_help(),
    }
}
