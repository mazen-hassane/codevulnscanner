use std::process::Command;
use std::env;
use std::fs;
use std::mem;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: cmd <input>");
        return;
    }

    let user_input = &args[1];

    // -----------------------------
    // Command Injection
    // -----------------------------
    let output = Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output()
        .expect("failed");

    println!("{}", String::from_utf8_lossy(&output.stdout));

    // -----------------------------
    // File Read
    // -----------------------------
    if args.len() > 2 {
        let file = &args[2];
        let content = fs::read_to_string(file).unwrap();
        println!("{}", content);
    }

    // -----------------------------
    // Unsafe Pointer Arithmetic
    // -----------------------------
    let arr = [1, 2, 3];

    unsafe {
        let ptr = arr.as_ptr();
        let val = *ptr.add(10);
        println!("Unsafe val: {}", val);
    }

    // -----------------------------
    // Transmute Abuse
    // -----------------------------
    let x: u32 = 1065353216;

    unsafe {
        let y: f32 = mem::transmute(x);
        println!("Transmuted: {}", y);
    }
}
