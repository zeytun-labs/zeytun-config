use std::env;
use std::io::{self, Read};

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let input = if args.is_empty() || args[0] == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).expect("stdin");
        buf
    } else {
        args.remove(0)
    };

    match zeytun_config::convert(&input) {
        Ok(bytes) => {
            println!("{}", String::from_utf8_lossy(&bytes));
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
