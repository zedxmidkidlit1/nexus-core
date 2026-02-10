//! Build script to configure Npcap SDK library path for Windows
//!
//! Required for pnet library to link against Packet.lib and wpcap.lib

fn main() {
    // Only needed for Windows
    #[cfg(target_os = "windows")]
    {
        // Common Npcap SDK installation paths
        let possible_paths = [
            // User-specific install
            r"C:\npcap-sdk\Lib\x64",
            // System-wide install
            r"C:\Program Files\Npcap\SDK\Lib\x64",
            // Alternative paths
            r"C:\npcap-sdk-1.13\Lib\x64",
            // From environment variable (highest priority)
        ];

        // Check LIB environment variable first
        if let Ok(lib_path) = std::env::var("LIB") {
            for path in lib_path.split(';') {
                if std::path::Path::new(path).join("Packet.lib").exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    println!("cargo:rerun-if-changed={}", path);
                    return;
                }
            }
        }

        // Try common paths
        for path in &possible_paths {
            let packet_lib = std::path::Path::new(path).join("Packet.lib");
            if packet_lib.exists() {
                println!("cargo:rustc-link-search=native={}", path);
                println!("cargo:rerun-if-changed={}", path);
                eprintln!("[build.rs] Found Npcap SDK at: {}", path);
                return;
            }
        }

        // If we get here, Npcap SDK was not found
        eprintln!("[build.rs] WARNING: Npcap SDK not found in common locations.");
        eprintln!("[build.rs] Please install Npcap SDK and set LIB environment variable.");
        eprintln!("[build.rs] Download from: https://npcap.com/#download");
        eprintln!("[build.rs] Trying default paths anyway...");

        // Add default path even if not found (might work if SDK is installed elsewhere)
        println!("cargo:rustc-link-search=native=C:\\npcap-sdk\\Lib\\x64");
    }
}
