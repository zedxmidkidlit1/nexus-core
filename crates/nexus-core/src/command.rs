#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppCommand {
    Scan {
        interface: Option<String>,
    },
    LoadTest {
        interface: Option<String>,
        iterations: u32,
        concurrency: usize,
    },
    AiCheck,
    AiInsights,
    Interfaces,
    Help,
    Version,
}
