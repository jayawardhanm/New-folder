use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "scarlett", about = "PC-native D3D12 runtime for Scarlett titles")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load and inspect / boot a title executable.
    Run {
        exe: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { exe, dry_run } => {
            if let Some(dir) = exe.parent()
                && !dir.as_os_str().is_empty()
            {
                let _ = std::env::set_current_dir(dir);
            }
            let _device = scarlett_gpu::device_x::init_global_device()?;
            let rt = scarlett_hle::load_title(&exe)?;
            scarlett_gpu::device_x::set_title_allocator(
                scarlett_hle::xmem::title_allocate_callback()
                    .unwrap_or(scarlett_hle::xmem::xmem_alloc as *const () as usize),
            );
            tracing::info!(
                ep = format_args!("{:#x}", rt.exe.entry_point),
                dry_run,
                "PC-native runtime initialized"
            );
            if !dry_run {
                // SAFETY: runtime and D3D12 device initialized, all imports bound.
                let code = unsafe { scarlett_hle::execute_title(&rt) };
                tracing::info!(exit_code = code, "title exited");
            }
        }
    }
    Ok(())
}
