use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "constitute-operator")]
#[command(about = "Constitute gateway installer utility (service install/update only)")]
struct Cli {
    #[arg(long)]
    gui: bool,

    #[arg(long)]
    dry_run: bool,

    #[arg(long, default_value = "Aux0x7F")]
    repo_owner: String,

    #[arg(long, default_value = "constitute-gateway")]
    repo_name: String,

    #[arg(long, default_value = "ConstituteGateway")]
    service_name: String,

    #[arg(long, default_value_t = 30)]
    update_interval_minutes: u32,

    #[arg(long)]
    install_dir: Option<String>,

    #[arg(long)]
    pair_identity: Option<String>,

    #[arg(long)]
    pair_code: Option<String>,

    #[arg(long)]
    pair_code_hash: Option<String>,

    #[arg(long)]
    skip_update_task: bool,

    #[command(subcommand)]
    command: Option<InstallTarget>,
}

#[derive(Debug, Subcommand, Clone, Copy)]
enum InstallTarget {
    /// Install/update Windows service from releases/latest
    WindowsService,
    /// Install/update Linux service from releases/latest
    LinuxService,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.gui {
        eprintln!("[operator] GUI mode has been removed. Using CLI flow.");
    }

    let target = cli.command.unwrap_or_else(default_target_for_host);
    match target {
        InstallTarget::WindowsService => run_windows_service(&cli),
        InstallTarget::LinuxService => run_linux_service(&cli),
    }
}

fn default_target_for_host() -> InstallTarget {
    if cfg!(target_os = "windows") {
        InstallTarget::WindowsService
    } else {
        InstallTarget::LinuxService
    }
}

fn run_windows_service(cli: &Cli) -> Result<()> {
    if !cfg!(target_os = "windows") {
        bail!("windows-service is only supported on Windows hosts");
    }

    let script = resolve_script(&["scripts", "windows", "install-latest.ps1"])?;
    let mut cmd = Command::new("powershell");
    cmd.arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script)
        .arg("-RepoOwner")
        .arg(&cli.repo_owner)
        .arg("-RepoName")
        .arg(&cli.repo_name)
        .arg("-ServiceName")
        .arg(&cli.service_name)
        .arg("-UpdateIntervalMinutes")
        .arg(cli.update_interval_minutes.to_string());

    if let Some(install_dir) = cli.install_dir.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-InstallDir").arg(install_dir);
    }
    if let Some(v) = cli.pair_identity.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-PairIdentity").arg(v);
    }
    if let Some(v) = cli.pair_code.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-PairCode").arg(v);
    }
    if let Some(v) = cli.pair_code_hash.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("-PairCodeHash").arg(v);
    }
    if cli.skip_update_task {
        cmd.arg("-SkipUpdateTask");
    }

    run_command(cmd, cli.dry_run, "windows service install/update")
}

fn run_linux_service(cli: &Cli) -> Result<()> {
    let script = resolve_script(&["scripts", "linux", "install-latest.sh"])?;

    if cfg!(target_os = "windows") {
        return run_linux_service_via_wsl(cli, &script);
    }

    let mut cmd = Command::new("bash");
    cmd.arg(script)
        .arg("--repo-owner")
        .arg(&cli.repo_owner)
        .arg("--repo-name")
        .arg(&cli.repo_name)
        .arg("--timer-interval")
        .arg(format!("{}m", cli.update_interval_minutes));

    if let Some(v) = cli.pair_identity.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("--pair-identity").arg(v);
    }
    if let Some(v) = cli.pair_code.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("--pair-code").arg(v);
    }
    if let Some(v) = cli.pair_code_hash.as_deref().filter(|v| !v.trim().is_empty()) {
        cmd.arg("--pair-code-hash").arg(v);
    }
    run_command(cmd, cli.dry_run, "linux service install/update")
}

fn run_linux_service_via_wsl(cli: &Cli, script: &Path) -> Result<()> {
    let wsl_script = wsl_path(script)?;
    let mut args: Vec<String> = vec![
        "bash".to_string(),
        wsl_script,
        "--repo-owner".to_string(),
        cli.repo_owner.clone(),
        "--repo-name".to_string(),
        cli.repo_name.clone(),
        "--timer-interval".to_string(),
        format!("{}m", cli.update_interval_minutes),
    ];

    if let Some(v) = cli.pair_identity.as_deref().filter(|v| !v.trim().is_empty()) {
        args.push("--pair-identity".to_string());
        args.push(v.to_string());
    }
    if let Some(v) = cli.pair_code.as_deref().filter(|v| !v.trim().is_empty()) {
        args.push("--pair-code".to_string());
        args.push(v.to_string());
    }
    if let Some(v) = cli.pair_code_hash.as_deref().filter(|v| !v.trim().is_empty()) {
        args.push("--pair-code-hash".to_string());
        args.push(v.to_string());
    }

    if cli.skip_update_task {
        eprintln!("[operator] note: skip-update-task is not supported for Linux path via WSL; run install on target host.");
    }

    let mut cmd = Command::new("wsl");
    cmd.arg("-e");
    for a in args {
        cmd.arg(a);
    }

    run_command(cmd, cli.dry_run, "linux service install/update via wsl")
}

fn resolve_script(parts: &[&str]) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve current executable path")?;
    let mut roots = Vec::new();
    if let Some(parent) = exe.parent() {
        roots.push(parent.to_path_buf());
        if let Some(pp) = parent.parent() {
            roots.push(pp.to_path_buf());
        }
    }
    roots.push(std::env::current_dir().context("resolve current dir")?);

    for root in roots {
        let candidate = parts.iter().fold(root.clone(), |acc, part| acc.join(part));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    bail!("script not found: {}", parts.join("/"))
}

fn wsl_path(path: &Path) -> Result<String> {
    let output = Command::new("wsl")
        .arg("wslpath")
        .arg("-a")
        .arg(path)
        .output()
        .context("run wslpath")?;

    if !output.status.success() {
        bail!("wslpath failed with status {}", output.status);
    }

    let converted = String::from_utf8(output.stdout).context("decode wslpath output")?;
    let out = converted.trim();
    if out.is_empty() {
        bail!("wslpath returned empty path");
    }
    Ok(out.to_string())
}

fn run_command(mut cmd: Command, dry_run: bool, label: &str) -> Result<()> {
    if dry_run {
        println!("[operator] dry-run: {label}");
        println!("[operator] command: {:?}", cmd);
        return Ok(());
    }

    println!("[operator] {label}...");
    let status = cmd.status().context("spawn command")?;
    if !status.success() {
        bail!("{label} failed with status {status}");
    }
    println!("[operator] {label} complete");
    Ok(())
}