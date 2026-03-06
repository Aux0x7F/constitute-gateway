use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "constitute-operator",
    version,
    about = "Constitute installer utility (GUI + CLI)",
    long_about = "Download once, then use this utility to install a Windows gateway service or build a Linux FCOS gateway image. Defaults to release assets unless dev mode is enabled."
)]
struct Cli {
    /// Launch native GUI mode.
    #[arg(long)]
    gui: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build a Linux FCOS image (works on Linux directly or via WSL on Windows).
    LinuxImage(LinuxImageArgs),
    /// Install or update local Windows service from latest release.
    WindowsService(WindowsServiceArgs),
}

#[derive(Parser, Debug, Clone)]
struct SharedArgs {
    /// GitHub owner
    #[arg(long, default_value = "Aux0x7F")]
    repo_owner: String,

    /// GitHub repository name
    #[arg(long, default_value = "constitute-gateway")]
    repo_name: String,

    /// Enable dev source mode (build from source branch instead of release assets)
    #[arg(long)]
    dev_source: bool,

    /// Dev branch for --dev-source mode
    #[arg(long, default_value = "main")]
    dev_branch: String,

    /// Pairing identity label for bootstrap enrollment
    #[arg(long)]
    pair_identity: Option<String>,

    /// Pairing code for bootstrap enrollment
    #[arg(long)]
    pair_code: Option<String>,

    /// Pairing code hash override for bootstrap enrollment
    #[arg(long)]
    pair_code_hash: Option<String>,
}

#[derive(Parser, Debug, Clone)]
struct LinuxImageArgs {
    #[command(flatten)]
    shared: SharedArgs,

    /// FCOS stream
    #[arg(long, default_value = "stable")]
    stream: String,

    /// Architecture
    #[arg(long, default_value = "x86_64")]
    arch: String,

    /// Output directory for generated image artifacts
    #[arg(long)]
    out_dir: Option<PathBuf>,

    /// Enable dev polling profile (2m)
    #[arg(long)]
    dev_poll: bool,

    /// Optional direct write target (destructive)
    #[arg(long)]
    device: Option<String>,

    /// Also print post-boot NVR install helper command
    #[arg(long)]
    include_nvr: bool,
}

#[derive(Parser, Debug, Clone)]
struct WindowsServiceArgs {
    #[command(flatten)]
    shared: SharedArgs,

    /// Windows service name
    #[arg(long, default_value = "ConstituteGateway")]
    service_name: String,

    /// Optional install directory override
    #[arg(long)]
    install_dir: Option<PathBuf>,

    /// Update interval minutes for scheduled updater
    #[arg(long, default_value_t = 30)]
    update_interval_minutes: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum InstallTarget {
    LinuxImage,
    WindowsService,
}

#[derive(Clone, Debug)]
struct InstallPlan {
    target: InstallTarget,
    repo_owner: String,
    repo_name: String,
    dev_source: bool,
    dev_branch: String,
    pair_identity: Option<String>,
    pair_code: Option<String>,
    pair_code_hash: Option<String>,
    stream: String,
    arch: String,
    out_dir: Option<PathBuf>,
    dev_poll: bool,
    device: Option<String>,
    include_nvr: bool,
    service_name: String,
    install_dir: Option<PathBuf>,
    update_interval_minutes: u32,
}

impl Default for InstallPlan {
    fn default() -> Self {
        Self {
            target: InstallTarget::LinuxImage,
            repo_owner: "Aux0x7F".to_string(),
            repo_name: "constitute-gateway".to_string(),
            dev_source: false,
            dev_branch: "main".to_string(),
            pair_identity: None,
            pair_code: None,
            pair_code_hash: None,
            stream: "stable".to_string(),
            arch: "x86_64".to_string(),
            out_dir: None,
            dev_poll: false,
            device: None,
            include_nvr: false,
            service_name: "ConstituteGateway".to_string(),
            install_dir: None,
            update_interval_minutes: 30,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.gui {
        return launch_gui();
    }

    match cli.command {
        Some(Commands::LinuxImage(args)) => run_plan(plan_from_linux_args(args)),
        Some(Commands::WindowsService(args)) => run_plan(plan_from_windows_args(args)),
        None => run_interactive(),
    }
}

fn plan_from_linux_args(args: LinuxImageArgs) -> InstallPlan {
    InstallPlan {
        target: InstallTarget::LinuxImage,
        repo_owner: args.shared.repo_owner,
        repo_name: args.shared.repo_name,
        dev_source: args.shared.dev_source,
        dev_branch: args.shared.dev_branch,
        pair_identity: args.shared.pair_identity,
        pair_code: args.shared.pair_code,
        pair_code_hash: args.shared.pair_code_hash,
        stream: args.stream,
        arch: args.arch,
        out_dir: args.out_dir,
        dev_poll: args.dev_poll,
        device: args.device,
        include_nvr: args.include_nvr,
        ..InstallPlan::default()
    }
}

fn plan_from_windows_args(args: WindowsServiceArgs) -> InstallPlan {
    InstallPlan {
        target: InstallTarget::WindowsService,
        repo_owner: args.shared.repo_owner,
        repo_name: args.shared.repo_name,
        dev_source: args.shared.dev_source,
        dev_branch: args.shared.dev_branch,
        pair_identity: args.shared.pair_identity,
        pair_code: args.shared.pair_code,
        pair_code_hash: args.shared.pair_code_hash,
        service_name: args.service_name,
        install_dir: args.install_dir,
        update_interval_minutes: args.update_interval_minutes,
        ..InstallPlan::default()
    }
}

fn run_interactive() -> Result<()> {
    println!("Constitute Operator Utility\n");
    let mut plan = InstallPlan::default();

    let windows_host = cfg!(windows);
    if windows_host {
        println!("Targets:");
        println!("  1) Linux Image (FCOS metal)");
        println!("  2) Windows Service (local install/update)");
        print!("Select target [1/2]: ");
        io::stdout().flush().ok();
        let mut target = String::new();
        io::stdin().read_line(&mut target)?;
        if target.trim() == "2" {
            plan.target = InstallTarget::WindowsService;
        }
    } else {
        println!("Target: Linux Image (FCOS metal)");
        plan.target = InstallTarget::LinuxImage;
    }

    print!("Use dev source mode? [y/N]: ");
    io::stdout().flush().ok();
    let mut dev = String::new();
    io::stdin().read_line(&mut dev)?;
    plan.dev_source = matches!(dev.trim().to_ascii_lowercase().as_str(), "y" | "yes");

    if plan.dev_source {
        print!("Dev branch [main]: ");
        io::stdout().flush().ok();
        let mut branch = String::new();
        io::stdin().read_line(&mut branch)?;
        let branch = branch.trim();
        if !branch.is_empty() {
            plan.dev_branch = branch.to_string();
        }
    }

    print!("Pair identity label (optional): ");
    io::stdout().flush().ok();
    let mut pair_identity = String::new();
    io::stdin().read_line(&mut pair_identity)?;
    let pair_identity = pair_identity.trim();
    if !pair_identity.is_empty() {
        plan.pair_identity = Some(pair_identity.to_string());

        print!("Pair code: ");
        io::stdout().flush().ok();
        let mut pair_code = String::new();
        io::stdin().read_line(&mut pair_code)?;
        let pair_code = pair_code.trim();
        if !pair_code.is_empty() {
            plan.pair_code = Some(pair_code.to_string());
        }

        print!("Pair code hash (optional): ");
        io::stdout().flush().ok();
        let mut pair_hash = String::new();
        io::stdin().read_line(&mut pair_hash)?;
        let pair_hash = pair_hash.trim();
        if !pair_hash.is_empty() {
            plan.pair_code_hash = Some(pair_hash.to_string());
        }
    }

    if plan.target == InstallTarget::LinuxImage {
        print!("Include NVR post-boot helper command? [y/N]: ");
        io::stdout().flush().ok();
        let mut include = String::new();
        io::stdin().read_line(&mut include)?;
        plan.include_nvr = matches!(include.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    }

    run_plan(plan)
}

fn run_plan(plan: InstallPlan) -> Result<()> {
    validate_pairing(&plan)?;

    match plan.target {
        InstallTarget::LinuxImage => run_linux_image(&plan),
        InstallTarget::WindowsService => run_windows_service(&plan),
    }
}

fn validate_pairing(plan: &InstallPlan) -> Result<()> {
    let has_identity = plan
        .pair_identity
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_code = plan
        .pair_code
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    if has_identity ^ has_code {
        bail!("pairing requires both --pair-identity and --pair-code");
    }
    Ok(())
}

fn run_windows_service(plan: &InstallPlan) -> Result<()> {
    if !cfg!(windows) {
        bail!("windows-service target is only available on Windows operators");
    }

    let script = resolve_script(&["scripts", "windows", "install-latest.ps1"])?;
    let mut cmd = Command::new("powershell");
    cmd.arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script)
        .arg("-RepoOwner")
        .arg(&plan.repo_owner)
        .arg("-RepoName")
        .arg(&plan.repo_name)
        .arg("-ServiceName")
        .arg(&plan.service_name)
        .arg("-UpdateIntervalMinutes")
        .arg(plan.update_interval_minutes.to_string());

    if let Some(path) = &plan.install_dir {
        cmd.arg("-InstallDir").arg(path);
    }

    if plan.dev_source {
        cmd.arg("-DevSource");
        cmd.arg("-DevBranch").arg(&plan.dev_branch);
    }

    if plan.pair_identity.is_some() {
        eprintln!("[operator] note: pairing bootstrap is supported for Linux image path, not Windows service path.");
    }

    run_command(&mut cmd, "install/update windows service")
}

fn run_linux_image(plan: &InstallPlan) -> Result<()> {
    if cfg!(windows) {
        run_linux_image_from_windows(plan)
    } else {
        run_linux_image_from_unix(plan)
    }
}

fn run_linux_image_from_windows(plan: &InstallPlan) -> Result<()> {
    let script = resolve_script(&["scripts", "windows", "prepare-auto-update-image.ps1"])?;
    let mut cmd = Command::new("powershell");
    cmd.arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script)
        .arg("-RepoOwner")
        .arg(&plan.repo_owner)
        .arg("-RepoName")
        .arg(&plan.repo_name)
        .arg("-Stream")
        .arg(&plan.stream)
        .arg("-Arch")
        .arg(&plan.arch);

    if let Some(path) = &plan.out_dir {
        cmd.arg("-OutDir").arg(path);
    }
    if plan.dev_poll {
        cmd.arg("-DevPoll");
    }
    if plan.dev_source {
        cmd.arg("-DevSource")
            .arg("-DevBranch")
            .arg(&plan.dev_branch);
    }
    if let Some(v) = &plan.pair_identity {
        cmd.arg("-PairIdentity").arg(v);
    }
    if let Some(v) = &plan.pair_code {
        cmd.arg("-PairCode").arg(v);
    }
    if let Some(v) = &plan.pair_code_hash {
        cmd.arg("-PairCodeHash").arg(v);
    }
    if let Some(v) = &plan.device {
        cmd.arg("-Device").arg(v);
    }

    run_command(&mut cmd, "build linux image")?;
    maybe_print_nvr_postboot(plan);
    Ok(())
}

fn run_linux_image_from_unix(plan: &InstallPlan) -> Result<()> {
    let script = resolve_script(&["scripts", "fcos", "prepare-auto-update-image.sh"])?;
    let mut cmd = Command::new("bash");
    cmd.arg(script)
        .arg("--repo-owner")
        .arg(&plan.repo_owner)
        .arg("--repo-name")
        .arg(&plan.repo_name)
        .arg("--stream")
        .arg(&plan.stream)
        .arg("--arch")
        .arg(&plan.arch);

    if let Some(path) = &plan.out_dir {
        cmd.arg("--download-dir").arg(path);
    }
    if plan.dev_poll {
        cmd.arg("--dev-poll");
    }
    if plan.dev_source {
        cmd.arg("--dev-source")
            .arg("--dev-branch")
            .arg(&plan.dev_branch);
    }
    if let Some(v) = &plan.pair_identity {
        cmd.arg("--pair-identity").arg(v);
    }
    if let Some(v) = &plan.pair_code {
        cmd.arg("--pair-code").arg(v);
    }
    if let Some(v) = &plan.pair_code_hash {
        cmd.arg("--pair-code-hash").arg(v);
    }
    if let Some(v) = &plan.device {
        cmd.arg("--device").arg(v);
    }

    run_command(&mut cmd, "build linux image")?;
    maybe_print_nvr_postboot(plan);
    Ok(())
}

fn maybe_print_nvr_postboot(plan: &InstallPlan) {
    if !plan.include_nvr {
        return;
    }

    let mut parts = vec![
        "curl -fsSL https://raw.githubusercontent.com/Aux0x7F/constitute-nvr/main/scripts/linux/install-latest.sh | bash -s -- --non-interactive".to_string(),
        "--swarm-peer '127.0.0.1:4040'".to_string(),
        "--public-ws-url 'ws://127.0.0.1:8456/session'".to_string(),
    ];

    if let Some(v) = &plan.pair_identity {
        parts.push(format!("--pair-identity '{}'", shell_single_quote(v)));
    }
    if let Some(v) = &plan.pair_code {
        parts.push(format!("--pair-code '{}'", shell_single_quote(v)));
    }
    if let Some(v) = &plan.pair_code_hash {
        parts.push(format!("--pair-code-hash '{}'", shell_single_quote(v)));
    }

    eprintln!("\n[operator] NVR post-boot helper command (run on gateway host):");
    eprintln!("{}\n", parts.join(" "));
}

fn shell_single_quote(input: &str) -> String {
    input.replace('\'', "'\\''")
}

fn run_command(cmd: &mut Command, label: &str) -> Result<()> {
    cmd.stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    eprintln!("[operator] {}...", label);
    let status = cmd
        .status()
        .with_context(|| format!("failed to launch command for {label}"))?;
    if !status.success() {
        return Err(anyhow!("{label} failed with status {status}"));
    }
    eprintln!("[operator] {} complete", label);
    Ok(())
}

fn resolve_script(parts: &[&str]) -> Result<PathBuf> {
    let mut candidates = Vec::<PathBuf>::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(parts.join(std::path::MAIN_SEPARATOR_STR)));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(parts.join(std::path::MAIN_SEPARATOR_STR)));
    }

    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(parts.join(std::path::MAIN_SEPARATOR_STR)),
    );

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("required script not found: {}", parts.join("/"));
}

#[cfg(feature = "operator-gui")]
fn launch_gui() -> Result<()> {
    use eframe::egui;

    struct AppState {
        plan: InstallPlan,
        status: String,
    }

    impl Default for AppState {
        fn default() -> Self {
            Self {
                plan: InstallPlan::default(),
                status: "Ready".to_string(),
            }
        }
    }

    impl eframe::App for AppState {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Constitute Operator Utility");
                ui.label("Defaults to releases/latest. Enable dev source only for local development loops.");
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Target");
                    egui::ComboBox::from_id_salt("target")
                        .selected_text(match self.plan.target {
                            InstallTarget::LinuxImage => "Linux Image (FCOS)",
                            InstallTarget::WindowsService => "Windows Service",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.plan.target, InstallTarget::LinuxImage, "Linux Image (FCOS)");
                            if cfg!(windows) {
                                ui.selectable_value(&mut self.plan.target, InstallTarget::WindowsService, "Windows Service");
                            }
                        });
                });

                ui.horizontal(|ui| {
                    ui.label("Repo owner");
                    ui.text_edit_singleline(&mut self.plan.repo_owner);
                    ui.label("Repo name");
                    ui.text_edit_singleline(&mut self.plan.repo_name);
                });

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.plan.dev_source, "Dev source mode");
                    ui.label("Branch");
                    ui.text_edit_singleline(&mut self.plan.dev_branch);
                });

                if self.plan.target == InstallTarget::LinuxImage {
                    ui.horizontal(|ui| {
                        ui.label("Stream");
                        ui.text_edit_singleline(&mut self.plan.stream);
                        ui.label("Arch");
                        ui.text_edit_singleline(&mut self.plan.arch);
                    });
                    ui.checkbox(&mut self.plan.dev_poll, "Dev poll (2m)");
                    ui.checkbox(&mut self.plan.include_nvr, "Print NVR post-boot helper command");
                } else {
                    ui.horizontal(|ui| {
                        ui.label("Service");
                        ui.text_edit_singleline(&mut self.plan.service_name);
                        ui.label("Update minutes");
                        ui.add(egui::DragValue::new(&mut self.plan.update_interval_minutes).range(5..=1440));
                    });
                }

                ui.separator();
                ui.label("Pairing bootstrap (optional)");
                ui.horizontal(|ui| {
                    ui.label("Identity");
                    let mut v = self.plan.pair_identity.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut v).changed() {
                        self.plan.pair_identity = if v.trim().is_empty() { None } else { Some(v) };
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Code");
                    let mut v = self.plan.pair_code.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut v).changed() {
                        self.plan.pair_code = if v.trim().is_empty() { None } else { Some(v) };
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Code hash");
                    let mut v = self.plan.pair_code_hash.clone().unwrap_or_default();
                    if ui.text_edit_singleline(&mut v).changed() {
                        self.plan.pair_code_hash = if v.trim().is_empty() { None } else { Some(v) };
                    }
                });

                ui.separator();
                if ui.button("Run").clicked() {
                    match run_plan(self.plan.clone()) {
                        Ok(()) => self.status = "Completed successfully".to_string(),
                        Err(err) => self.status = format!("Failed: {err}"),
                    }
                }

                ui.label(format!("Status: {}", self.status));
            });
        }
    }

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Constitute Operator Utility",
        native_options,
        Box::new(|_cc| Ok(Box::<AppState>::default())),
    )
    .map_err(|e| anyhow!("gui failed: {e}"))
}

#[cfg(not(feature = "operator-gui"))]
fn launch_gui() -> Result<()> {
    bail!("this build does not include GUI support; rebuild with --features operator-gui")
}
