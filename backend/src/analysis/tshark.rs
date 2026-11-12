//! TShark process management. TShark is the dissection engine:
//! * `-T fields -e ...` for bulk extraction (detection + normalized packet table);
//! * `-T json` for on-demand full dissection of a single packet (packet inspector).
//! All invocations avoid a shell, disable name resolution (`-n`, so analysis never makes
//! DNS lookups) and run with a scrubbed environment.
use std::{collections::HashSet, path::Path, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use super::model::{AGG, FIELDS, SEP};

pub enum Input<'a> {
    File(&'a Path),
    Stdin,
}

fn base(tshark: &str, home: &Path) -> Command {
    let mut c = Command::new(tshark);
    c.env_clear()
        .env("HOME", home)
        .env("TMPDIR", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

/// Command for bulk field extraction.
pub fn fields_command(tshark: &str, home: &Path, input: Input<'_>) -> Command {
    let mut c = base(tshark, home);
    c.arg("-n").arg("-Q").arg("-l");
    match input {
        Input::File(p) => c.arg("-r").arg(p),
        Input::Stdin => c.arg("-r").arg("-").stdin(Stdio::piped()),
    };
    c.args(["-T", "fields"])
        .args(["-E", "header=n", "-E", "occurrence=a", "-E", "quote=n"])
        .arg("-E")
        .arg(format!("separator={SEP}"))
        .arg("-E")
        .arg(format!("aggregator={AGG}"));
    for f in FIELDS {
        c.arg("-e").arg(f);
    }
    c
}

/// Command for full JSON dissection (with raw bytes) of one frame.
pub fn dissect_command(tshark: &str, home: &Path, file: &Path, frame: u64) -> Command {
    let mut c = base(tshark, home);
    c.arg("-n")
        .arg("-r")
        .arg(file)
        .arg("-Y")
        .arg(format!("frame.number == {frame}"))
        .args(["-T", "json", "-x"]);
    c
}

/// Verify the installed TShark knows every field we extract. Returns the version banner.
pub async fn validate(tshark: &str, home: &Path) -> Result<String, String> {
    let out = tokio::time::timeout(
        Duration::from_secs(15),
        base(tshark, home).arg("--version").output(),
    )
    .await
    .map_err(|_| "tshark --version timed out".to_string())?
    .map_err(|e| format!("cannot run '{tshark}': {e}"))?;
    let version = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("unknown")
        .to_string();

    let mut child = base(tshark, home)
        .args(["-G", "fields"])
        .spawn()
        .map_err(|e| format!("cannot run '{tshark} -G fields': {e}"))?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut wanted: HashSet<&str> = FIELDS.iter().copied().collect();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        // Field records: F <name> <abbrev> <type> ...
        let mut cols = line.split('\t');
        if cols.next() == Some("F") {
            if let Some(abbrev) = cols.nth(1) {
                wanted.remove(abbrev);
                if wanted.is_empty() {
                    break;
                }
            }
        }
    }
    let _ = child.kill().await;
    if wanted.is_empty() {
        Ok(version)
    } else {
        let mut missing: Vec<&str> = wanted.into_iter().collect();
        missing.sort_unstable();
        Err(format!(
            "{version} lacks required fields: {}",
            missing.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_command_has_no_shell_and_uses_explicit_fields() {
        let cmd = fields_command(
            "tshark",
            Path::new("/tmp"),
            Input::File(Path::new("/x/a.pcap")),
        );
        let std = cmd.as_std();
        let args: Vec<String> = std
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(std.get_program(), "tshark");
        assert!(args.windows(2).any(|w| w == ["-T", "fields"]));
        assert!(
            args.contains(&"-n".to_string()),
            "name resolution must be off"
        );
        assert_eq!(args.iter().filter(|a| *a == "-e").count(), FIELDS.len());
        assert!(args.contains(&"/x/a.pcap".to_string()));
    }

    #[test]
    fn dissect_filter_is_numeric_only() {
        let cmd = dissect_command("tshark", Path::new("/tmp"), Path::new("/x/a.pcap"), 42);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"frame.number == 42".to_string()));
        assert!(args.windows(2).any(|w| w == ["-T", "json"]));
    }
}
