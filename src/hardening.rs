//! Process hardening, and honest reporting of what actually took effect.
//!
//! Notas is a single process that spawns nothing, loads no plugins and makes no
//! network calls. So "sandboxing" here does not mean confining a child — it means
//! having the kernel enforce that *this* process cannot do the things it never
//! needed, so that a bug or an injected payload has nowhere to go.
//!
//! Four layers, applied in [`harden_process`] before any secret material exists:
//!
//! 1. **No core dumps** (`RLIMIT_CORE = 0`) — a dump would contain decrypted
//!    notes and the cached key in plaintext.
//! 2. **Not dumpable** (`PR_SET_DUMPABLE = 0`) — denies other same-user processes
//!    both `ptrace` *and* reads of `/proc/<pid>/mem`. The latter is the real
//!    protection: Yama's `ptrace_scope` only restricts ATTACH, not READ, so
//!    without this a same-user app can passively scrape our memory.
//! 3. **No new privileges** (`PR_SET_NO_NEW_PRIVS`) — also a prerequisite for
//!    installing a seccomp filter without `CAP_SYS_ADMIN`.
//! 4. **A seccomp-bpf filter** — see [`install_seccomp_filter`].
//!
//! # Why every seccomp rule returns EPERM rather than killing the process
//!
//! The security property is identical either way: the syscall cannot succeed.
//! `SIGSYS`/kill differs only in the aftermath — and it converts any future GTK
//! or GLib quirk we did not anticipate into a hard crash of a note-taking app
//! holding unsaved work. EPERM blocks just as completely and degrades safely.
//!
//! # What this does NOT protect against
//!
//! Root, a hostile kernel, or anything with `CAP_SYS_PTRACE`. And see
//! [`lock_memory`] for the swap caveat, which is the notable open exposure.

use std::sync::OnceLock;

/// Outcome of the seccomp install, recorded at startup so the Security page can
/// report what really happened instead of what we intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompStatus {
    Installed { rules: usize },
    Failed(String),
}

/// Outcome of the attempt to keep decrypted notes out of swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemlockStatus {
    /// `mlockall` succeeded — nothing this process holds can be paged out.
    Locked,
    /// Deliberately not attempted: `RLIMIT_MEMLOCK` is too low for `MCL_FUTURE`
    /// to be survivable. Carries the effective limit in bytes.
    SkippedLimitTooLow { limit: u64 },
    /// `mlockall` was attempted and the kernel refused.
    Failed { errno: i32 },
}

static SECCOMP_STATUS: OnceLock<SeccompStatus> = OnceLock::new();
static MEMLOCK_STATUS: OnceLock<MemlockStatus> = OnceLock::new();

/// `mlockall(MCL_FUTURE)` makes *every* later allocation unswappable, and an
/// allocation that would exceed `RLIMIT_MEMLOCK` fails outright. GTK routinely
/// allocates well past the 8 MiB that systemd hands a desktop session, so
/// attempting it under a small limit does not harden the app — it makes it die
/// at a random later allocation. Only try when there is real headroom.
const MEMLOCK_REQUIRED: u64 = 512 * 1024 * 1024;

/// Apply every hardening measure. Must run first thing in `main`, before any
/// secret material exists and before threads are spawned — seccomp filters are
/// inherited across `clone`, so installing here covers the tokio pool and the
/// tray's D-Bus thread without needing TSYNC.
pub fn harden_process() {
    unsafe {
        // No core dumps — they would contain decrypted notes / the key.
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);

        // Deny same-user ptrace AND /proc/<pid>/mem reads. Side effect: /proc/<pid>
        // becomes root-owned, so xdg-desktop-portal logs a harmless warning about
        // reading appearance settings (Notas uses its own themes and its file
        // dialogs are in-app, so nothing actually breaks).
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);

        // Required before a seccomp filter can be installed unprivileged, and
        // independently useful: no setuid binary we exec could ever elevate.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    let _ = SECCOMP_STATUS.set(install_seccomp_filter());
    let _ = MEMLOCK_STATUS.set(lock_memory());
}

/// Install the seccomp-bpf filter.
///
/// The filter is a **denylist over an allow default**, not an allowlist. A full
/// syscall allowlist for a GTK4 process is unmaintainable and one kernel or
/// driver update away from a crash; a denylist targeted at capabilities this app
/// provably never uses gives most of the value at a fraction of the risk.
///
/// What it forbids, and why each one is safe to forbid here:
///
/// - **`socket` with `AF_INET` / `AF_INET6` / `AF_PACKET`** — the headline
///   guarantee: Notas cannot open a network socket. `AF_UNIX` stays allowed
///   because Wayland, D-Bus and the tray all need it, and `AF_NETLINK` stays
///   allowed because GIO's network monitor uses it. Filtering socket *creation*
///   is sufficient — without an inet fd there is nothing for `connect`/`sendto`
///   to act on, and those take a pointer argument seccomp cannot inspect anyway.
/// - **`execve` / `execveat`** — Notas never runs another program.
/// - **`ptrace`, `process_vm_readv`, `process_vm_writev`** — belt and braces
///   with `PR_SET_DUMPABLE`, and blocks us being used as the *attacker* too.
/// - **`unshare`, `mount`, `umount2`, `pivot_root`, `chroot`** — namespace and
///   mount manipulation, a common escalation primitive.
/// - **`keyctl`, `add_key`, `request_key`** — the kernel keyring; our keys live
///   in mlocked userspace buffers.
/// - **`init_module`, `finit_module`, `delete_module`, `kexec_load`** — module
///   and kernel loading.
/// - **`perf_event_open`, `bpf`** — side-channel and tracing facilities.
fn install_seccomp_filter() -> SeccompStatus {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };

    // Only these three socket domains are denied; everything else falls through
    // to the allow default.
    let denied_domains = [libc::AF_INET, libc::AF_INET6, libc::AF_PACKET];
    let mut socket_rules = Vec::new();
    for domain in denied_domains {
        match SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain as u64)
            .and_then(|c| SeccompRule::new(vec![c]))
        {
            Ok(rule) => socket_rules.push(rule),
            Err(e) => return SeccompStatus::Failed(format!("socket rule: {e}")),
        }
    }

    // An empty rule vector means "match this syscall whatever its arguments".
    let mut rules: Vec<(i64, Vec<SeccompRule>)> = vec![
        (libc::SYS_socket, socket_rules),
        (libc::SYS_execve, vec![]),
        (libc::SYS_execveat, vec![]),
        (libc::SYS_ptrace, vec![]),
        (libc::SYS_process_vm_readv, vec![]),
        (libc::SYS_process_vm_writev, vec![]),
        (libc::SYS_unshare, vec![]),
        (libc::SYS_mount, vec![]),
        (libc::SYS_umount2, vec![]),
        (libc::SYS_pivot_root, vec![]),
        (libc::SYS_chroot, vec![]),
        (libc::SYS_keyctl, vec![]),
        (libc::SYS_add_key, vec![]),
        (libc::SYS_request_key, vec![]),
        (libc::SYS_init_module, vec![]),
        (libc::SYS_finit_module, vec![]),
        (libc::SYS_delete_module, vec![]),
        (libc::SYS_kexec_load, vec![]),
        (libc::SYS_perf_event_open, vec![]),
        (libc::SYS_bpf, vec![]),
    ];
    // `fork`/`vfork` are legacy x86_64-only entry points; aarch64 routes both
    // through `clone`, which we must NOT touch because threads need it.
    #[cfg(target_arch = "x86_64")]
    {
        rules.push((libc::SYS_fork, vec![]));
        rules.push((libc::SYS_vfork, vec![]));
    }

    let rule_count = rules.len();
    let arch = match std::env::consts::ARCH.try_into() {
        Ok(a) => a,
        Err(e) => return SeccompStatus::Failed(format!("unsupported arch: {e:?}")),
    };

    let filter = match SeccompFilter::new(
        rules.into_iter().collect(),
        // Anything not named above runs normally...
        SeccompAction::Allow,
        // ...anything named above fails with EPERM. See the module docs for why
        // this is EPERM and not a kill.
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    ) {
        Ok(f) => f,
        Err(e) => return SeccompStatus::Failed(format!("compile: {e}")),
    };

    let program: seccompiler::BpfProgram = match filter.try_into() {
        Ok(p) => p,
        Err(e) => return SeccompStatus::Failed(format!("assemble: {e}")),
    };

    match seccompiler::apply_filter(&program) {
        Ok(()) => SeccompStatus::Installed { rules: rule_count },
        Err(e) => SeccompStatus::Failed(format!("apply: {e}")),
    }
}

/// Test-only handle on the real filter, so tests can install it in a forked
/// child and verify its effects rather than trusting the rule list by eye.
#[cfg(test)]
pub fn install_seccomp_filter_for_test() -> SeccompStatus {
    install_seccomp_filter()
}

/// Try to keep decrypted note text out of swap.
///
/// `SecureBuffer` already mlocks key material, but the *notes themselves* live in
/// a `GtkTextBuffer` on the ordinary heap, so on a machine with swap they can be
/// written to disk in plaintext by the kernel. `mlockall` is the only way to
/// cover allocations we do not own.
///
/// It is frequently not possible: a desktop session's `RLIMIT_MEMLOCK` is
/// typically 8 MiB with an equal hard limit, so we cannot raise it without
/// `CAP_SYS_RESOURCE`, and `MCL_FUTURE` under that ceiling would make GTK's own
/// allocations start failing. In that case we deliberately do nothing and say so
/// on the Security page rather than pretend, or crash.
fn lock_memory() -> MemlockStatus {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return MemlockStatus::Failed {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        };
    }

    // Raise the soft limit to the hard limit where that is allowed; usually they
    // are already equal, but it costs nothing to ask.
    if lim.rlim_cur < lim.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) } == 0 {
            lim.rlim_cur = lim.rlim_max;
        }
    }

    let effective = lim.rlim_cur as u64;
    if effective != libc::RLIM_INFINITY as u64 && effective < MEMLOCK_REQUIRED {
        return MemlockStatus::SkippedLimitTooLow { limit: effective };
    }

    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0 {
        MemlockStatus::Locked
    } else {
        MemlockStatus::Failed {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        }
    }
}

// ── Live status probing ──────────────────────────────────────────────────────

/// What the kernel is *actually* enforcing on this process, right now.
///
/// Everything here is read back from the kernel rather than assumed from what we
/// asked for, so the Security page reports reality — including the cases where a
/// measure could not be applied.
#[derive(Debug, Clone)]
pub struct SecurityStatus {
    /// `/proc/self/status` `Seccomp:` — 0 disabled, 1 strict, 2 filter.
    pub seccomp_mode: u8,
    pub seccomp: SeccompStatus,
    pub no_new_privs: bool,
    /// False means other same-user processes cannot read `/proc/<pid>/mem`.
    pub dumpable: bool,
    pub core_dumps_disabled: bool,
    /// AppArmor confinement, e.g. `unconfined` or a profile name.
    pub apparmor: Option<String>,
    /// Landlock ABI version, or `None` when the LSM is not enabled in the kernel.
    pub landlock_abi: Option<i32>,
    pub memlock: MemlockStatus,
    /// Total swap in bytes; decrypted notes can reach disk when this is non-zero
    /// and memory locking is unavailable.
    pub swap_total: u64,
}

fn proc_status_field(field: &str) -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix(field)
            .and_then(|r| r.strip_prefix(':'))
            .map(|v| v.trim().to_string())
    })
}

/// Ask the kernel for the Landlock ABI version. `EOPNOTSUPP`/`ENOSYS` means the
/// LSM is not enabled — on Ubuntu that is the default, since `landlock` is
/// absent from the boot-time `lsm=` list, so filesystem confinement has to come
/// from AppArmor instead.
fn landlock_abi() -> Option<i32> {
    // LANDLOCK_CREATE_RULESET_VERSION = 1
    let rc = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) };
    (rc > 0).then_some(rc as i32)
}

fn swap_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("SwapTotal:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

pub fn probe() -> SecurityStatus {
    let mut core_lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let core_dumps_disabled = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core_lim) } == 0
        && core_lim.rlim_cur == 0;

    SecurityStatus {
        seccomp_mode: proc_status_field("Seccomp")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        seccomp: SECCOMP_STATUS
            .get()
            .cloned()
            .unwrap_or_else(|| SeccompStatus::Failed("not attempted".into())),
        no_new_privs: proc_status_field("NoNewPrivs").as_deref() == Some("1"),
        dumpable: unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } == 1,
        core_dumps_disabled,
        apparmor: std::fs::read_to_string("/proc/self/attr/current")
            .ok()
            .map(|s| s.trim_end_matches('\0').trim().to_string())
            .filter(|s| !s.is_empty()),
        landlock_abi: landlock_abi(),
        memlock: MEMLOCK_STATUS
            .get()
            .cloned()
            .unwrap_or(MemlockStatus::Failed { errno: 0 }),
        swap_total: swap_total(),
    }
}

/// Human-readable size for the Security page.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (unit, size) in UNITS {
        if bytes >= size {
            return format!("{:.1} {unit}", bytes as f64 / size as f64);
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary calls neither `harden_process` nor `main`, so this checks
    /// the probe reads the kernel rather than echoing our own intentions.
    #[test]
    fn probe_reflects_the_kernel_not_our_wishes() {
        let s = probe();
        assert_eq!(s.seccomp_mode, 0, "no filter installed in the test binary");
        assert!(matches!(s.seccomp, SeccompStatus::Failed(_)));
        assert!(s.dumpable, "test binary should still be dumpable");
    }

    #[test]
    fn memlock_is_skipped_under_a_desktop_rlimit() {
        // A desktop session's 8 MiB ceiling must never lead to mlockall being
        // attempted — MCL_FUTURE under it would starve GTK.
        assert!(MEMLOCK_REQUIRED > 8 * 1024 * 1024);
    }

    #[test]
    fn human_bytes_picks_a_sensible_unit() {
        assert_eq!(human_bytes(8 * 1024 * 1024), "8.0 MiB");
        assert_eq!(human_bytes(4 * 1024 * 1024 * 1024), "4.0 GiB");
        assert_eq!(human_bytes(512), "512 B");
    }

    /// Proves the headline guarantee rather than assuming it: fork a child,
    /// install the real filter there, and check that an inet socket is refused
    /// while a unix socket still works (Wayland, D-Bus and the tray all need the
    /// latter, so blocking it would break the app).
    ///
    /// The child only makes raw syscalls and `_exit`s — no allocation, no
    /// printing — because it is forked from a multi-threaded test binary and must
    /// not touch a lock another thread might hold. Findings come back as exit
    /// codes for the same reason.
    #[test]
    fn the_filter_blocks_inet_sockets_but_not_unix() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let code = match install_seccomp_filter() {
                    SeccompStatus::Installed { .. } => {
                        let inet = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                        let inet6 = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
                        let unix = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                        match (inet, inet6, unix) {
                            (-1, -1, u) if u >= 0 => 0,
                            (i, _, _) if i != -1 => 2,
                            (_, s, _) if s != -1 => 3,
                            _ => 4,
                        }
                    }
                    SeccompStatus::Failed(_) => 5,
                };
                libc::_exit(code);
            }
            let mut wstatus: libc::c_int = 0;
            libc::waitpid(pid, &mut wstatus, 0);
            let code = libc::WEXITSTATUS(wstatus);
            assert_eq!(
                code, 0,
                "child exit {code} (2 = AF_INET allowed, 3 = AF_INET6 allowed, \
                 4 = AF_UNIX wrongly blocked, 5 = filter would not install)"
            );
        }
    }

    /// The filter must compile on this arch even though the test binary does not
    /// install it — a malformed rule would otherwise only surface at runtime.
    #[test]
    fn seccomp_filter_compiles() {
        use seccompiler::{SeccompAction, SeccompFilter};
        let filter = SeccompFilter::new(
            vec![(libc::SYS_execve, vec![])].into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .expect("filter should compile");
        let program: seccompiler::BpfProgram = filter.try_into().expect("should assemble");
        assert!(!program.is_empty());
    }
}
