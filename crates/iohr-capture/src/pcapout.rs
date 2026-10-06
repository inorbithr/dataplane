//! `iohr-capture pcap --out`: root copies the companion's pcap file for the person who ran
//! `sudo`. The parser process (the least trusted part of the companion, which owns the pcap
//! directory) names the file in its answer, so nothing in that answer is trusted:
//!
//! 1. the path must be `<dir>/<name>` for the directory this command resolves itself
//!    (`--pcap-dir`, `IOHR_CAPTURE_PCAP_DIR`), and the name one the companion makes
//!    ([`crate::pcap::ours`]);
//! 2. the directory is opened `O_DIRECTORY | O_NOFOLLOW`, the file with `openat` and
//!    `O_NOFOLLOW | O_NONBLOCK` (a symbolic link fails, a FIFO cannot block);
//! 3. `fstat` of the open file: a regular file, one link, owned by the directory's owner
//!    (the companion's user, never root), no larger than the cap;
//! 4. only then root gives up its identity for the person's (`setgroups`, `setresgid`,
//!    `setresuid` to `SUDO_UID`/`SUDO_GID`) and creates `--out` as that person, so the
//!    copy can never land anywhere the person could not write themselves. A partial copy
//!    is removed.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags};

/// The companion's file, open and checked.
#[derive(Debug)]
pub(crate) struct Source {
    pub(crate) file: File,
    pub(crate) size: u64,
}

/// Opens the file the companion named, refusing anything but its own regular file in
/// `dir` (see the module docs). `max` caps its size.
pub(crate) fn open_source(dir: &Path, answered: &str, max: u64) -> Result<Source, String> {
    let path = Path::new(answered);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the companion named no file")?;
    if path.parent() != Some(dir) || !crate::pcap::ours(name) {
        return Err(format!(
            "the companion named a file outside {} or not one of its own; refusing to copy it",
            dir.display()
        ));
    }
    let dirfd: OwnedFd = rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("opening {}: {e}", dir.display()))?;
    let dir_owner = rustix::fs::fstat(&dirfd)
        .map_err(|e| format!("stat {}: {e}", dir.display()))?
        .st_uid;
    let fd = rustix::fs::openat(
        &dirfd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("opening {name}: {e} (a symbolic link is refused)"))?;
    let st = rustix::fs::fstat(fd.as_fd()).map_err(|e| format!("stat {name}: {e}"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!("{name} is not a regular file; refusing"));
    }
    if st.st_nlink != 1 {
        return Err(format!("{name} has more than one link; refusing"));
    }
    if st.st_uid != dir_owner || st.st_uid == 0 {
        return Err(format!(
            "{name} is owned by uid {}, not the companion's user (uid {dir_owner}); refusing",
            st.st_uid
        ));
    }
    let size = u64::try_from(st.st_size).unwrap_or(u64::MAX);
    if size > max {
        return Err(format!(
            "{name} is {size} bytes, over the {max} byte cap; refusing"
        ));
    }
    Ok(Source {
        file: File::from(fd),
        size,
    })
}

/// The person who ran `sudo`, from `SUDO_UID`/`SUDO_GID` (root or missing: `None`).
pub(crate) fn sudo_user() -> Option<(u32, u32)> {
    let id = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
    match (id("SUDO_UID"), id("SUDO_GID")) {
        (Some(u), Some(g)) if u != 0 => Some((u, g)),
        _ => None,
    }
}

/// Becomes `user` for good (this thread is the process's only one: the caller dropped
/// its runtime first).
pub(crate) fn become_user(uid: u32, gid: u32) -> io::Result<()> {
    use rustix::thread::{set_thread_groups, set_thread_res_gid, set_thread_res_uid};
    let gid = rustix::process::Gid::from_raw(gid);
    let uid = rustix::process::Uid::from_raw(uid);
    set_thread_groups(&[gid])?;
    set_thread_res_gid(gid, gid, gid)?;
    set_thread_res_uid(uid, uid, uid)?;
    if rustix::process::geteuid() != uid || rustix::process::getuid() != uid {
        return Err(io::Error::other("the identity did not change"));
    }
    Ok(())
}

/// Copies `src` to `out` (created, must not exist, no symbolic link followed, mode 0600)
/// as whoever this process is now; removes a partial copy on failure.
pub(crate) fn copy(mut src: Source, out: &Path) -> io::Result<u64> {
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
        .open(out)?;
    let result = (|| {
        let n = io::copy(&mut (&mut src.file).take(src.size), &mut dst)?;
        dst.flush()?;
        dst.sync_all()?;
        Ok(n)
    })();
    if result.is_err() {
        drop(dst);
        let _ = std::fs::remove_file(out);
    }
    result
}

/// Reads at most `n` bytes (tests).
#[cfg(test)]
fn read_all(mut s: Source) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = s.file.read_to_end(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "iohr-20261006T120000Z-1.pcapng";

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("iohr-pcapout-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_companions_own_file_is_copied() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = dir("ok");
        std::fs::write(d.join(NAME), b"pcapng bytes").unwrap();
        let p = d.join(NAME);
        let s = open_source(&d, p.to_str().unwrap(), 1 << 20).unwrap();
        assert_eq!(s.size, 12);
        assert_eq!(read_all(s), b"pcapng bytes");
        let s = open_source(&d, p.to_str().unwrap(), 1 << 20).unwrap();
        let out = d.join("copy.pcapng");
        assert_eq!(copy(s, &out).unwrap(), 12);
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Never over an existing file.
        let s = open_source(&d, p.to_str().unwrap(), 1 << 20).unwrap();
        assert!(copy(s, &out).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn whatever_else_the_companion_names_is_refused() {
        let d = dir("bad");
        let target = d.join("secret");
        std::fs::write(&target, b"root's secret").unwrap();
        // A path outside the directory, or a name the companion never makes.
        for answered in [
            "/etc/shadow".to_owned(),
            format!("{}/../{NAME}", d.display()),
            format!("{}/secret", d.display()),
            format!("{}/sub/{NAME}", d.display()),
        ] {
            assert!(open_source(&d, &answered, 1 << 20).is_err(), "{answered}");
        }
        let named = d.join(NAME);
        let named = named.to_str().unwrap();
        // A symbolic link with the right name.
        std::os::unix::fs::symlink(&target, d.join(NAME)).unwrap();
        assert!(
            open_source(&d, named, 1 << 20)
                .unwrap_err()
                .contains("symbolic")
        );
        std::fs::remove_file(d.join(NAME)).unwrap();
        // A hard link to another file.
        std::fs::hard_link(&target, d.join(NAME)).unwrap();
        assert!(
            open_source(&d, named, 1 << 20)
                .unwrap_err()
                .contains("link")
        );
        std::fs::remove_file(d.join(NAME)).unwrap();
        // A FIFO: refused at once, never blocks.
        rustix::fs::mknodat(
            rustix::fs::CWD,
            d.join(NAME),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(
            open_source(&d, named, 1 << 20)
                .unwrap_err()
                .contains("regular")
        );
        std::fs::remove_file(d.join(NAME)).unwrap();
        // Over the cap.
        std::fs::write(d.join(NAME), vec![0u8; 100]).unwrap();
        assert!(open_source(&d, named, 10).unwrap_err().contains("cap"));
        // The directory itself a symbolic link.
        let link = std::env::temp_dir().join(format!("iohr-pcapout-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&d, &link).unwrap();
        let via = link.join(NAME);
        assert!(open_source(&link, via.to_str().unwrap(), 1 << 20).is_err());
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&d);
    }
}
