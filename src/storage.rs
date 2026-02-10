use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

pub fn ensure_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

pub fn write_file_0600_fsync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent dir"))?;
    ensure_dir(dir)?;

    // Write to a temp file in the same directory, then rename.
    let tmp_path = tmp_path_in_dir(dir, path.file_name().unwrap_or_default());
    let mut f = open_0600(&tmp_path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp_path, path)?;
    fsync_dir(dir)?;
    Ok(())
}

fn open_0600(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts.open(path)
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let f = File::open(dir)?;
        f.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn tmp_path_in_dir(dir: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let mut tmp_name = OsString::from(file_name);
    tmp_name.push(".tmp");
    dir.join(tmp_name)
}
