use std::path::PathBuf;
use std::{fs, io::Write as _};

use eyre::Report;

pub struct UserInfo {
    user: String,
    host: String,
    pid: u64,
}

pub struct LockFile {
    path: PathBuf,
}

impl LockFile {
    pub fn create(path: PathBuf, info: &UserInfo) -> Result<Self, Report> {
        let mut options = fs::OpenOptions::new();

        options
            .write(true)
            .create(true)
            .create_new(true);

        #[cfg(target_family = "unix")] {
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        }

        // FIXME: error diagnosis for EEXIST could be done.
        let mut file = options.open(&path)?;

        // pwsafe's handling of the identifier written to the lock file here is rather obscure. It
        // *does* care about writing some data by having an **ASSERT**. Yet, it does not in
        // particular care about correctness. The calls to `write` are plain and do not handle
        // partial writes. It only detects erroneous writes in aggregate, i.e. sums up the return
        // reported from each of 5 different calls and requires that the total is `> 0`.
        //
        // Let's do better.
        write!(file, "{}@{}:{}", info.user, info.host, info.pid)?;
        // File handle itself can be closed now.
        drop(file);

        Ok(LockFile {
            path,
        })
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl UserInfo {
    pub fn new() -> Result<Self, Report> {
        let pid = {
            let pid_c = uapi::getpid();
            assert!(pid_c > 0, "PID always returns successfully");
            pid_c as u64
        };

        let hostname = {
            let mut buffer = [0u8; 256];
            let _ = uapi::gethostname(&mut buffer[..]);

            // We don't really care about mangled names here, just use some..
            let terminator = buffer
                .iter()
                .position(|x| *x == b'\0')
                .unwrap_or(buffer.len());

            String::from_utf8_lossy(&buffer[..terminator]).into_owned()
        };

        let username = {
            let euid = uapi::geteuid();

            let mut pwd = core::mem::MaybeUninit::<uapi::c::passwd>::zeroed();
            let mut buffer = vec![0u8; 4096];
            let mut pwd_ptr = core::ptr::null_mut();

            loop {
                let status = unsafe {
                    uapi::c::getpwuid_r(
                        euid,
                        pwd.as_mut_ptr(),
                        buffer.as_mut_ptr() as *mut i8,
                        buffer.len(),
                        &mut pwd_ptr
                    )
                };

                match status {
                    0 => break,
                    uapi::c::ERANGE if buffer.len() < (1 << 20) => {
                        let newlen = buffer.len() * 2;
                        buffer.resize(newlen, 0);
                    }
                    uapi::c::ERANGE => {
                        todo!()
                    }
                    err => {
                        return Err(std::io::Error::from_raw_os_error(err))?;
                    }
                }
            }

            // We would have to check against `NULL` here but Rust's `ptr::null_mut()` need not
            // agree with C's definition. (The former is actually 0, the latter is not necessarily
            // the same value). But luckily the method guarantees to write a pointer to the passed
            // structure on success and find.
            if pwd_ptr != pwd.as_mut_ptr() {
                return Err(Report::msg("User was not found in passwd database, can not create pwsafe lock file information"));
            }

            // Initialized by `getpwuid_r`, which confirms that initialization by writing the
            // `pwd_ptr` as a side effect. Initially we have that pointer not point to the
            // structure and do not modify it ourselves. Only the success path of `getpwuid_r`
            // modifies to pointer to non-NULL.
            let passwd = unsafe { pwd.assume_init() };
            // We could CStr this pointer directly but let's trust it as little as possible.
            let offset = (passwd.pw_name as usize) - (buffer.as_ptr() as usize);
            let cstr = core::ffi::CStr::from_bytes_until_nul(&buffer[offset..])?;

            String::from_utf8_lossy(cstr.to_bytes()).into_owned()
        };

        Ok(UserInfo {
            pid,
            user: username,
            host: hostname,
        })
    }
}
