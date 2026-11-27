// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! OS integration: store location and ACL, administrator check and the
//! `CercanoAgent` Windows service. Everything Windows-specific lives in
//! `imp` behind `cfg(windows)`; other platforms get explicit
//! "unsupported" answers so the workspace still builds and tests on Linux.

use crate::CliError;
use std::path::PathBuf;

#[cfg(windows)]
pub use imp::{install, is_admin, run_service, service_state, store_dir, uninstall};

#[cfg(not(windows))]
mod other {
    use super::*;

    const UNSUPPORTED: &str =
        "el agente Cercano solo funciona como servicio en Windows (ADR-015 §2.12)";

    /// Store directory. Off Windows it is only used by tests and diagnostics.
    pub fn store_dir() -> Result<PathBuf, CliError> {
        Ok(std::env::var_os("CERCANO_AGENT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/cercano-agent")))
    }

    // shortcut: no root check off Windows; the agent only runs on Windows (ADR-015 §2.12).
    pub fn is_admin() -> bool {
        false
    }

    pub fn service_state() -> &'static str {
        "unsupported_platform"
    }

    pub fn install() -> Result<(), CliError> {
        Err(CliError::Unsupported(UNSUPPORTED))
    }

    pub fn uninstall() -> Result<(), CliError> {
        Err(CliError::Unsupported(UNSUPPORTED))
    }

    pub fn run_service() -> Result<(), CliError> {
        Err(CliError::Unsupported(UNSUPPORTED))
    }
}

#[cfg(not(windows))]
pub use other::{install, is_admin, run_service, service_state, store_dir, uninstall};

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::logs;
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ProgressInvokeNever,
        TreeSetNamedSecurityInfoW, SE_FILE_OBJECT, TREE_SEC_INFO_RESET,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    const SERVICE_NAME: &str = "CercanoAgent";

    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, IsUserAnAdmin, SHGetKnownFolderPath,
    };

    /// Owner Administrators; protected DACL: SYSTEM and Administrators full control,
    /// inherited by everything inside. No other principal has any access.
    const STORE_SDDL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    fn os_err(context: &str, code: u32) -> CliError {
        CliError::Failed(format!(
            "{context}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        ))
    }

    fn svc_err(context: &str, e: windows_service::Error) -> CliError {
        CliError::Failed(format!("{context}: {e}"))
    }

    /// Known folder from the shell, not from `%ProgramData%`, which the caller controls.
    fn known_folder(id: &GUID) -> Result<PathBuf, CliError> {
        let mut raw: *mut u16 = std::ptr::null_mut();
        // SAFETY: valid GUID pointer and out-pointer; the buffer is freed with CoTaskMemFree.
        let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
        if hr < 0 {
            return Err(CliError::Failed(format!(
                "no se pudo resolver la carpeta del sistema (HRESULT {hr:#x})"
            )));
        }
        // SAFETY: on success `raw` is a NUL-terminated wide string owned by us.
        let path = unsafe {
            let len = (0..).take_while(|&i| *raw.add(i) != 0).count();
            let s = OsString::from_wide(std::slice::from_raw_parts(raw, len));
            CoTaskMemFree(raw as *const _);
            s
        };
        Ok(PathBuf::from(path))
    }

    pub fn store_dir() -> Result<PathBuf, CliError> {
        Ok(known_folder(&FOLDERID_ProgramData)?
            .join("Cercano")
            .join("agent"))
    }

    /// Creates the store and resets owner and DACL on the whole tree, so a
    /// directory pre-created by an unprivileged user cannot keep its own ACL.
    pub fn ensure_store() -> Result<PathBuf, CliError> {
        let dir = store_dir()?;
        std::fs::create_dir_all(logs::log_dir(&dir))
            .map_err(|e| CliError::Failed(format!("no se pudo crear {}: {e}", dir.display())))?;
        let sddl = wide(OsStr::new(STORE_SDDL));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: NUL-terminated SDDL; `sd` is released with LocalFree below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(CliError::Failed(format!(
                "SDDL del almacén: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let (mut defaulted, mut present) = (0, 0);
        let path = wide(dir.as_os_str());
        // SAFETY: `sd` is a valid self-relative descriptor; owner/dacl point into it.
        let rc = unsafe {
            GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted);
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
            let rc = TreeSetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
                TREE_SEC_INFO_RESET,
                None,
                ProgressInvokeNever,
                std::ptr::null(),
            );
            LocalFree(sd as _);
            rc
        };
        if rc != ERROR_SUCCESS {
            return Err(os_err("no se pudo fijar la ACL del almacén", rc));
        }
        Ok(dir)
    }

    pub fn is_admin() -> bool {
        // SAFETY: no arguments; reads the current process token.
        unsafe { IsUserAnAdmin() != 0 }
    }

    pub fn service_state() -> &'static str {
        let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        else {
            return "unknown";
        };
        let Ok(svc) = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
            return "not_installed";
        };
        match svc.query_status().map(|s| s.current_state) {
            Ok(ServiceState::Running) => "running",
            Ok(ServiceState::Stopped) => "stopped",
            Ok(ServiceState::StartPending) => "start_pending",
            Ok(ServiceState::StopPending) => "stop_pending",
            Ok(_) => "paused",
            Err(_) => "unknown",
        }
    }

    pub fn install() -> Result<(), CliError> {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| CliError::Failed(format!("ruta del ejecutable: {e}")))?;
        // A SYSTEM service must not run a binary that standard users can replace.
        let program_files = std::fs::canonicalize(known_folder(&FOLDERID_ProgramFiles)?)
            .map_err(|e| CliError::Failed(format!("Program Files: {e}")))?;
        if !exe.starts_with(&program_files) {
            return Err(CliError::Failed(format!(
                "el ejecutable debe estar dentro de {} para instalarse como servicio (está en {})",
                program_files.display(),
                exe.display()
            )));
        }
        let mgr = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| svc_err("administrador de servicios", e))?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("Cercano Agent"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![OsString::from("run")],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = mgr
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .map_err(|e| svc_err("no se pudo crear el servicio", e))?;
        svc.set_description("Vincula este equipo con el servidor Cercano de la organización")
            .map_err(|e| svc_err("descripción del servicio", e))?;
        let store = ensure_store()?;
        let _ = logs::write(&logs::log_dir(&store), "INFO", "servicio instalado");
        svc.start::<&str>(&[])
            .map_err(|e| svc_err("el servicio se instaló pero no arrancó", e))
    }

    pub fn uninstall() -> Result<(), CliError> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| svc_err("administrador de servicios", e))?;
        let svc = mgr
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(|e| svc_err("no se encontró el servicio", e))?;
        let state =
            |svc: &windows_service::service::Service| svc.query_status().map(|s| s.current_state);
        if state(&svc).map_err(|e| svc_err("estado del servicio", e))? != ServiceState::Stopped {
            let _ = svc.stop();
            let deadline = Instant::now() + Duration::from_secs(20);
            while state(&svc).ok() != Some(ServiceState::Stopped) {
                if Instant::now() > deadline {
                    return Err(CliError::Failed(
                        "el servicio no se detuvo en 20 s".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        svc.delete()
            .map_err(|e| svc_err("no se pudo eliminar el servicio", e))?;
        drop(svc);
        // "Sin restos": the store (pinned keys, logs) goes with the service.
        let store = store_dir()?;
        match std::fs::remove_dir_all(&store) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(CliError::Failed(format!(
                    "servicio eliminado, pero no se pudo borrar {}: {e}",
                    store.display()
                )))
            }
        }
        if let Some(parent) = store.parent() {
            let _ = std::fs::remove_dir(parent); // only if empty
        }
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_service() -> Result<(), CliError> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
            svc_err(
                "«run» solo lo invoca el administrador de servicios de Windows",
                e,
            )
        })
    }

    fn service_main(_args: Vec<OsString>) {
        let log_dir = store_dir().map(|d| logs::log_dir(&d)).ok();
        let log = |level: &str, msg: &str| {
            if let Some(dir) = &log_dir {
                let _ = logs::write(dir, level, msg);
            }
        };
        if let Err(e) = serve(&log) {
            log("ERROR", &format!("el servicio terminó con error: {e}"));
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    fn serve(log: &dyn Fn(&str, &str)) -> windows_service::Result<()> {
        let (tx, rx) = mpsc::channel();
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, handler)?;
        handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))?;
        if let Err(e) = ensure_store() {
            log("ERROR", &format!("almacén: {e}"));
        }
        log(
            "INFO",
            &format!("servicio iniciado (versión {})", env!("CARGO_PKG_VERSION")),
        );
        // F3.5-06 adds the pipe server here; F3.5-05/07 add enrollment, policy and heartbeat.
        let _ = rx.recv();
        log("INFO", "servicio detenido");
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))
    }
}
