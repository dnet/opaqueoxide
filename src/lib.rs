use libopaque_sys as ffi;
use std::num::TryFromIntError;

use libsodium_sys::{crypto_hash_sha512_BYTES, crypto_scalarmult_SCALARBYTES,
        crypto_auth_hmacsha512_BYTES, crypto_scalarmult_BYTES};

#[derive(Debug)]
enum OpaqueError {
    EmptyPassword,
    InvalidParameterLength(&'static str),
    Conflict(&'static str),
    LibraryError,
}

impl From<TryFromIntError> for OpaqueError {
    fn from(e: TryFromIntError) -> OpaqueError {
        OpaqueError::InvalidParameterLength("id")
    }
}

#[derive(Debug)]
struct PkgConfig {
    sk_usr: PkgConfigValue,
    pk_usr: PkgConfigValue,
    pk_srv: PkgConfigValue,
    id_usr: PkgConfigValue,
    id_srv: PkgConfigValue,
}

impl From<&PkgConfig> for ffi::Opaque_PkgConfig {
    fn from(pc: &PkgConfig) -> ffi::Opaque_PkgConfig {
        ffi::Opaque_PkgConfig {
            _bitfield_1: ffi::Opaque_PkgConfig::new_bitfield_1(
                *(&pc.sk_usr) as u8,
                *(&pc.pk_usr) as u8, *(&pc.pk_srv) as u8,
                *(&pc.id_usr) as u8, *(&pc.id_srv) as u8)
        }
    }
}

impl From<&RecoverConfig<'_>> for PkgConfig {
    fn from(rc: &RecoverConfig) -> PkgConfig {
        PkgConfig {
            sk_usr: rc.sk_usr,
            pk_usr: rc.pk_usr,
            pk_srv: rc.pk_srv.into(),
            id_usr: rc.id_usr.into(),
            id_srv: rc.id_srv.into(),
        }
    }
}

#[derive(Debug)]
struct RecoverConfig<'a> {
    sk_usr: PkgConfigValue,
    pk_usr: PkgConfigValue,
    pk_srv: RecoverConfigValue<'a>,
    id_usr: RecoverConfigValue<'a>,
    id_srv: RecoverConfigValue<'a>,
}

#[derive(Debug)]
struct Ids {
    usr: Id,
    srv: Id,
}

impl Ids {
    unsafe fn to_ffi_mut(&mut self) -> Result<ffi::Opaque_Ids, TryFromIntError> {
        Ok(ffi::Opaque_Ids {
            idU_len: self.usr.vec.len().try_into()?,
            idU: self.usr.vec.as_mut_ptr(),
            idS_len: self.srv.vec.len().try_into()?,
            idS: self.srv.vec.as_mut_ptr(),
        })
    }

    fn into_tuple(self, ffi_obj: ffi::Opaque_Ids) -> (Vec<u8>, Vec<u8>) {
        let usr = self.usr.drain_vec(ffi_obj.idU_len);
        let srv = self.srv.drain_vec(ffi_obj.idS_len);
        (usr, srv)
    }
}

#[derive(Debug, PartialEq)]
struct Id {
    vec: Vec<u8>,
    src: IdSource,
}

impl Id {
    fn from_user(value: &[u8]) -> Id {
        Id { vec: value.to_vec(), src: IdSource::FromUser }
    }

    fn allocate() -> Id {
        Id { vec: vec![0u8; u16::MAX as usize], src: IdSource::Allocated }
    }

    fn drain_vec(mut self, length: u16) -> Vec<u8> {
        if self.src == IdSource::Allocated {
            unsafe {
                self.vec.set_len(length as usize);
            }
            self.vec.shrink_to_fit();
        }
        self.vec
    }
}

impl From<RecoverConfigValue<'_>> for Id {
    fn from(rcv: RecoverConfigValue) -> Id {
        match rcv {
            RecoverConfigValue::InSecEnv | RecoverConfigValue::InClrEnv =>
                Id::allocate(),
            RecoverConfigValue::NotPackaged(k) => Id::from_user(k),
        }
    }
}

#[derive(Debug, PartialEq)]
enum IdSource {
    FromUser,
    Allocated,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
enum PkgConfigValue {
    NotPackaged = ffi::Opaque_PkgTarget_NotPackaged,
    InSecEnv = ffi::Opaque_PkgTarget_InSecEnv,
    InClrEnv = ffi::Opaque_PkgTarget_InClrEnv,
}

impl From<RecoverConfigValue<'_>> for PkgConfigValue {
    fn from(rcv: RecoverConfigValue) -> PkgConfigValue {
        match rcv {
            RecoverConfigValue::NotPackaged(_) => PkgConfigValue::NotPackaged,
            RecoverConfigValue::InSecEnv => PkgConfigValue::InSecEnv,
            RecoverConfigValue::InClrEnv => PkgConfigValue::InClrEnv,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
enum RecoverConfigValue<'a> {
    NotPackaged(&'a [u8]),
    InSecEnv,
    InClrEnv,
}

fn register(user_pwd: &[u8], cfg: &PkgConfig, ids: (&[u8], &[u8]),
            server_keys: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    if user_pwd.is_empty() { return Err(OpaqueError::EmptyPassword) };
    let sks_ptr = if let Some(sks) = server_keys {
        if sks.len() != crypto_scalarmult_SCALARBYTES as usize {
            return Err(OpaqueError::InvalidParameterLength("server_keys"));
        } else {
            sks.as_ptr()
        }
    } else {
        std::ptr::null()
    };
    let mut ids_mut = Ids { usr: Id::from_user(ids.0), srv: Id::from_user(ids.1) };
    let env_user_len = envelope_len(cfg, &mut ids_mut)?;
    let mut rec: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_USER_RECORD_LEN + env_user_len);
    let mut export_key: Vec<u8> = Vec::with_capacity(crypto_hash_sha512_BYTES as usize);
    if unsafe { ffi::opaque_Register(user_pwd.as_ptr(), user_pwd.len() as u16,
            sks_ptr, &cfg.into(), &ids_mut.to_ffi_mut()?, rec.as_mut_ptr(),
            export_key.as_mut_ptr()) } == 0 {
        unsafe {
            rec.set_len(ffi::OPAQUE_USER_RECORD_LEN + env_user_len);
            export_key.set_len(crypto_hash_sha512_BYTES as usize);
        }
        Ok((rec, export_key))
    } else {
        Err(OpaqueError::LibraryError)
    }
}

fn create_credential_request(user_pwd: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    if user_pwd.is_empty() { return Err(OpaqueError::EmptyPassword) };
    let mut sec: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_USER_SESSION_SECRET_LEN +
                                              user_pwd.len());
    let mut pub_: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_USER_SESSION_PUBLIC_LEN);
    unsafe {
        if ffi::opaque_CreateCredentialRequest(user_pwd.as_ptr(), user_pwd.len() as u16,
                                     sec.as_mut_ptr(), pub_.as_mut_ptr()) != 0 {
            return Err(OpaqueError::LibraryError);
        }
        sec.set_len(ffi::OPAQUE_USER_SESSION_SECRET_LEN + user_pwd.len());
        pub_.set_len(ffi::OPAQUE_USER_SESSION_PUBLIC_LEN);
    }
    Ok((pub_, sec))
}

fn create_credential_response(pub_: &[u8], rec: &[u8], cfg: &PkgConfig,
                              ids: (&[u8], &[u8]), infos: Option<()>
                              ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), OpaqueError> {
    if pub_.len() != ffi::OPAQUE_USER_SESSION_PUBLIC_LEN as usize {
        return Err(OpaqueError::InvalidParameterLength("pub"));
    }
    let mut ids_mut = Ids { usr: Id::from_user(ids.0), srv: Id::from_user(ids.1) };
    let env_user_len = envelope_len(cfg, &mut ids_mut)?;
    if rec.len() != ffi::OPAQUE_USER_RECORD_LEN + env_user_len {
        return Err(OpaqueError::InvalidParameterLength("rec"));
    }
    let mut resp: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_SERVER_SESSION_LEN +
                                           env_user_len);
    let mut sk: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_SHARED_SECRETBYTES);
    let mut sec: Vec<u8> = Vec::with_capacity(ffi::opaque_server_auth_ctx_len());
    let infos_ptr: *const ffi::Opaque_App_Infos = if let Some(i) = infos {
        panic!("not implemented for now")
    } else { std::ptr::null() };
    if unsafe { ffi::opaque_CreateCredentialResponse(pub_.as_ptr(), rec.as_ptr(),
            &ids_mut.to_ffi_mut()?, infos_ptr, resp.as_mut_ptr(), sk.as_mut_ptr(),
            sec.as_mut_ptr()) } == 0 {
        unsafe {
            resp.set_len(ffi::OPAQUE_SERVER_SESSION_LEN + env_user_len);
            sk.set_len(ffi::OPAQUE_SHARED_SECRETBYTES);
            sec.set_len(ffi::opaque_server_auth_ctx_len());
        }
        Ok((resp, sk, sec))
    } else {
        Err(OpaqueError::LibraryError)
    }
}

fn recover_credentials(resp: &[u8], sec: &[u8], cfg: &RecoverConfig, infos: Option<()>,
                       ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, (Vec<u8>, Vec<u8>)),
                                   OpaqueError> {
    if resp.len() <= ffi::OPAQUE_SERVER_SESSION_LEN {
        return Err(OpaqueError::InvalidParameterLength("resp"));
    }
    if sec.len() <= ffi::OPAQUE_USER_SESSION_SECRET_LEN {
        return Err(OpaqueError::InvalidParameterLength("sec"));
    }
    let mut sk: Vec<u8> = Vec::with_capacity(ffi::OPAQUE_SHARED_SECRETBYTES);
    let mut auth_user: Vec<u8> = Vec::with_capacity(
        crypto_auth_hmacsha512_BYTES as usize);
    let mut export_key: Vec<u8> = Vec::with_capacity(
        crypto_hash_sha512_BYTES as usize);
    let pk_ptr = match cfg.pk_srv {
        RecoverConfigValue::InSecEnv | RecoverConfigValue::InClrEnv
            => std::ptr::null(),
        RecoverConfigValue::NotPackaged(k)
            if k.len() != crypto_scalarmult_BYTES as usize =>
            { return Err(OpaqueError::InvalidParameterLength("pk_srv")); },
        RecoverConfigValue::NotPackaged(k) => k.as_ptr(),
    };
    let mut ids1 = Ids { usr: cfg.id_usr.into(), srv: cfg.id_srv.into() };
    let infos_ptr: *const ffi::Opaque_App_Infos = if let Some(i) = infos {
        panic!("not implemented for now")
    } else { std::ptr::null() };
    let pcfg: PkgConfig = cfg.into();
    unsafe {
        let mut ids_ptr = ids1.to_ffi_mut()?;
        if ffi::opaque_RecoverCredentials(resp.as_ptr(), sec.as_ptr(),
                    pk_ptr, &(&pcfg).into(), infos_ptr, &mut ids_ptr,
                    sk.as_mut_ptr(), auth_user.as_mut_ptr(),
                    export_key.as_mut_ptr()) == 0 {
            sk.set_len(ffi::OPAQUE_SHARED_SECRETBYTES);
            auth_user.set_len(crypto_auth_hmacsha512_BYTES as usize);
            export_key.set_len(crypto_hash_sha512_BYTES as usize);
            Ok((sk, auth_user, export_key, ids1.into_tuple(ids_ptr)))
        } else {
            Err(OpaqueError::LibraryError)
        }
    }
}

fn user_auth(sec_srv: &[u8], auth_user: &[u8]) -> Result<(), OpaqueError> {
    if sec_srv.len() != ffi::opaque_server_auth_ctx_len() {
        return Err(OpaqueError::InvalidParameterLength("sec_srv"));
    }
    if auth_user.len() != crypto_auth_hmacsha512_BYTES as usize {
        return Err(OpaqueError::InvalidParameterLength("auth_user"));
    }
    if (unsafe { ffi::opaque_UserAuth(sec_srv.as_ptr(),
                                             auth_user.as_ptr()) } == 0) {
        Ok(())
    } else {
        Err(OpaqueError::LibraryError)
    }
}

fn envelope_len(cfg: &PkgConfig, ids: &mut Ids) -> Result<usize, TryFromIntError> {
    Ok(unsafe {
        ffi::opaque_envelope_len(&cfg.into(), &ids.to_ffi_mut()?) as usize
    })
}

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn simple() {
        let pwd_user = b"simple guessable dictionary password";
        let ids = ("user".as_bytes(), "server".as_bytes());
        let cfg = PkgConfig {
            sk_usr: PkgConfigValue::InSecEnv,
            pk_usr: PkgConfigValue::InSecEnv, pk_srv: PkgConfigValue::InSecEnv,
            id_usr: PkgConfigValue::InSecEnv, id_srv: PkgConfigValue::InSecEnv,
        };
        let (rec, export_key) = register(pwd_user, &cfg, ids, None).expect("register");
        
        let (pub_, sec_user) = create_credential_request(pwd_user).expect("ccreq");

        let (resp, sk, sec_srv) = create_credential_response(&pub_, &rec, &cfg, ids, None).expect("ccresp");

        let recfg = RecoverConfig {
            sk_usr: cfg.sk_usr, pk_usr: cfg.pk_usr,
            pk_srv: RecoverConfigValue::InSecEnv,
            id_usr: RecoverConfigValue::InSecEnv,
            id_srv: RecoverConfigValue::InSecEnv,
        };

        let (sk1, auth_user, export_key1, ids1) = recover_credentials(
            &resp, &sec_user, &recfg, None).expect("recover");

        user_auth(&sec_srv, &auth_user).expect("user_auth");

        assert_eq!(ids.0, ids1.0);
        assert_eq!(ids.1, ids1.1);
        assert_eq!(export_key, export_key1);
        assert_eq!(sk, sk1);
    }
}
