// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 Moew72 <Moew72@proton.me>

use std::ffi::{CString, c_char};
use std::fs;
use std::mem::ManuallyDrop;
use std::path::Path;
use std::ptr::null;

use data_encoding::HEXUPPER;
use ntex::web;
use serde::{Deserialize, Serialize};

mod lib {
    use std::ffi::*;
    type Func = extern "C" fn(*const c_char, *const c_uchar, c_int, c_int, *mut c_uchar);
    unsafe extern "C" {
        pub(super) static mut libs: *mut *const c_char;
        pub(super) static mut offset: usize;
        pub(super) static mut sign: Func;
        pub(super) fn load_module() -> c_int;
        pub(super) fn unload_module();
    }
}

// Linux签名偏移列表 后续签名版本可能会有变化，需要手动更新
const LINUX_SIGN_OFFSETS: &[(&str, &str, usize)] = &[
    ("3.1.2-12912", "12912", 0x33C38E0),
    ("3.1.2-13107", "13107", 0x33C3920),
    ("3.2.7-23361", "23361", 0x4C93C57),
    ("3.2.9-24815", "24815", 0x4E5D3B7),
    ("3.2.10-25765", "25765", 0x4F176D6),
    ("3.2.19-39038", "39038", 0x5ADE220),
    ("3.2.20-40990", "40990", 0x5D418B1),
];

fn set_libs(libs: Vec<&str>) {
    println!("[INFO] Setting libraries: {:?}", libs);
    let mut libs = libs
        .iter()
        .map(|&x| ManuallyDrop::new(CString::new(x).unwrap()).as_ptr())
        .collect::<Vec<*const c_char>>();
    libs.push(null());
    unsafe {
        lib::libs = ManuallyDrop::new(libs).as_mut_ptr();
    }
}

fn set_offset(offset: usize) {
    println!("[INFO] Setting offset: 0x{:X}", offset);
    unsafe {
        lib::offset = offset;
    }
}

fn load_module() {
    println!("[INFO] Loading module...");
    let ret = unsafe { lib::load_module() };
    if ret != 0 {
        panic!("[ERROR] Load module error: {}", ret);
    }
    println!("[INFO] Module loaded successfully");
}

#[allow(unused)]
fn unload_module() {
    println!("[INFO] Unloading module...");
    unsafe { lib::unload_module() }
}

fn sign(cmd: &str, src: &[u8], seq: i32) -> [Vec<u8>; 3] {
    println!("[DEBUG] Signing request - cmd: {}, src_len: {}, seq: {}", cmd, src.len(), seq);
    
    const TOKEN_DATA_OFFSET: usize = 0x000;
    const TOKEN_LEN_OFFSET: usize = 0x0FF;
    const EXTRA_DATA_OFFSET: usize = 0x100;
    const EXTRA_LEN_OFFSET: usize = 0x1FF;
    const SIGN_DATA_OFFSET: usize = 0x200;
    const SIGN_LEN_OFFSET: usize = 0x2FF;

    let c_cmd = CString::new(cmd).unwrap();
    let mut buf = [0u8; 0x300];
    let _ = unsafe {
        lib::sign(
            c_cmd.as_ptr(),
            src.as_ptr(),
            src.len() as i32,
            seq,
            buf.as_mut_ptr(),
        )
    };

    let token_len = buf[TOKEN_LEN_OFFSET];
    let token = &buf[TOKEN_DATA_OFFSET..TOKEN_DATA_OFFSET + token_len as usize];
    let extra_len = buf[EXTRA_LEN_OFFSET];
    let extra = &buf[EXTRA_DATA_OFFSET..EXTRA_DATA_OFFSET + extra_len as usize];
    let sign_len = buf[SIGN_LEN_OFFSET];
    let sign = &buf[SIGN_DATA_OFFSET..SIGN_DATA_OFFSET + sign_len as usize];

    println!("[DEBUG] Sign result - token_len: {}, extra_len: {}, sign_len: {}", 
             token_len, extra_len, sign_len);

    [Vec::from(token), Vec::from(extra), Vec::from(sign)]
}

fn get_offset_for_version(version: &str) -> Option<(String, usize)> {
    println!("[INFO] Looking up offset for version: {}", version);
    
 
    for (full_ver, short_ver, offset) in LINUX_SIGN_OFFSETS {
        if *full_ver == version {
            println!("[INFO] Found offset 0x{:X} for full version {}", offset, version);
            return Some((full_ver.to_string(), *offset));
        }
    }
    

    for (full_ver, short_ver, offset) in LINUX_SIGN_OFFSETS {
        if *short_ver == version {
            println!("[INFO] Found offset 0x{:X} for short version {} (full: {})", offset, version, full_ver);
            return Some((full_ver.to_string(), *offset));
        }
    }
    
    println!("[WARN] No offset found for version: {}", version);
    None
}


fn get_full_version(version: &str) -> Option<String> {

    for (full_ver, short_ver, _) in LINUX_SIGN_OFFSETS {
        if *full_ver == version {
            return Some(full_ver.to_string());
        }
    }
    

    for (full_ver, short_ver, _) in LINUX_SIGN_OFFSETS {
        if *short_ver == version {
            return Some(full_ver.to_string());
        }
    }
    
    // 如果都不匹配，返回None表示版本不受支持
    None
}

fn read_package_json() -> Option<PackageJson> {
    let path = "/opt/QQ/resources/app/package.json";
    println!("[INFO] Reading package.json from: {}", path);
    
    if !Path::new(path).exists() {
        println!("[WARN] package.json not found at: {}", path);
        return None;
    }
    
    match fs::read_to_string(path) {
        Ok(content) => {
            println!("[DEBUG] Package.json content: {}", content);
            match serde_json::from_str(&content) {
                Ok(pkg) => {
                    println!("[INFO] Successfully parsed package.json");
                    Some(pkg)
                }
                Err(e) => {
                    println!("[ERROR] Failed to parse package.json: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            println!("[ERROR] Failed to read package.json: {}", e);
            None
        }
    }
}

#[ntex::main]
async fn main() -> std::io::Result<()> {
    println!("[INFO] Starting Sign Server...");

    set_libs(vec!["libgnutls.so.30", "./libsymbols.so"]);
    
    set_offset(0x5ADE220);
    
    load_module();
    
    println!("[INFO] Server starting on 0.0.0.0:11479");
    
    web::HttpServer::new(|| {
        web::App::new()
            .service(homepage)
            .service(sign_api_get)
            .service(sign_api_post)
            .service(appinfo_api)
    })
    .bind(("0.0.0.0", 11479))?
    .run()
    .await
}

#[web::get("/")]
async fn homepage() -> impl web::Responder {
    println!("[INFO] Serving homepage");
    match fs::read_to_string("static/index.html") {
        Ok(content) => web::HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(content),
        Err(_) => web::HttpResponse::NotFound().body("Homepage not found"),
    }
}

#[web::get("/api/sign/{version}")]
async fn sign_api_get(path: web::types::Path<String>) -> impl web::Responder {
    let version = path.into_inner();
    println!("[INFO] GET /api/sign/{}", version);
    
    // 检查版本是否受支持
    if get_full_version(&version).is_none() {
        println!("[WARN] Unsupported version requested via GET: {}", version);
        match fs::read_to_string("static/unsupported.html") {
            Ok(content) => return web::HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(content),
            Err(_) => return web::HttpResponse::NotFound().body("Unsupported version page not found"),
        }
    }
    
    match fs::read_to_string("static/sign.html") {
        Ok(content) => web::HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(content),
        Err(_) => web::HttpResponse::NotFound().body("Sign API page not found"),
    }
}


#[web::post("/api/sign/{version}")]
async fn sign_api_post(
    path: web::types::Path<String>,
    params: web::types::Json<Params>,
) -> impl web::Responder {
    let requested_version = path.into_inner();
    println!("[INFO] POST /api/sign/{} - cmd: {}, seq: {}", requested_version, params.cmd, params.seq);

    let (full_version, offset) = match get_offset_for_version(&requested_version) {
        Some((full_ver, offset)) => {
            println!("[INFO] Using offset 0x{:X} for version {} (requested: {})", offset, full_ver, requested_version);
            (full_ver, offset)
        }
        None => {
            println!("[WARN] Unsupported version: {}", requested_version);
            return web::HttpResponse::BadRequest().body(format!("Unsupported version: {}", requested_version));
        }
    };
    
    set_offset(offset);
    load_module();
    
    let ret = HEXUPPER.decode(params.src.to_uppercase().as_bytes());
    let src = match ret {
        Ok(v) => v,
        Err(err) => {
            println!("[ERROR] Failed to decode src: {}", err);
            return web::HttpResponse::BadRequest().body(format!("Invalid src: {}", err));
        }
    };
    
    let [token, extra, sign] = sign(&params.cmd, &src, params.seq);
    let token = HEXUPPER.encode(&token);
    let extra = HEXUPPER.encode(&extra);
    let sign = HEXUPPER.encode(&sign);
    
    let value = Value { 
        token, 
        extra, 
        sign 
    };
    
    let body = RespBody { 
        platform: "Linux".to_string(),
        value,
        version: full_version.clone(),
    };
    
    println!("[INFO] Sign response generated for version: {} (requested: {})", full_version, requested_version);
    web::HttpResponse::Ok().json(&body)
}


#[web::get("/api/sign/{version}/appinfo")]
async fn appinfo_api(path: web::types::Path<String>) -> impl web::Responder {
    let requested_version = path.into_inner();
    println!("[INFO] GET /api/sign/{}/appinfo", requested_version);
    
    let full_version = match get_full_version(&requested_version) {
        Some(version) => version,
        None => {
            println!("[WARN] Unsupported version: {}", requested_version);
            return web::HttpResponse::BadRequest().body(format!("Unsupported version: {}", requested_version));
        }
    };
    
    let package_json = read_package_json();
    
    let current_version = if let Some(pkg) = &package_json {
        if pkg.version == full_version {
            println!("[INFO] Using package.json version: {}", pkg.version);
            pkg.version.clone()
        } else {
            println!("[INFO] Version mismatch, using full version: {}", full_version);
            full_version.clone()
        }
    } else {
        println!("[INFO] No package.json found, using full version: {}", full_version);
        full_version.clone()
    };
    
    let app_client_version = full_version
        .split('-')
        .last()
        .and_then(|v| v.parse().ok())
        .unwrap_or(39038);
    

    let appinfo = AppInfo {
        AppClientVersion: app_client_version,
        AppId: 1600001615,
        AppIdQrCode: 537313942,
        CurrentVersion: current_version,
        Kernel: "Linux".to_string(),
        MainSigMap: 169742560,
        MiscBitmap: 32764,
        NTLoginType: 1,
        Os: "Linux".to_string(),
        PackageName: "com.tencent.qq".to_string(),
        PtVersion: "2.0.0".to_string(),
        SsoVersion: 19,
        SubAppId: 537313942,
        SubSigMap: 0,
        VendorOs: "linux".to_string(),
        WtLoginSdk: "nt.wtlogin.0.0.1".to_string(),
    };
    
    println!("[INFO] AppInfo response generated for requested version: {} -> full version: {}", requested_version, full_version);
    web::HttpResponse::Ok().json(&appinfo)
}

#[derive(Deserialize)]
struct Params {
    cmd: String,
    src: String,
    seq: i32,
}

#[derive(Serialize)]
struct RespBody {
    platform: String,
    value: Value,
    version: String,
}

#[derive(Serialize)]
struct Value {
    token: String,
    extra: String,
    sign: String,
}

#[derive(Serialize)]
struct AppInfo {
    AppClientVersion: u32,
    AppId: u32,
    AppIdQrCode: u32,
    CurrentVersion: String,
    Kernel: String,
    MainSigMap: u32,
    MiscBitmap: u32,
    NTLoginType: u8,
    Os: String,
    PackageName: String,
    PtVersion: String,
    SsoVersion: u8,
    SubAppId: u32,
    SubSigMap: u32,
    VendorOs: String,
    WtLoginSdk: String,
}

#[derive(Deserialize, Serialize)]
struct PackageJson {
    version: String,
}