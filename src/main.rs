use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use console::style;
use directories::ProjectDirs;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};
use thiserror::Error;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const MAX_ATTEMPTS: u32 = 3;
const ATTEMPT_LOG_FILE: &str = ".attempt_log";
const ENCRYPTED_MARKER: &[u8] = b"SECURE_ENCRYPTED_FILE_V1";

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Max attempts exceeded")]
    MaxAttemptsExceeded,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Clone)]
struct EncryptedPayload {
    nonce: String,
    ciphertext: String,
    salt: String,
    signature: String,
    original_filename: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct AttemptLog {
    file_id: String,
    attempts: u32,
    locked_until: Option<u64>,
}

fn derive_key(password: &str, salt: &SaltString) -> Result<[u8; 32], CryptoError> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];

    argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    argon2
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(key)
}

fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedPayload, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let mut key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let signature = sign_data(&ciphertext, &key)?;

    key.zeroize();

    Ok(EncryptedPayload {
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(&ciphertext),
        salt: salt.to_string(),
        signature,
        original_filename: String::new(),
    })
}

fn decrypt_data(payload: &EncryptedPayload, password: &str) -> Result<Vec<u8>, CryptoError> {
    let salt = SaltString::from_b64(&payload.salt)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let mut key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let ciphertext = BASE64
        .decode(&payload.ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    if !verify_signature(&ciphertext, &payload.signature, &key)? {
        key.zeroize();
        return Err(CryptoError::SignatureVerificationFailed);
    }

    let nonce = BASE64
        .decode(&payload.nonce)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    key.zeroize();

    Ok(plaintext)
}

fn sign_data(data: &[u8], key: &[u8]) -> Result<String, CryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    mac.update(data);
    let result = mac.finalize();
    Ok(BASE64.encode(result.into_bytes()))
}

fn verify_signature(data: &[u8], signature: &str, key: &[u8]) -> Result<bool, CryptoError> {
    let sig_bytes = BASE64
        .decode(signature)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    mac.update(data);

    Ok(mac.verify_slice(&sig_bytes).is_ok())
}

fn get_attempt_log_path() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "secureencrypt", "fileencryptor") {
        let data_dir = proj_dirs.data_dir();
        let _ = fs::create_dir_all(data_dir);
        return data_dir.join(ATTEMPT_LOG_FILE);
    }
    PathBuf::from(ATTEMPT_LOG_FILE)
}

fn read_attempt_log(file_id: &str) -> Option<AttemptLog> {
    let path = get_attempt_log_path();
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    let logs: Vec<AttemptLog> = serde_json::from_str(&content).ok()?;
    logs.into_iter().find(|l| l.file_id == file_id)
}

fn write_attempt_log(log: &AttemptLog) -> Result<(), CryptoError> {
    let path = get_attempt_log_path();
    let mut logs: Vec<AttemptLog> = if path.exists() {
        let content = fs::read_to_string(&path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    if let Some(existing) = logs.iter_mut().find(|l| l.file_id == log.file_id) {
        *existing = log.clone();
    } else {
        logs.push(log.clone());
    }

    let content = serde_json::to_string_pretty(&logs)?;
    fs::write(&path, content)?;
    Ok(())
}

fn check_and_record_attempt(file_id: &str) -> Result<u32, CryptoError> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut log = read_attempt_log(file_id).unwrap_or(AttemptLog {
        file_id: file_id.to_string(),
        attempts: 0,
        locked_until: None,
    });

    if let Some(locked_until) = log.locked_until {
        if current_time < locked_until {
            return Err(CryptoError::MaxAttemptsExceeded);
        }
        log.attempts = 0;
        log.locked_until = None;
    }

    log.attempts += 1;

    if log.attempts >= MAX_ATTEMPTS {
        log.locked_until = Some(current_time + 300);
    }

    write_attempt_log(&log)?;

    Ok(log.attempts)
}

fn clear_attempt_log(file_id: &str) {
    let path = get_attempt_log_path();
    if !path.exists() {
        return;
    }
    let content = fs::read_to_string(&path).ok();
    if let Some(content) = content {
        let mut logs: Vec<AttemptLog> = serde_json::from_str(&content).unwrap_or_default();
        logs.retain(|l| l.file_id != file_id);
        let _ = fs::write(path, serde_json::to_string_pretty(&logs).unwrap_or_default());
    }
}

fn get_file_id(file_path: &Path) -> String {
    let mut hasher = Sha256::new();
    if let Ok(metadata) = fs::metadata(file_path) {
        hasher.update(format!("{:?}", metadata).as_bytes());
    }
    hasher.update(file_path.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

fn print_banner() {
    println!();
    println!("{}", style("╔══════════════════════════════════════════════════════════════╗").cyan());
    println!("{}", style("║          安全文件加密器 v1.0 - Rust 实现                          ║").cyan());
    println!("{}", style("║         高级加密算法 • 自解压可执行文件                        ║").cyan());
    println!("{}", style("╚══════════════════════════════════════════════════════════════╝").cyan());
    println!();
}

fn print_menu(title: &str, options: &[&str]) {
    println!();
    println!("  {} {}", style("▶").green(), style(title).bold().white());
    println!("  {}", style("─".repeat(60)).dim());
    for (i, option) in options.iter().enumerate() {
        println!("  {} {}", style(format!("[{}]", i + 1)).cyan(), style(option).white());
    }
    println!();
}

fn get_input(prompt: &str) -> String {
    print!("  {} {}: ", style("◆").yellow(), style(prompt).white());
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn get_password(prompt: &str) -> String {
    print!("  {} {}: ", style("◆").yellow(), style(prompt).white());
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    println!();
    input.trim().to_string()
}

fn get_current_exe_path() -> Option<PathBuf> {
    env::current_exe().ok()
}

fn encrypt_file_menu() -> Result<(), CryptoError> {
    println!();
    println!("{}", style("  ═══ 文件加密模式 ═══").green().bold());
    println!();

    let file_path = get_input("请输入要加密的文件路径");
    if file_path.is_empty() {
        println!("{}", style("  ✗ 操作已取消").red());
        return Ok(());
    }

    let path = Path::new(&file_path);
    if !path.exists() {
        println!("{}", style("  ✗ 错误：文件不存在").red());
        return Ok(());
    }

    let password = get_password("请输入加密密码（8-32个字符）");
    if password.len() < 8 {
        println!();
        println!("{}", style("  ✗ 密码长度必须至少8个字符").red());
        return Ok(());
    }
    if password.len() > 32 {
        println!();
        println!("{}", style("  ✗ 密码长度不能超过32个字符").red());
        return Ok(());
    }

    let confirm_password = get_password("请再次输入密码进行确认");
    if password != confirm_password {
        println!();
        println!("{}", style("  ═══════════════════════════════════════════════════════════════").red());
        println!("{}", style("  ✗ 两次输入的密码不一致，请重新加密").red());
        println!("{}", style("  ═══════════════════════════════════════════════════════════════").red());
        return Ok(());
    }

    println!();
    println!("{}", style("  ✓ 密码确认成功").green());
    println!("  {} 正在读取文件...", style("●").cyan());
    let file_data = fs::read(path)?;
    let original_filename = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("  {} 正在加密文件...", style("●").cyan());
    let mut payload = encrypt_data(&file_data, &password)?;
    payload.original_filename = original_filename.clone();

    let json_data = serde_json::to_string(&payload)?;
    let mut combined: Vec<u8> = ENCRYPTED_MARKER.iter().copied().collect();
    combined.extend(json_data.bytes());

    let output_path = Path::new(&file_path).with_extension("sfx.exe");

    if let Some(current_exe_path) = get_current_exe_path() {
        println!("  {} 正在创建自解压程序...", style("●").cyan());
        fs::copy(&current_exe_path, &output_path)?;
        let mut sfx_file = fs::OpenOptions::new()
            .append(true)
            .open(&output_path)?;
        sfx_file.write_all(&combined)?;
    } else {
        fs::write(&output_path, combined)?;
        println!();
        println!("{}", style("  ⚠ 警告：无法获取当前程序路径").yellow().bold());
    }

    println!();
    println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").green());
    println!("{}", style("  ║                    ✓ 加密成功                              ║").green());
    println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").green());
    println!();
    println!("  {} 加密后的文件: {}", style("●").green(), style(output_path.display()).white());
    println!("  {} 原始文件名: {}", style("●").green(), style(original_filename).white());
    println!();
    println!("{}", style("  ⚠ 重要提示：解密时需要输入密码！").yellow().bold());
    println!();

    Ok(())
}

fn decrypt_file_menu() -> Result<(), CryptoError> {
    println!();
    println!("{}", style("  ═══ 文件解密模式 ═══").red().bold());
    println!();

    let exe_path = env::current_exe()?;
    let file_id = get_file_id(&exe_path);

    println!("  {} 正在检查尝试次数...", style("●").cyan());

    let log = read_attempt_log(&file_id);
    if let Some(ref l) = log {
        if let Some(locked_until) = l.locked_until {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if current_time < locked_until {
                let remaining = locked_until - current_time;
                println!();
                println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").red());
                println!("{}", style("  ║                    ✗ 访问已被临时锁定                         ║").red());
                println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").red());
                println!();
                println!("  {} 失败次数过多，请等待 {} 秒后重试。", style("●").red(), remaining);
                println!();
                return Ok(());
            }
        }
    }

    println!();
    println!("{}", style("  ⚠ 警告：您只有一次解密尝试机会！").yellow().bold());
    println!("  {} 如果密码错误，文件将无法恢复。", style("●").yellow());
    println!();

    let password = get_password("请输入解密密码");

    match check_and_record_attempt(&file_id) {
        Ok(attempts) => {
            if attempts > 1 {
                println!("  {} 剩余尝试次数: {}", style("●").yellow(), style(MAX_ATTEMPTS - attempts).yellow());
            }
        }
        Err(CryptoError::MaxAttemptsExceeded) => {
            println!();
            println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").red());
            println!("{}", style("  ║                    ✗ 访问已锁定                            ║").red());
            println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").red());
            println!();
            println!("  {} 本次会话失败次数过多。", style("●").red());
            println!();
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    let current_exe = env::current_exe()?;
    let file_data = fs::read(&current_exe)?;

    let marker_pos = file_data
        .windows(ENCRYPTED_MARKER.len())
        .position(|window| window == ENCRYPTED_MARKER);

    let json_data = if let Some(pos) = marker_pos {
        &file_data[pos + ENCRYPTED_MARKER.len()..]
    } else {
        println!();
        println!("{}", style("  ✗ 错误：无效的加密文件格式").red());
        return Ok(());
    };

    let payload: EncryptedPayload = match serde_json::from_slice(json_data) {
        Ok(p) => p,
        Err(_) => {
            println!();
            println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").red());
            println!("{}", style("  ║                    ✗ 解密失败                              ║").red());
            println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").red());
            println!();
            println!("  {} 密码错误，解密尝试次数已用完。", style("●").red());
            println!();
            return Ok(());
        }
    };

    match decrypt_data(&payload, &password) {
        Ok(plaintext) => {
            clear_attempt_log(&file_id);

            let output_dir = env::current_dir()?;
            let output_path = output_dir.join(&payload.original_filename);

            let mut final_path = output_path.clone();
            let mut counter = 1;
            while final_path.exists() {
                let stem = output_path.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".to_string());
                let ext = output_path.extension()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_name = if ext.is_empty() {
                    format!("{}_{}", stem, counter)
                } else {
                    format!("{}_{}.{}", stem, counter, ext)
                };
                final_path = output_dir.join(new_name);
                counter += 1;
            }

            fs::write(&final_path, &plaintext)?;

            println!();
            println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").green());
            println!("{}", style("  ║                    ✓ 解密成功                              ║").green());
            println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").green());
            println!();
            println!("  {} 解密后的文件已保存: {}", style("●").green(), style(final_path.display()).white());
            println!();

            let self_path = env::current_exe()?;
            println!("  {} 正在清理加密文件...", style("●").cyan());
            cleanup_encrypted_artifacts(&self_path);
        }
        Err(_) => {
            println!();
            println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").red());
            println!("{}", style("  ║                    ✗ 解密失败                              ║").red());
            println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").red());
            println!();
            println!("  {} 密码错误或文件已损坏。", style("●").red());
            println!("  {} 这是您最后一次尝试机会。", style("●").red());
            println!();
        }
    }

    Ok(())
}

fn show_about() {
    println!();
    println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").cyan());
    println!("{}", style("  ║                         关于本工具                           ║").cyan());
    println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").cyan());
    println!();
    println!("  {} 安全文件加密器 v1.0", style("●").white());
    println!();
    println!("  {} 密码学算法:", style("●").white());
    println!("    • AES-256-GCM - 对称加密");
    println!("    • Argon2id - 基于密码的密钥派生");
    println!("    • HMAC-SHA256 - 完整性验证");
    println!();
    println!("  {} 安全特性:", style("●").white());
    println!("    • 每次执行仅允许一次解密");
    println!("    • 防暴力破解保护（最多3次尝试）");
    println!("    • 安全内存处理（零化）");
    println!("    • 自包含可执行文件输出");
    println!();
}

fn run_main_menu() {
    loop {
        print_banner();
        print_menu("主菜单", &[
            "加密文件",
            "关于 / 帮助",
            "退出"
        ]);

        let choice = get_input("请选择选项");

        match choice.as_str() {
            "1" => {
                if let Err(e) = encrypt_file_menu() {
                    println!();
                    println!("{} 错误: {}", style("✗").red(), e);
                }
            }
            "2" => {
                show_about();
            }
            "3" | "q" | "Q" => {
                println!();
                println!("  {} 再见！", style("●").green());
                println!();
                break;
            }
            _ => {
                println!();
                println!("{}", style("  ✗ 无效选项，请重试。").red());
                println!();
            }
        }

        if choice != "3" && choice != "q" && choice != "Q" {
            println!("  按回车键继续...");
            let _ = io::stdin().read_line(&mut String::new());
        }
    }
}

fn run_decrypt_mode(should_self_delete: bool) {
    let current_exe = env::current_exe().expect("无法获取当前程序路径");
    let result = decrypt_file_once();

    match result {
        Ok(success_msg) => {
            if !success_msg.is_empty() {
                println!();
                println!("{}", style("  ═══════════════════════════════════════════════════════════════").green());
                println!("{}", style(&format!("  {}", success_msg)).green());
                println!("{}", style("  ═══════════════════════════════════════════════════════════════").green());
            }
        }
        Err(err_msg) => {
            println!();
            println!("{}", style("  ═══════════════════════════════════════════════════════════════").red());
            println!("{}", style(&format!("  {}", err_msg)).red());
            println!("{}", style("  ═══════════════════════════════════════════════════════════════").red());
        }
    }

    println!();
    println!("  按回车键退出...");
    let _ = io::stdin().read_line(&mut String::new());

    if should_self_delete {
        cleanup_encrypted_artifacts(&current_exe);
    }
    process::exit(0);
}

fn decrypt_file_once() -> Result<String, String> {
    println!();
    println!("{}", style("  ═══ 文件解密 ═══").red().bold());
    println!();

    let current_exe = env::current_exe().expect("无法获取当前程序路径");
    let file_data = fs::read(&current_exe).expect("无法读取当前程序");

    let marker_pos = file_data
        .windows(ENCRYPTED_MARKER.len())
        .position(|window| window == ENCRYPTED_MARKER);

    let json_data = if let Some(pos) = marker_pos {
        &file_data[pos + ENCRYPTED_MARKER.len()..]
    } else {
        return Err("✗ 无效的加密文件".to_string());
    };

    let payload: EncryptedPayload = match serde_json::from_slice(json_data) {
        Ok(p) => p,
        Err(_) => {
            return Err("✗ 解密失败：无有效的加密数据".to_string());
        }
    };

    println!();
    println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").yellow());
    println!("{}", style("  ║            ⚠ 重要警告：只有一次解密机会！               ║").yellow());
    println!("{}", style("  ║  • 输入正确的密码才能解密文件                           ║").yellow());
    println!("{}", style("  ║  • 密码错误或取消将永久无法恢复                         ║").yellow());
    println!("{}", style("  ║  • 请务必牢记您的密码，无法找回                          ║").yellow());
    println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").yellow());
    println!();

    let password = get_password("请输入密码");

    println!();
    println!("  {} 正在解密...", style("●").cyan());
    print!("  [");

    let total_steps = 20;
    for _ in 0..total_steps {
        print!("{}", style("█").cyan());
        io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!("]");

    match decrypt_data(&payload, &password) {
        Ok(plaintext) => {
            let output_dir = env::current_dir().map_err(|e| format!("无法获取当前目录: {}", e))?;
            let output_path = output_dir.join(&payload.original_filename);

            let mut final_path = output_path.clone();
            let mut counter = 1;
            while final_path.exists() {
                let stem = output_path.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".to_string());
                let ext = output_path.extension()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_name = if ext.is_empty() {
                    format!("{}_{}", stem, counter)
                } else {
                    format!("{}_{}.{}", stem, counter, ext)
                };
                final_path = output_dir.join(new_name);
                counter += 1;
            }

            println!();
            println!("  {} 正在释放文件...", style("●").cyan());
            print!("  [");

            for _ in 0..total_steps {
                print!("{}", style("█").green());
                io::stdout().flush().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            println!("]");

            fs::write(&final_path, &plaintext).map_err(|e| format!("写入文件失败: {}", e))?;

            Ok(format!("✓ 解密成功！文件已保存: {}", final_path.display()))
        }
        Err(_) => {
            Err("✗ 密码错误！".to_string())
        }
    }
}

fn is_encrypted_file(path: &Path) -> bool {
    if let Ok(data) = fs::read(path) {
        data.windows(ENCRYPTED_MARKER.len()).any(|window| window == ENCRYPTED_MARKER)
    } else {
        false
    }
}

fn run_marker_path(current_exe: &Path) -> Option<PathBuf> {
    let exe_stem = current_exe.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("secure_exe");
    current_exe.parent()
        .map(|p| p.join(format!(".{}.run", exe_stem)))
}

fn check_single_run(current_exe: &Path) -> bool {
    let run_marker = run_marker_path(current_exe);
    if let Some(marker_path) = run_marker {
        if marker_path.exists() {
            return false;
        }
        return fs::write(&marker_path, b"1").is_ok();
    }
    false
}

#[cfg(windows)]
fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

fn cleanup_encrypted_artifacts(current_exe: &Path) {
    let marker_path = run_marker_path(current_exe);

    #[cfg(windows)]
    {
        let exe = escape_powershell_single_quoted(&current_exe.to_string_lossy());
        let marker = marker_path.as_ref()
            .map(|p| escape_powershell_single_quoted(&p.to_string_lossy()))
            .unwrap_or_default();

        let script = format!(
            "$exe='{exe}';$marker='{marker}';\
            for($i=0;$i -lt 200;$i++){{\
            try{{Remove-Item -LiteralPath $exe -Force -ErrorAction Stop}}catch{{}};\
            if(-not (Test-Path -LiteralPath $exe)){{break}};\
            Start-Sleep -Milliseconds 100\
            }};\
            if($marker -and (Test-Path -LiteralPath $marker)){{\
            try{{Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue}}catch{{}}\
            }}"
        );

        let _ = process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .spawn();
    }

    #[cfg(not(windows))]
    {
        let _ = fs::remove_file(current_exe);
        if let Some(marker_path) = marker_path {
            let _ = fs::remove_file(marker_path);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let current_exe = env::current_exe().expect("无法获取当前程序路径");
    let exe_data = fs::read(&current_exe).expect("无法读取当前程序");

    let is_encrypted_exe = exe_data
        .windows(ENCRYPTED_MARKER.len())
        .any(|window| window == ENCRYPTED_MARKER);

    if is_encrypted_exe {
        if !check_single_run(&current_exe) {
            println!();
            println!("{}", style("  ╔══════════════════════════════════════════════════════════════╗").red());
            println!("{}", style("  ║            ✗ 检测到重复运行！                       ║").red());
            println!("{}", style("  ╚══════════════════════════════════════════════════════════════╝").red());
            println!();
            println!("  此加密文件已运行过一次，无法再次运行。");
            println!("  请勿重复运行此程序。");
            println!();
            cleanup_encrypted_artifacts(&current_exe);
            process::exit(1);
        }

        run_decrypt_mode(true);
        return;
    }

    if args.len() > 1 && args[1] == "--decrypt" {
        run_decrypt_mode(false);
        return;
    }

    if args.len() > 1 {
        let exe_path = &args[1];
        let path = Path::new(exe_path);

        if !is_encrypted_file(path) {
            println!("{}", style("✗ 无效或已损坏的加密文件").red());
            process::exit(1);
        }

        run_decrypt_mode(false);
        return;
    }

    run_encrypt_mode();
}

fn run_encrypt_mode() {
    print_banner();
    println!();
    println!("  {} 欢迎使用文件加密工具", style("●").cyan());
    println!();

    match encrypt_file_menu() {
        Ok(_) => {}
        Err(e) => {
            println!();
            println!("{} 错误: {}", style("✗").red(), e);
        }
    }

    println!();
    println!("  按回车键退出...");
    let _ = io::stdin().read_line(&mut String::new());
}
