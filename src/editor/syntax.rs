use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxType {
    Bash,
    Yaml,
    Json,
    Toml,
    IniConf,
    Python,
    Rust,
    C,
    Sql,
    Markdown,
    HtmlXml,
    PlainText,
}

impl SyntaxType {
    pub fn name(&self) -> &'static str {
        match self {
            SyntaxType::Bash => "Bash / Shell",
            SyntaxType::Yaml => "YAML",
            SyntaxType::Json => "JSON",
            SyntaxType::Toml => "TOML",
            SyntaxType::IniConf => "INI / Conf / Systemd",
            SyntaxType::Python => "Python",
            SyntaxType::Rust => "Rust",
            SyntaxType::C => "C / C++",
            SyntaxType::Sql => "SQL",
            SyntaxType::Markdown => "Markdown",
            SyntaxType::HtmlXml => "HTML / XML",
            SyntaxType::PlainText => "Plain Text",
        }
    }
}

pub struct SyntaxRules {
    pub keywords: &'static [&'static str],
    pub types_builtins: &'static [&'static str],
    pub line_comment: Option<&'static str>,
    pub multi_comment: Option<(&'static str, &'static str)>,
    pub case_insensitive: bool,
    pub highlight_numbers: bool,
    pub highlight_strings: bool,
}

impl SyntaxType {
    pub fn rules(&self) -> SyntaxRules {
        match self {
            SyntaxType::Bash => SyntaxRules {
                keywords: &[
                    "if", "then", "else", "elif", "fi", "case", "esac", "for", "while", "until",
                    "do", "done", "in", "function", "select", "time", "echo", "exit", "return",
                    "export", "source", "local", "readonly", "set", "unset", "alias",
                ],
                types_builtins: &[
                    "true", "false", "sudo", "systemctl", "journalctl", "ssh", "scp", "curl",
                    "wget", "tar", "chmod", "chown", "mkdir", "rm", "cp", "mv", "cat", "grep",
                    "sed", "awk", "find", "ps", "kill", "docker", "git",
                ],
                line_comment: Some("#"),
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Yaml => SyntaxRules {
                keywords: &[
                    "true", "false", "yes", "no", "null", "on", "off", "version", "services",
                    "image", "ports", "environment", "volumes", "restart", "networks", "deploy",
                    "build",
                ],
                types_builtins: &[],
                line_comment: Some("#"),
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Json => SyntaxRules {
                keywords: &["true", "false", "null"],
                types_builtins: &[],
                line_comment: Some("//"),
                multi_comment: Some(("/*", "*/")),
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Toml => SyntaxRules {
                keywords: &["true", "false"],
                types_builtins: &[],
                line_comment: Some("#"),
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::IniConf => SyntaxRules {
                keywords: &["true", "false", "on", "off", "yes", "no", "enabled", "disabled"],
                types_builtins: &[],
                line_comment: Some("#"),
                multi_comment: None,
                case_insensitive: true,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Python => SyntaxRules {
                keywords: &[
                    "def", "class", "import", "from", "as", "return", "if", "elif", "else",
                    "for", "while", "try", "except", "finally", "with", "raise", "yield",
                    "lambda", "pass", "break", "continue", "global", "nonlocal", "assert",
                    "async", "await", "and", "or", "not", "in", "is",
                ],
                types_builtins: &[
                    "int", "float", "str", "bool", "list", "dict", "set", "tuple", "bytes",
                    "None", "True", "False", "self", "cls", "print", "len", "range",
                ],
                line_comment: Some("#"),
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Rust => SyntaxRules {
                keywords: &[
                    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else",
                    "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop",
                    "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
                    "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
                    "where", "while",
                ],
                types_builtins: &[
                    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64",
                    "u128", "usize", "f32", "f64", "bool", "char", "str", "String", "Vec",
                    "Option", "Some", "None", "Result", "Ok", "Err", "Box", "Rc", "Arc",
                ],
                line_comment: Some("//"),
                multi_comment: Some(("/*", "*/")),
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::C => SyntaxRules {
                keywords: &[
                    "auto", "break", "case", "char", "const", "continue", "default", "do",
                    "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
                    "int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
                    "static", "struct", "switch", "typedef", "union", "unsigned", "void",
                    "volatile", "while", "class", "namespace", "public", "private", "protected",
                    "template", "typename", "virtual", "override", "new", "delete", "nullptr",
                    "true", "false",
                ],
                types_builtins: &[
                    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
                    "int32_t", "int64_t", "size_t", "ssize_t", "std", "string", "vector", "map",
                ],
                line_comment: Some("//"),
                multi_comment: Some(("/*", "*/")),
                case_insensitive: false,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Sql => SyntaxRules {
                keywords: &[
                    "select", "from", "where", "insert", "into", "update", "delete", "create",
                    "table", "drop", "alter", "add", "join", "left", "right", "inner", "outer",
                    "on", "group", "by", "order", "having", "limit", "offset", "as", "distinct",
                    "union", "all", "and", "or", "not", "in", "is", "null", "like", "case",
                    "when", "then", "else", "end", "primary", "key", "foreign", "references",
                    "index", "default", "values", "set", "asc", "desc",
                ],
                types_builtins: &[
                    "int", "integer", "varchar", "char", "text", "boolean", "date", "datetime",
                    "timestamp", "decimal", "numeric", "float", "blob",
                ],
                line_comment: Some("--"),
                multi_comment: Some(("/*", "*/")),
                case_insensitive: true,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::Markdown => SyntaxRules {
                keywords: &[],
                types_builtins: &[],
                line_comment: None,
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: false,
                highlight_strings: false,
            },
            SyntaxType::HtmlXml => SyntaxRules {
                keywords: &["doctype", "html", "head", "body", "div", "span", "p", "a", "script", "style"],
                types_builtins: &[],
                line_comment: None,
                multi_comment: Some(("<!--", "-->")),
                case_insensitive: true,
                highlight_numbers: true,
                highlight_strings: true,
            },
            SyntaxType::PlainText => SyntaxRules {
                keywords: &[],
                types_builtins: &[],
                line_comment: None,
                multi_comment: None,
                case_insensitive: false,
                highlight_numbers: false,
                highlight_strings: false,
            },
        }
    }
}

pub fn detect_syntax(path: Option<&Path>, content: &str) -> SyntaxType {
    if let Some(p) = path {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_lowercase();
            match lower.as_str() {
                "dockerfile" | "makefile" | "pkgbuild" | ".bashrc" | ".bash_profile"
                | ".profile" | ".zshrc" | ".env" => return SyntaxType::Bash,
                "cargo.lock" => return SyntaxType::Toml,
                "hosts" | "resolv.conf" | "nginx.conf" | "sshd_config" => {
                    return SyntaxType::IniConf
                }
                _ => {}
            }
        }

        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "sh" | "bash" | "zsh" | "env" => return SyntaxType::Bash,
                "yml" | "yaml" => return SyntaxType::Yaml,
                "json" | "jsonc" => return SyntaxType::Json,
                "toml" => return SyntaxType::Toml,
                "ini" | "conf" | "cfg" | "cnf" | "service" | "timer" | "desktop"
                | "properties" => return SyntaxType::IniConf,
                "py" | "pyw" => return SyntaxType::Python,
                "rs" => return SyntaxType::Rust,
                "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => return SyntaxType::C,
                "sql" => return SyntaxType::Sql,
                "md" | "markdown" => return SyntaxType::Markdown,
                "html" | "htm" | "xml" | "svg" => return SyntaxType::HtmlXml,
                _ => {}
            }
        }
    }

    // Shebang fallback
    if content.starts_with("#!") {
        let first_line = content.lines().next().unwrap_or("");
        if first_line.contains("sh") || first_line.contains("bash") || first_line.contains("zsh") {
            return SyntaxType::Bash;
        }
        if first_line.contains("python") {
            return SyntaxType::Python;
        }
    }

    SyntaxType::PlainText
}

pub fn is_known_binary_extension(ext: &str) -> bool {
    let lower = ext.to_lowercase();
    matches!(
        lower.as_str(),
        "gz" | "tgz" | "bz2" | "tbz2" | "xz" | "txz" | "zst" | "zip" | "tar" | "7z" | "rar"
            | "iso" | "rpm" | "deb" | "apk" | "jar" | "war"
            | "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "bmp" | "svgz"
            | "mp3" | "mp4" | "mkv" | "avi" | "mov" | "wav" | "flac"
            | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
            | "bin" | "exe" | "dll" | "so" | "dylib" | "o" | "a" | "pyc" | "pyo" | "class"
            | "wasm" | "db" | "sqlite" | "sqlite3"
    )
}

pub fn is_binary_buffer(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // Check known magic bytes
    if buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
        // Gzip magic
        return true;
    }
    if buf.len() >= 4 && buf[0] == 0x50 && buf[1] == 0x4b && buf[2] == 0x03 && buf[3] == 0x04 {
        // Zip magic
        return true;
    }
    if buf.len() >= 4 && buf[0] == 0x7f && buf[1] == b'E' && buf[2] == b'L' && buf[3] == b'F' {
        // ELF binary magic
        return true;
    }
    if buf.len() >= 2 && buf[0] == b'M' && buf[1] == b'Z' {
        // DOS/PE binary magic
        return true;
    }
    if buf.len() >= 3 && buf[0] == b'B' && buf[1] == b'Z' && buf[2] == b'h' {
        // Bzip2 magic
        return true;
    }
    if buf.len() >= 6 && &buf[0..6] == b"7z\xbc\xaf'\x1c" {
        // 7z magic
        return true;
    }

    // Check first 8 KB for null bytes (\0)
    let check_len = buf.len().min(8192);
    buf[..check_len].iter().any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_detect_syntax_by_extension() {
        assert_eq!(detect_syntax(Some(&PathBuf::from("deploy.sh")), ""), SyntaxType::Bash);
        assert_eq!(detect_syntax(Some(&PathBuf::from("config.yaml")), ""), SyntaxType::Yaml);
        assert_eq!(detect_syntax(Some(&PathBuf::from("data.json")), ""), SyntaxType::Json);
        assert_eq!(detect_syntax(Some(&PathBuf::from("Cargo.toml")), ""), SyntaxType::Toml);
        assert_eq!(detect_syntax(Some(&PathBuf::from("server.py")), ""), SyntaxType::Python);
        assert_eq!(detect_syntax(Some(&PathBuf::from("main.rs")), ""), SyntaxType::Rust);
        assert_eq!(detect_syntax(Some(&PathBuf::from("main.c")), ""), SyntaxType::C);
        assert_eq!(detect_syntax(Some(&PathBuf::from("query.sql")), ""), SyntaxType::Sql);
        assert_eq!(detect_syntax(Some(&PathBuf::from("README.md")), ""), SyntaxType::Markdown);
        assert_eq!(detect_syntax(Some(&PathBuf::from("index.html")), ""), SyntaxType::HtmlXml);
        assert_eq!(detect_syntax(Some(&PathBuf::from("notes.txt")), ""), SyntaxType::PlainText);
    }

    #[test]
    fn test_detect_syntax_by_filename() {
        assert_eq!(detect_syntax(Some(&PathBuf::from("Dockerfile")), ""), SyntaxType::Bash);
        assert_eq!(detect_syntax(Some(&PathBuf::from("Makefile")), ""), SyntaxType::Bash);
        assert_eq!(detect_syntax(Some(&PathBuf::from(".bashrc")), ""), SyntaxType::Bash);
        assert_eq!(detect_syntax(Some(&PathBuf::from("nginx.conf")), ""), SyntaxType::IniConf);
        assert_eq!(detect_syntax(Some(&PathBuf::from("hosts")), ""), SyntaxType::IniConf);
    }

    #[test]
    fn test_detect_syntax_by_shebang() {
        assert_eq!(detect_syntax(None, "#!/bin/bash\necho hello"), SyntaxType::Bash);
        assert_eq!(detect_syntax(None, "#!/usr/bin/env python3\nprint('hello')"), SyntaxType::Python);
        assert_eq!(detect_syntax(None, "just random plain text"), SyntaxType::PlainText);
    }

    #[test]
    fn test_binary_detection() {
        assert!(is_known_binary_extension("gz"));
        assert!(is_known_binary_extension("tar"));
        assert!(is_known_binary_extension("zip"));
        assert!(is_known_binary_extension("png"));
        assert!(is_known_binary_extension("bin"));
        assert!(!is_known_binary_extension("rs"));
        assert!(!is_known_binary_extension("py"));
        assert!(!is_known_binary_extension("sh"));

        // Gzip magic
        assert!(is_binary_buffer(&[0x1f, 0x8b, 0x08, 0x00]));
        // Null byte in text
        assert!(is_binary_buffer(b"hello\x00world"));
        // Plain text is NOT binary
        assert!(!is_binary_buffer(b"#!/bin/bash\necho 'hello world'\n"));
    }
}

