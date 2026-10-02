use std::path::Path;

use crate::error::{Error, Result};
use crate::tx::msg::{MemFile, MemPackage, MemPackageType};

/// File names (compared lowercase) included besides the good extensions.
const GOOD_FILES: &[&str] = &[
    "license",
    "license.txt",
    "licence",
    "licence.txt",
    "gno.mod",
];

/// File extensions included.
const GOOD_EXTENSIONS: &[&str] = &[".gno", ".toml", ".md"];

/// File extensions excluded even when they end with a good extension.
const BAD_EXTENSIONS: &[&str] = &[".gen.go"];

/// Subdirectory whose `*_filetest.gno` files are part of the package.
const FILETESTS_DIR: &str = "filetests";

impl MemPackage {
    /// Read a package directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn read_dir(dir: impl AsRef<Path>, pkg_path: &str) -> Result<Self> {
        let dir = dir.as_ref();
        let mut entries = read_sorted_dir(dir)?;
        let mut filetests = None;
        let mut files = Vec::new();

        for entry in entries.drain(..) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir && name == FILETESTS_DIR {
                filetests = Some(entry.path());
                continue;
            }

            if is_dir || name.starts_with('.') || !is_good_file(&name) {
                continue;
            }

            files.push(read_mem_file(&entry.path(), name)?);
        }

        if let Some(filetests_dir) = filetests {
            for entry in read_sorted_dir(&filetests_dir)? {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with("_filetest.gno") {
                    continue;
                }

                if files.iter().any(|f| f.name == name) {
                    return Err(Error::Package(format!(
                        "cannot add {name:?} in filetests: same filename in package dir {:?}",
                        dir.display()
                    )));
                }

                files.push(read_mem_file(&entry.path(), name)?);
            }
        }

        Self::from_files(pkg_path, files)
    }

    /// Assemble a user package from already-read files
    pub fn from_files(pkg_path: &str, files: Vec<MemFile>) -> Result<Self> {
        validate_user_pkg_path(pkg_path)?;

        let mut pkg_name: Option<String> = None;
        let mut filetest_name: Option<String> = None;
        let mut filetest_names_differ = false;

        for file in &files {
            if !file.name.ends_with(".gno") {
                continue;
            }

            let name = extract_package_name_from_body(&file.body)
                .map_err(|e| Error::Package(format!("{}: {e}", file.name)))?;

            if file.name.ends_with("_filetest.gno") {
                // Filetests may have arbitrary package names
                match &filetest_name {
                    None if !filetest_names_differ => filetest_name = Some(name),
                    Some(seen) if *seen != name => {
                        filetest_name = None;
                        filetest_names_differ = true;
                    }
                    _ => {}
                }
            } else {
                let name = name.strip_suffix("_test").unwrap_or(&name).to_owned();
                match &pkg_name {
                    None => pkg_name = Some(name),
                    Some(seen) if *seen != name => {
                        return Err(Error::Package(format!(
                            "{}:0: expected package name {seen:?} but got {name:?}",
                            file.name
                        )));
                    }
                    _ => {}
                }
            }
        }

        if files.is_empty() {
            return Err(Error::Package("package has no files".into()));
        }

        // Only filetests: use their name if consistent, else a placeholder
        let name = pkg_name
            .or(filetest_name)
            .unwrap_or_else(|| FILETESTS_DIR.to_owned());

        Ok(Self {
            name,
            path: pkg_path.to_owned(),
            files,
            r#type: Some(MemPackageType::user_all()),
        })
    }

    /// The package to run a file: a single file under the
    /// `main` package, no path, no type.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn run_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .ok_or_else(|| Error::Package(format!("{:?} is not a file", path.display())))?
            .to_string_lossy()
            .into_owned();
        Ok(Self::run_from_source(name, std::fs::read_to_string(path)?))
    }

    /// The package to run one source body, as a single file named `file_name`
    /// under the `main` package.
    pub fn run_from_source(file_name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: "main".to_owned(),
            path: String::new(),
            files: vec![MemFile {
                name: file_name.into(),
                body: body.into(),
            }],
            r#type: None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn read_sorted_dir(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    // Go's os.ReadDir sorts by file name (byte order)
    entries.sort_by_key(|e| e.file_name());
    Ok(entries)
}

#[cfg(not(target_arch = "wasm32"))]
fn read_mem_file(path: &Path, name: String) -> Result<MemFile> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::Package(format!("{}: {e}", path.display())))?;
    Ok(MemFile { name, body })
}

/// Whether a top-level file of a package directory is part of the package.
fn is_good_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let good = GOOD_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
        || GOOD_FILES.contains(&lower.as_str());
    good && !BAD_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

/// Extract the package name declared by a Gno source file's `package` clause.
pub fn extract_package_name_from_body(body: &str) -> Result<String> {
    let mut rest = body;
    if let Some(stripped) = char::from_u32(0xFEFF).and_then(|bom| rest.strip_prefix(bom)) {
        rest = stripped;
    }

    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map(|i| &after[i + 1..]).unwrap_or("");
        } else if let Some(after) = rest.strip_prefix("/*") {
            let end = after
                .find("*/")
                .ok_or_else(|| Error::Package("comment not terminated".into()))?;
            rest = &after[end + 2..];
        } else {
            break;
        }
    }

    let after_keyword = rest
        .strip_prefix("package")
        .filter(|r| r.starts_with(|c: char| c.is_whitespace()))
        .ok_or_else(|| Error::Package("expected 'package' clause".into()))?;
    let ident = after_keyword.trim_start();
    let len = ident
        .char_indices()
        .take_while(|&(i, c)| c == '_' || c.is_alphabetic() || (i > 0 && c.is_numeric()))
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    match &ident[..len] {
        "" => Err(Error::Package("expected package name".into())),
        "_" => Err(Error::Package("invalid package name _".into())),
        name => Ok(name.to_owned()),
    }
}

/// Check whether `path` is a user package path, e.g. `gno.land/r/demo/hello`.
pub fn is_user_pkg_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3 {
        return false;
    }

    let domain_ok = segments[0].contains('.')
        && segments[0]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'));
    let letter_ok =
        segments[1].len() == 1 && segments[1].starts_with(|c: char| c.is_ascii_lowercase());
    let names_ok = segments[2..]
        .iter()
        .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    domain_ok && letter_ok && names_ok
}

/// Validates that `path` is a user package path, e.g. `gno.land/r/demo/hello`.
fn validate_user_pkg_path(path: &str) -> Result<()> {
    if path.ends_with("_test") {
        return Err(Error::Package(format!(
            "only integration package types may end with \"_test\" but got {path:?}"
        )));
    }

    if path.ends_with("/filetests") {
        return Err(Error::Package(format!(
            "expected user package path but got {path:?} ending in filetests"
        )));
    }

    if !is_user_pkg_path(path) {
        return Err(Error::Package(format!(
            "expected user package path but got {path:?}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, body: &str) -> MemFile {
        MemFile {
            name: name.into(),
            body: body.into(),
        }
    }

    #[test]
    fn package_name_skips_comments_and_bom() {
        // Assert
        assert_eq!(
            extract_package_name_from_body("package hello\n").unwrap(),
            "hello"
        );
        assert_eq!(
            extract_package_name_from_body("\n// doc\n// more\npackage x_y1 // trailing").unwrap(),
            "x_y1"
        );
        assert_eq!(
            extract_package_name_from_body("/* block\n comment */ package hello_test\n").unwrap(),
            "hello_test"
        );

        let bom = char::from_u32(0xFEFF).unwrap();
        assert_eq!(
            extract_package_name_from_body(&format!("{bom}package bom")).unwrap(),
            "bom"
        );
        assert_eq!(
            extract_package_name_from_body("package ünïcode").unwrap(),
            "ünïcode"
        );
    }

    #[test]
    fn package_name_rejects_missing_or_blank_clause() {
        // Assert
        for (body, msg) in [
            ("func main() {}", "expected 'package' clause"),
            ("packagehello", "expected 'package' clause"),
            ("package\n", "expected package name"),
            ("package 1abc", "expected package name"),
            ("package _", "invalid package name _"),
            ("/* never closed\npackage x", "comment not terminated"),
        ] {
            let err = extract_package_name_from_body(body).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("invalid package: {msg}"),
                "{body:?}"
            );
        }
    }

    #[test]
    fn user_pkg_path_rule() {
        // Assert
        for ok in [
            "gno.land/r/demo/hello",
            "gno.land/p/demo/avl",
            "gno.land/r/user_1",
            "x.y/e/g1abc/run",
        ] {
            assert!(is_user_pkg_path(ok), "{ok}");
        }

        for bad in [
            "hello",
            "gno.land/hello",
            "gno.land/rr/x",
            "gno.land/r/",
            "gno.land/r/a/",
            "strings",
            "gno.land/R/x",
            "gno.land/r/we-b",
        ] {
            assert!(!is_user_pkg_path(bad), "{bad}");
        }
    }

    #[test]
    fn from_files_derives_name_and_stamps_type() {
        // Arrange
        let files = vec![
            file("README.md", "# x"),
            file("hello.gno", "package hello"),
            file("hello_test.gno", "package hello_test"),
            file("z_filetest.gno", "package main"),
        ];

        // Act
        let pkg = MemPackage::from_files("gno.land/r/demo/hello", files.clone()).unwrap();

        // Assert
        assert_eq!(pkg.name, "hello");
        assert_eq!(pkg.path, "gno.land/r/demo/hello");
        assert_eq!(pkg.files, files);
        assert_eq!(pkg.r#type, Some(MemPackageType::user_all()));
    }

    #[test]
    fn from_files_uses_filetest_name_when_there_is_nothing_else() {
        // Assert
        let only = MemPackage::from_files(
            "gno.land/r/x/y",
            vec![
                file("a_filetest.gno", "package one"),
                file("b_filetest.gno", "package one"),
            ],
        )
        .unwrap();
        assert_eq!(only.name, "one");

        let mixed = MemPackage::from_files(
            "gno.land/r/x/y",
            vec![
                file("a_filetest.gno", "package one"),
                file("b_filetest.gno", "package two"),
            ],
        )
        .unwrap();
        assert_eq!(mixed.name, "filetests");

        let docs_only =
            MemPackage::from_files("gno.land/r/x/y", vec![file("README.md", "hi")]).unwrap();
        assert_eq!(docs_only.name, "filetests");
    }

    #[test]
    fn from_files_rejects_inconsistent_names_bad_clauses_and_empty_packages() {
        // Assert
        let err = MemPackage::from_files(
            "gno.land/r/x/y",
            vec![file("a.gno", "package a"), file("b.gno", "package b")],
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid package: b.gno:0: expected package name \"a\" but got \"b\""
        );

        let err =
            MemPackage::from_files("gno.land/r/x/y", vec![file("a.gno", "nope")]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid package: a.gno: invalid package: expected 'package' clause"
        );

        let err = MemPackage::from_files("gno.land/r/x/y", vec![]).unwrap_err();
        assert_eq!(err.to_string(), "invalid package: package has no files");
    }

    #[test]
    fn from_files_validates_the_package_path() {
        // Assert
        for (path, msg) in [
            (
                "gno.land/r/x/y_test",
                "only integration package types may end with \"_test\" but got \"gno.land/r/x/y_test\"",
            ),
            (
                "gno.land/r/x/filetests",
                "expected user package path but got \"gno.land/r/x/filetests\" ending in filetests",
            ),
            ("strings", "expected user package path but got \"strings\""),
        ] {
            let err = MemPackage::from_files(path, vec![file("a.gno", "package a")]).unwrap_err();
            assert_eq!(err.to_string(), format!("invalid package: {msg}"));
        }
    }

    #[test]
    fn run_from_source_is_a_main_package_without_type() {
        // Act
        let pkg = MemPackage::run_from_source("stdin.gno", "package main");

        // Assert
        assert_eq!(pkg.name, "main");
        assert_eq!(pkg.path, "");
        assert_eq!(pkg.files, vec![file("stdin.gno", "package main")]);
        assert_eq!(pkg.r#type, None);
    }

    #[test]
    fn good_file_rules() {
        // Assert
        for ok in [
            "a.gno",
            "gno.mod",
            "GNO.MOD",
            "LICENSE",
            "Licence.txt",
            "README.md",
            "x.toml",
        ] {
            assert!(is_good_file(ok), "{ok}");
        }
        for bad in [
            "notes.txt",
            "x.go",
            "x.gen.go",
            "Makefile",
            "license.md.bak",
        ] {
            assert!(!is_good_file(bad), "{bad}");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod fs_tests {
        use super::*;

        fn fixture() -> std::path::PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello")
        }

        #[test]
        fn read_dir_selects_and_orders_files_like_gno() {
            // Act
            let pkg = MemPackage::read_dir(fixture(), "gno.land/r/demo/hello").unwrap();

            // Assert
            let names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(
                names,
                [
                    "LICENSE",
                    "README.md",
                    "gno.mod",
                    "hello.gno",
                    "hello_test.gno",
                    "z_filetest.gno"
                ]
            );
            assert_eq!(pkg.name, "hello");
            assert_eq!(pkg.r#type, Some(MemPackageType::user_all()));
        }

        #[test]
        fn read_dir_rejects_a_filetest_shadowing_a_top_level_file() {
            // Arrange
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("a_filetest.gno"), "package main").unwrap();
            std::fs::create_dir(dir.path().join("filetests")).unwrap();
            std::fs::write(dir.path().join("filetests/a_filetest.gno"), "package main").unwrap();

            // Act
            let err = MemPackage::read_dir(dir.path(), "gno.land/r/x/y").unwrap_err();

            // Assert
            assert!(
                err.to_string()
                    .starts_with("invalid package: cannot add \"a_filetest.gno\" in filetests")
            );
        }

        #[test]
        fn run_from_file_uses_the_base_name() {
            // Act
            let pkg =
                MemPackage::run_from_file(fixture().join("filetests/z_filetest.gno")).unwrap();

            // Assert
            assert_eq!(pkg.files[0].name, "z_filetest.gno");
            assert!(pkg.files[0].body.starts_with("package main"));
        }
    }
}
