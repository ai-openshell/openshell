// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result, WrapErr};

pub(super) struct TlsFiles {
    certificate: PathBuf,
    key: PathBuf,
}

pub(super) struct TlsPem {
    pub(super) certificate: Vec<u8>,
    pub(super) key: Vec<u8>,
    pub(super) generation: Option<PathBuf>,
}

impl TlsFiles {
    pub(super) fn new(certificate: PathBuf, key: PathBuf) -> Self {
        Self { certificate, key }
    }

    pub(super) fn read_initial(&self) -> Result<TlsPem> {
        self.load(self.projected_generation(None))
    }

    pub(super) fn read(&self, previous_generation: Option<&Path>) -> Result<Option<TlsPem>> {
        let generation = self.projected_generation(previous_generation);
        if generation
            .as_ref()
            .is_some_and(|generation| Some(generation.directory.as_path()) == previous_generation)
        {
            return Ok(None);
        }
        self.load(generation).map(Some)
    }

    fn projected_generation(&self, previous_generation: Option<&Path>) -> Option<Generation<'_>> {
        let parent = self.certificate.parent()?;
        if self.key.parent()? != parent {
            return None;
        }
        let marker = Path::new("..data");
        let directory = parent.join(fs::read_link(parent.join(marker)).ok()?);
        let certificate = self.certificate.file_name()?;
        let key = self.key.file_name()?;
        if Some(directory.as_path()) != previous_generation
            && (fs::read_link(&self.certificate).ok()? != marker.join(certificate)
                || fs::read_link(&self.key).ok()? != marker.join(key))
        {
            return None;
        }
        Some(Generation {
            directory,
            certificate,
            key,
        })
    }

    fn load(&self, generation: Option<Generation<'_>>) -> Result<TlsPem> {
        let Some(generation) = generation else {
            return read_pem(&self.certificate, &self.key, None);
        };
        let candidate = generation.read();
        if candidate.is_err()
            && let Some(current) = self.projected_generation(None)
            && current.directory != generation.directory
        {
            // Kubelet may remove the old directory as soon as it publishes the new one.
            return current.read();
        }
        candidate
    }
}

struct Generation<'a> {
    directory: PathBuf,
    certificate: &'a OsStr,
    key: &'a OsStr,
}

impl Generation<'_> {
    fn read(&self) -> Result<TlsPem> {
        // Both opens use the same generation even if kubelet swaps the public symlink.
        read_pem(
            &self.directory.join(self.certificate),
            &self.directory.join(self.key),
            Some(self.directory.clone()),
        )
    }
}

fn read_pem(certificate: &Path, key: &Path, generation: Option<PathBuf>) -> Result<TlsPem> {
    Ok(TlsPem {
        certificate: fs::read(certificate)
            .into_diagnostic()
            .wrap_err("cannot read certificate file")?,
        key: fs::read(key)
            .into_diagnostic()
            .wrap_err("cannot read private key file")?,
        generation,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn reads_one_projection_and_resamples_when_kubelet_removes_it() {
        let temporary = tempfile::tempdir().unwrap();
        let mount = temporary.path();
        let original = mount.join("..original");
        let replacement = mount.join("..replacement");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&replacement).unwrap();
        for name in ["tls.crt", "tls.key"] {
            fs::write(original.join(name), format!("original {name}")).unwrap();
            fs::write(replacement.join(name), format!("replacement {name}")).unwrap();
            symlink(Path::new("..data").join(name), mount.join(name)).unwrap();
        }
        symlink("..original", mount.join("..data")).unwrap();

        let files = TlsFiles::new(mount.join("tls.crt"), mount.join("tls.key"));
        let sampled = files.projected_generation(None).unwrap();
        symlink("..replacement", mount.join("..data_tmp")).unwrap();
        fs::rename(mount.join("..data_tmp"), mount.join("..data")).unwrap();

        let old_pem = sampled.read().unwrap();
        assert_eq!(old_pem.certificate, b"original tls.crt");
        assert_eq!(old_pem.key, b"original tls.key");

        fs::remove_dir_all(original).unwrap();
        let new_pem = files.load(Some(sampled)).unwrap();
        assert_eq!(new_pem.certificate, b"replacement tls.crt");
        assert_eq!(new_pem.key, b"replacement tls.key");
        assert_eq!(new_pem.generation.as_deref(), Some(replacement.as_path()));
        assert!(files.read(new_pem.generation.as_deref()).unwrap().is_none());
    }
}
