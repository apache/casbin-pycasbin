# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import contextlib
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release


class ReleaseSafetyTest(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        subprocess.run(["git", "init", "-q"], check=True)
        for key, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid")):
            subprocess.run(["git", "config", key, value], check=True)
        text = '{"version":"1.2.3"}\n' if release.MANIFEST.endswith("json") else '[project]\nversion="1.2.3"\n'
        Path(release.MANIFEST).write_text(text, encoding="utf8")
        for filename in ("LICENSE", "NOTICE", "DISCLAIMER", "README.md"):
            Path(filename).write_text(
                "Fixture for command safety, not a legal compliance assessment.\n", encoding="utf8"
            )
        self.commit()
        for tag in ("v1.2.3", "v1.2.3-rc1"):
            subprocess.run(["git", "tag", tag], check=True)
        self.name = release.metadata("v1.2.3")[2]
        # A different gzip compression level proves verify preserves originals.
        self.original = gzip.compress(release.source("v1.2.3", self.name), compresslevel=1, mtime=0)

    def tearDown(self):
        os.chdir(self.previous)
        self.directory.cleanup()

    def commit(self):
        subprocess.run(["git", "add", "-A"], check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], check=True)

    def invoke(self, *args):
        with patch.object(sys, "argv", ["release.py", *args]), contextlib.redirect_stdout(io.StringIO()):
            release.main()

    def downloaded(self, url):
        if url.endswith("KEYS"):
            return b"MOCK KEY: cryptographic verification is covered by later real RC checks"
        if url.endswith(".sha512"):
            return (hashlib.sha512(self.original).hexdigest() + "  " + self.name + ".tar.gz\n").encode()
        if url.endswith(".asc"):
            return b"MOCK SIGNATURE"
        return self.original

    def test_strict_tags(self):
        for tag in ("master", "v1", "v1.2.3-rc0", "v1.2.3-beta1", "v1.2.3-rc1/x", "v1.2.3 "):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.metadata(tag)

    def test_version_must_be_committed(self):
        subprocess.run(["git", "tag", "v1.2.4-rc1"], check=True)
        with self.assertRaises(ValueError):
            release.metadata("v1.2.4-rc1")

    def test_reproducible_candidate(self):
        self.invoke("archive", "v1.2.3-rc1", "one")
        self.invoke("archive", "v1.2.3-rc1", "two")
        filename = self.name + ".tar.gz"
        self.assertEqual((Path("one") / filename).read_bytes(), (Path("two") / filename).read_bytes())

    def test_refuses_overwrite(self):
        Path("existing").mkdir()
        Path("existing/sentinel").write_bytes(b"preserve")
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3-rc1", "existing")
        self.assertEqual(Path("existing/sentinel").read_bytes(), b"preserve")

    def test_final_cannot_be_rebuilt(self):
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3", "final")

    def test_rc_cannot_be_promoted(self):
        with self.assertRaises(ValueError), patch.object(release, "download") as download:
            self.invoke("verify", "v1.2.3-rc1", "promotion")
        download.assert_not_called()

    def test_missing_legal_file(self):
        Path("NOTICE").unlink()
        self.commit()
        subprocess.run(["git", "tag", "v1.2.3-rc2"], check=True)
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3-rc2", "missing")

    def test_rejects_unsafe_archive_entries(self):
        for path, link in (("../escape", False), (self.name + "/../escape", False), (self.name + "/link", True)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                entry = tarfile.TarInfo(path)
                if link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "../../escape"
                archive.addfile(entry)
            with self.subTest(path=path), self.assertRaises(ValueError):
                release.inventory(buffer.getvalue(), self.name)

    def test_preserves_original_bytes_after_mock_verification(self):
        with (
            patch.object(release, "download", side_effect=self.downloaded),
            patch.object(release, "verify_signature") as gpg,
        ):
            self.invoke("verify", "v1.2.3", "approved")
        self.assertEqual(gpg.call_count, 1)
        self.assertEqual((Path("approved") / (self.name + ".tar.gz")).read_bytes(), self.original)
        self.assertTrue((Path("approved/source") / self.name / release.MANIFEST).is_file())

    def test_checksum_failure_stops_before_gpg_and_build(self):
        def bad(url):
            return (
                ("0" * 128 + "  " + self.name + ".tar.gz\n").encode()
                if url.endswith(".sha512")
                else self.downloaded(url)
            )

        with patch.object(release, "download", side_effect=bad), patch.object(release, "verify_signature") as gpg:
            with self.assertRaises(ValueError):
                self.invoke("verify", "v1.2.3", "bad-checksum")
        gpg.assert_not_called()
        self.assertFalse(Path("bad-checksum/source").exists())

    def test_signature_failure_stops_before_build(self):
        with patch.object(release, "download", side_effect=self.downloaded):
            with patch.object(release, "verify_signature", side_effect=subprocess.CalledProcessError(1, "gpg")):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke("verify", "v1.2.3", "bad-signature")
        self.assertFalse(Path("bad-signature/source").exists())

    def test_different_approved_source_is_rejected(self):
        Path("README.md").write_text("Changed source\n", encoding="utf8")
        self.commit()
        subprocess.run(["git", "tag", "-f", "v1.2.3"], check=True, stdout=subprocess.DEVNULL)
        with patch.object(release, "download", side_effect=self.downloaded), patch.object(release, "verify_signature"):
            with self.assertRaises(ValueError):
                self.invoke("verify", "v1.2.3", "different-source")
        self.assertFalse(Path("different-source/source").exists())

    def python_sdist_fixture(self, change=None):
        Path("casbin").mkdir(exist_ok=True)
        Path("casbin/__init__.py").write_bytes(b"# fixture\n")
        Path(release.MANIFEST).write_text(
            '[project]\nname="fixture"\nversion="1.2.3"\nlicense={text="Apache-2.0"}\n', encoding="utf8"
        )
        files = {
            name: Path(name).read_bytes()
            for name in (release.MANIFEST, "LICENSE", "NOTICE", "DISCLAIMER", "README.md", "casbin/__init__.py")
        }
        files["PKG-INFO"] = (
            b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.2.3\nLicense: Apache-2.0\n\n"
            + Path("README.md").read_bytes()
        )
        if change:
            change(files)
        with tarfile.open("fixture.tar.gz", "w:gz") as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo("fixture-1.2.3/" + name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def test_python_sdist_preserves_source_and_legal_files(self):
        self.python_sdist_fixture()
        release.check_python("fixture.tar.gz")

    def test_python_sdist_preserves_unicode_description(self):
        Path("README.md").write_text("Apache Casbin — test\n", encoding="utf8")
        self.python_sdist_fixture()
        release.check_python("fixture.tar.gz")

    def test_python_sdist_accepts_metadata_crlf_without_collapsing_paragraphs(self):
        Path("README.md").write_text("First paragraph.\n\nSecond paragraph.\n", encoding="utf8", newline="\n")
        self.python_sdist_fixture(lambda files: files.update({"PKG-INFO": files["PKG-INFO"].replace(b"\n", b"\r\n")}))
        release.check_python("fixture.tar.gz")

    def test_python_sdist_accepts_equivalent_specifier_order(self):
        def add_requirements(files):
            text = Path(release.MANIFEST).read_text(encoding="utf8")
            text += 'dependencies=["example>=1.0,<2"]\n'
            Path(release.MANIFEST).write_text(text, encoding="utf8", newline="\n")
            files[release.MANIFEST] = text.encode()
            files["PKG-INFO"] = files["PKG-INFO"].replace(
                b"License: Apache-2.0\n", b"License: Apache-2.0\nRequires-Dist: example<2,>=1.0\n"
            )

        self.python_sdist_fixture(add_requirements)
        release.check_python("fixture.tar.gz")

    def test_python_sdist_rejects_added_dependency(self):
        self.python_sdist_fixture(
            lambda files: files.update(
                {
                    "PKG-INFO": files["PKG-INFO"].replace(
                        b"License: Apache-2.0\n", b"License: Apache-2.0\nRequires-Dist: unsafe>=1\n"
                    )
                }
            )
        )
        with self.assertRaises(ValueError):
            release.check_python("fixture.tar.gz")

    def test_python_sdist_rejects_missing_source(self):
        self.python_sdist_fixture(lambda files: files.pop("casbin/__init__.py"))
        with self.assertRaises(ValueError):
            release.check_python("fixture.tar.gz")

    def test_python_sdist_rejects_changed_legal_file(self):
        self.python_sdist_fixture(lambda files: files.update({"NOTICE": b"wrong"}))
        with self.assertRaises(ValueError):
            release.check_python("fixture.tar.gz")

    def test_python_sdist_rejects_changed_identity(self):
        self.python_sdist_fixture(
            lambda files: files.update({"PKG-INFO": files["PKG-INFO"].replace(b"Version: 1.2.3", b"Version: 9.9.9")})
        )
        with self.assertRaises(ValueError):
            release.check_python("fixture.tar.gz")

    def python_wheel_fixture(self, change=None):
        Path("casbin").mkdir(exist_ok=True)
        Path("casbin/__init__.py").write_bytes(b"# fixture\n")
        Path(release.MANIFEST).write_text(
            '[project]\nname="fixture"\nversion="1.2.3"\nlicense={text="Apache-2.0"}\n', encoding="utf8"
        )
        prefix = "fixture-1.2.3.dist-info"
        files = {"casbin/__init__.py": Path("casbin/__init__.py").read_bytes()}
        files.update(
            {prefix + "/licenses/" + name: Path(name).read_bytes() for name in ("LICENSE", "NOTICE", "DISCLAIMER")}
        )
        files[prefix + "/METADATA"] = (
            b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.2.3\nLicense-Expression: Apache-2.0\n\n"
            + Path("README.md").read_bytes()
        )
        files[prefix + "/WHEEL"] = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        if change:
            change(files)
        record = io.StringIO()
        writer = release.csv.writer(record)
        for name, data in files.items():
            digest = (
                "sha256="
                + release.base64.urlsafe_b64encode(release.hashlib.sha256(data).digest()).rstrip(b"=").decode()
            )
            writer.writerow((name, digest, len(data)))
        writer.writerow((prefix + "/RECORD", "", ""))
        files[prefix + "/RECORD"] = record.getvalue().encode()
        with release.zipfile.ZipFile("fixture.whl", "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)

    def test_python_wheel_preserves_source_legal_and_record(self):
        self.python_wheel_fixture()
        release.check_python("fixture.whl")

    def test_python_wheel_rejects_missing_legal_file(self):
        self.python_wheel_fixture(lambda files: files.pop("fixture-1.2.3.dist-info/licenses/DISCLAIMER"))
        with self.assertRaises(ValueError):
            release.check_python("fixture.whl")

    def test_python_wheel_rejects_changed_source(self):
        self.python_wheel_fixture(lambda files: files.update({"casbin/__init__.py": b"wrong"}))
        with self.assertRaises(ValueError):
            release.check_python("fixture.whl")

    def test_python_wheel_rejects_checkout_files_outside_library(self):
        self.python_wheel_fixture(lambda files: files.update({"README.md": Path("README.md").read_bytes()}))
        with self.assertRaises(ValueError):
            release.check_python("fixture.whl")

    def test_python_wheel_rejects_changed_description(self):
        self.python_wheel_fixture(
            lambda files: files.update(
                {"fixture-1.2.3.dist-info/METADATA": files["fixture-1.2.3.dist-info/METADATA"] + b"wrong"}
            )
        )
        with self.assertRaises(ValueError):
            release.check_python("fixture.whl")

    def test_python_wheel_rejects_unsafe_path(self):
        self.python_wheel_fixture(lambda files: files.update({"../outside": b"unsafe"}))
        with self.assertRaises(ValueError):
            release.check_python("fixture.whl")


if __name__ == "__main__":
    unittest.main()
