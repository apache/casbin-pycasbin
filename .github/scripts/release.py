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

import argparse
import base64
import csv
import zipfile
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT = "casbin-pycasbin"
COMPONENT = "pycasbin"
MANIFEST = "pyproject.toml"
ASF_BASE = "https://downloads.apache.org/incubator/casbin"


def git(*args):
    return subprocess.check_output(["git", *args])


def metadata(tag):
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)(-rc[1-9]\d*)?", tag)
    if not match:
        raise ValueError("Use vX.Y.Z or vX.Y.Z-rcN (N >= 1)")
    version, rc = match.groups()
    manifest = git("show", f"{tag}:{MANIFEST}")
    actual = (
        json.loads(manifest)["version"]
        if MANIFEST.endswith("json")
        else tomllib.loads(manifest.decode())["project"]["version"]
    )
    if actual != version:
        raise ValueError(f"Commit version {actual} does not match {version}; no version stamping")
    name = f"apache-{PROJECT}-{version}-incubating-src"
    return version, bool(rc), name


def inventory(data, name):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            parts = Path(member.name).parts
            if not parts or parts[0] != name or ".." in parts or "\\" in member.name:
                raise ValueError(f"Unexpected archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or member.name in result:
                raise ValueError(f"Link, special file or duplicate: {member.name}")
            result[member.name] = (archive.extractfile(member).read(), member.mode & 0o777)
    for required in ("LICENSE", "NOTICE", "DISCLAIMER", MANIFEST):
        if f"{name}/{required}" not in result:
            raise ValueError(f"Missing {required}")
    return result


def source(tag, name):
    data = git("archive", "--format=tar", f"--prefix={name}/", tag)
    inventory(data, name)
    return data


def download(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        destination = urllib.parse.urlparse(response.url)
        if (
            destination.scheme != "https"
            or destination.hostname not in ("downloads.apache.org", "dlcdn.apache.org")
            or not destination.path.startswith("/incubator/casbin/")
        ):
            raise ValueError("Download redirected outside the project's approved ASF release area")
        return response.read()


def verify_signature(key_data, target, signature):
    with tempfile.TemporaryDirectory() as scratch:
        keyhome = Path(scratch) / "gnupg"
        keyhome.mkdir(mode=0o700)
        keys = Path(scratch) / "KEYS"
        keys.write_bytes(key_data)
        subprocess.run(["gpg", "--batch", "--homedir", str(keyhome), "--import", str(keys)], check=True)
        subprocess.run(
            ["gpg", "--batch", "--homedir", str(keyhome), "--verify", str(signature), str(target)], check=True
        )


def check_python(path):
    # Build installs packaging; meta/archive/verify remain standard-library-only.
    from packaging.requirements import Requirement

    root = Path.cwd()
    expected = tomllib.loads((root / MANIFEST).read_text(encoding="utf8"))["project"]

    def canonical(name):
        return re.sub(r"[-_.]+", "-", name).lower()

    def metadata_check(data):
        info = BytesParser().parsebytes(data)
        if canonical(info["Name"]) != canonical(expected["name"]) or info["Version"] != expected["version"]:
            raise ValueError("Python distribution identity mismatch")
        if (info["License-Expression"] or info["License"]) != "Apache-2.0":
            raise ValueError("Python license metadata mismatch")
        if info.get("Requires-Python") != expected.get("requires-python"):
            raise ValueError("Python compatibility metadata differs from approved source")
        description = info.get_payload(decode=True).decode("utf8").replace("\r\n", "\n").strip()
        if description != (root / "README.md").read_text(encoding="utf8").strip():
            raise ValueError("Python public description differs from approved README")
        requirements = root / "requirements.txt"
        declared = expected.get("dependencies", [])
        if "dependencies" in expected.get("dynamic", []) and requirements.exists():
            declared = [
                line.strip()
                for line in requirements.read_text(encoding="utf8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]

        def normalized_requirements(values):
            return sorted(
                (
                    canonical(req.name),
                    str(req.specifier),
                    tuple(sorted(req.extras)),
                    str(req.marker or ""),
                    req.url or "",
                )
                for req in map(Requirement, values)
            )

        if normalized_requirements(info.get_all("Requires-Dist", [])) != normalized_requirements(declared):
            raise ValueError("Python dependency metadata differs from approved source")

    files = {}
    target = Path(path)
    if target.suffix == ".whl":
        with zipfile.ZipFile(target) as archive:
            for entry in archive.infolist():
                parts = Path(entry.filename).parts
                if entry.filename.startswith("/") or ".." in parts or "\\" in entry.filename:
                    raise ValueError("Unsafe wheel path")
                if entry.is_dir():
                    continue
                canonical_path = "/".join(parts)
                if canonical_path in files or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Duplicate wheel entry or symbolic link")
                files[canonical_path] = archive.read(entry)
        metadata_files = [name for name in files if name.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise ValueError("Wheel must contain one METADATA record")
        metadata_path = metadata_files[0]
        metadata_check(files[metadata_path])
        prefix = metadata_path.rsplit("/", 1)[0]
        for name in ("LICENSE", "NOTICE", "DISCLAIMER"):
            matches = [f for f in (prefix + "/" + name, prefix + "/licenses/" + name) if f in files]
            if len(matches) != 1 or files[matches[0]] != (root / name).read_bytes():
                raise ValueError(f"Wheel legal file missing or changed: {name}")
        record = prefix + "/RECORD"
        rows = list(csv.reader(io.StringIO(files[record].decode())))
        if {row[0] for row in rows} != set(files):
            raise ValueError("Wheel RECORD coverage differs")
        for name, digest, size in rows:
            if name == record:
                continue
            actual = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode()
            if digest != actual or size != str(len(files[name])):
                raise ValueError("Wheel RECORD digest/size mismatch")
        for name, data in files.items():
            if name.startswith(prefix + "/"):
                continue
            if not name.startswith("casbin/") or not name.endswith(".py"):
                raise ValueError(f"Unexpected wheel payload outside the library: {name}")
            source = root / name
            if not source.is_file() or source.read_bytes() != data:
                raise ValueError(f"Unexpected or changed wheel source: {name}")
    else:
        prefix = expected["name"].replace("-", "_") + "-" + expected["version"]
        with tarfile.open(target) as archive:
            for entry in archive:
                parts = Path(entry.name).parts
                if not parts or parts[0] != prefix or ".." in parts or "\\" in entry.name:
                    raise ValueError("Unsafe sdist path")
                if entry.isdir():
                    continue
                name = "/".join(parts[1:])
                if not entry.isfile() or name in files:
                    raise ValueError("Sdist contains links, special files or duplicates")
                files[name] = archive.extractfile(entry).read()
        metadata_check(files["PKG-INFO"])
        for name in (MANIFEST, "LICENSE", "NOTICE", "DISCLAIMER", "README.md"):
            if files.get(name) != (root / name).read_bytes():
                raise ValueError(f"Sdist source/legal file missing or changed: {name}")
        for name, data in files.items():
            if name == "PKG-INFO" or ".egg-info/" in name or name == "setup.cfg":
                continue
            source = root / name
            if not source.is_file() or source.read_bytes() != data:
                raise ValueError(f"Unexpected or changed sdist file: {name}")
    for source in (root / "casbin").rglob("*.py"):
        if files.get(source.relative_to(root).as_posix()) != source.read_bytes():
            raise ValueError("Python distribution omits or changes module source")
    print(f"Python contents verified against approved source: {target}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["meta", "archive", "verify", "python-check"])
    parser.add_argument("tag")
    parser.add_argument("output", nargs="?", default="dist-release")
    args = parser.parse_args()
    if args.command == "python-check":
        check_python(args.tag)
        return
    version, rc, name = metadata(args.tag)
    if args.command == "meta":
        print(f"version={version}\nis_rc={str(rc).lower()}\nname={name}")
        return
    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Refusing to replace existing release files; choose an empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    expected = source(args.tag, name)
    filename = name + ".tar.gz"
    target = output / filename
    if args.command == "archive":
        if not rc:
            raise ValueError("Final releases must reuse approved ASF originals, not rebuild source archives")
        target.write_bytes(gzip.compress(expected, mtime=0))
        (output / (filename + ".sha512")).write_text(
            hashlib.sha512(target.read_bytes()).hexdigest() + "  " + filename + "\n", encoding="ascii"
        )
    else:
        if rc:
            raise ValueError("An RC cannot enter final publication")
        url = f"{ASF_BASE}/{COMPONENT}-{version}-incubating/{filename}"
        for suffix in ("", ".sha512", ".asc"):
            (output / (filename + suffix)).write_bytes(download(url + suffix))
        checksum = (output / (filename + ".sha512")).read_text(encoding="utf8").split()
        if len(checksum) != 2 or checksum[1].lstrip("*") != filename:
            raise ValueError("Unexpected checksum record")
        if hashlib.sha512(target.read_bytes()).hexdigest() != checksum[0].lower():
            raise ValueError("SHA-512 mismatch")
        verify_signature(download(ASF_BASE + "/KEYS"), target, output / (filename + ".asc"))
        if inventory(target.read_bytes(), name) != inventory(expected, name):
            raise ValueError("Approved source contents/modes differ from the selected Git tag")
        # Build package registries only from the approved source, never a fresh checkout.
        with tarfile.open(target) as archive:
            archive.extractall(output / "source", filter="data")
    print(f"Verified {target}; {'local unsigned candidate' if rc else 'approved ASF original'}")


if __name__ == "__main__":
    main()
