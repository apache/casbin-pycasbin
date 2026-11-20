<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Releasing Apache Casbin (Incubating) — PyCasbin

Apache Casbin (Incubating) is an effort undergoing incubation at the Apache Software Foundation (ASF), sponsored by the Apache Incubator PMC.

Incubation is required of all newly accepted projects until a further review indicates that the infrastructure, communications, and decision making process have stabilized in a manner consistent with other successful ASF projects.

While incubation status is not necessarily a reflection of the completeness or stability of the code, it does indicate that the project has yet to be fully endorsed by the ASF.

Apache source packages are the release artifacts. PyPI wheels and sdists are convenience distributions built from the approved Apache source. Historical versions through 2.8.0 predate incubation. A branch build or GitHub tag does not establish release approval.

The Apache distribution is `apache-casbin` and the import package remains `casbin`. The package identity is separate from registry ownership and release approval. Avoid co-installing legacy `casbin`/`pycasbin`, which contain overlapping import files. Adapter dependency migrations are separate components and do not silently substitute an old core in candidate verification.

The synchronized enforcer uses the in-tree lock in `casbin/util/rwlock.py`. Review the provenance and terms for the adaptation identified in that file before signing a candidate.

## Prepare and test

Use Python 3.9 or newer for the library, and Python 3.12 for release tooling. The dependency requirements already require Python 3.9. Prepare the committed version, scoped fixes, ASF headers, legal files, metadata, distributions and workflow changes for review. Retain origin notices and resolve third-party licensing before submission.

```sh
python -m pip install -r requirements_dev.txt coverage build twine
python -m unittest discover -s tests -t tests
python -m black --check .
python -m unittest discover -s .github/scripts -p 'test_*.py'
python -m build
python -m twine check --strict dist/*
java -jar /path/to/apache-rat.jar --scan-hidden-directories --exclude-file .rat-excludes --dir .
python .github/scripts/release.py python-check dist/<package>.whl
python .github/scripts/release.py python-check dist/<package>.tar.gz
```

To include the shared conformance suite, check out `apache/casbin` at commit `6a018f27246f5f270f6cfa6ca3e8c82f45812bec` separately and set `CASBIN_CONFORMANCE_DIR` to its `conformance` directory. This pins CI's test input; it does not bundle the other project's source. Without that environment variable the conformance test is explicitly skipped. Extracted-source builds should retain that input when testing the RC.

Test the built wheel in a fresh environment outside the checkout. Inspect both distributions for the exact committed version, full README disclaimer, all library modules and LICENSE/NOTICE/DISCLAIMER. The sdist also carries tests and example policies so it can be tested independently.

## Stage an RC

After merge, bind the actual merged commit and successful CI to the candidate. With the release manager's authorization, tag that commit as `vX.Y.Z-rcN`. Only RC-tag pushes trigger automatic candidate export. The workflow exports an **unsigned** `apache-casbin-pycasbin-X.Y.Z-incubating-src.tar.gz` and SHA-512 and creates a clearly marked GitHub prerelease with `latest=false`. It never uploads an RC to PyPI.

The release manager reviews the exact archive and legal/provenance evidence, signs it with an ASF key present in the project's KEYS, stages those same bytes under the ASF dev area, and verifies fresh public downloads and an independent extracted build. Obtain valid project/PPMC and IPMC approvals with source, signature/checksum and review links. Human review and voting are separate from the scripts' checks.

## Publish approved originals

Promote the approved source archive, `.asc` and `.sha512` unchanged to:

```text
https://downloads.apache.org/incubator/casbin/pycasbin-X.Y.Z-incubating/
```

Create the final `vX.Y.Z` tag at the approved candidate commit. A final-tag push performs no publication. After the approvals and ASF promotion, dispatch `release.yml` **from master** with that existing tag and the actual public project and IPMC result-thread URLs. The URLs are auditable references; a URL-shaped string does not prove that a vote passed. The release manager must validate their scope, votes and candidate binding before dispatch.

Before the first upload of `apache-casbin`, have a project-designated PyPI maintainer configure a pending Trusted Publisher for owner `apache`, repository `casbin-pycasbin`, workflow `release.yml`, and environment `pypi`. Use the same publisher configuration on the PyPI project if it already exists. Configure the matching GitHub Actions environment. A pending publisher does not reserve the name. Record who administers the PyPI project and the GitHub environment.

The workflow refuses an existing GitHub release, validates the tag and committed version, and verifies the promoted ASF originals against the tag, KEYS and SHA-512. The build job tests and packages the extracted approved source. A dedicated job in the `pypi` environment downloads the checked distributions from that run and uses Trusted Publishing. After that upload succeeds, a separate GitHub job uses the same run's verified source assets and release notes. The final source bytes are carried forward from ASF distribution.

Record registry administration and credential access for the PPMC separately from GitHub/tag and ASF SVN permissions. Never test the release by performing a real registry upload. Inspect the actual installed PyPI package, official downloads, website and announcements after approved publication.

## Safe retries

Output directories must be empty, archives and stable tags must not be overwritten, and RCs never set the stable `latest` alias. If a run fails, inspect ASF, PyPI and GitHub first. PyPI is immutable: a partial upload must not cause a second upload or a rebuild of voted originals. The publish action's `skip-existing` option is deliberately not enabled. Use a reviewed channel-specific recovery for a partial publication rather than rerunning the entire job blindly.

The tooling validates integrity, contents and the configured route. It does not grant publication permission, certify source originality, verify vote eligibility, control registry ownership or replace human review.
