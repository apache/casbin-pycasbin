<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Semantic Versioning Changelog

## [2.6.1](https://github.com/apache/casbin-pycasbin/compare/v2.6.0...v2.6.1) (2025-12-19)


### Bug Fixes

* remove irrelevant links in README ([6c3df05](https://github.com/apache/casbin-pycasbin/commit/6c3df05bde9e733d1f76f2db219b9c820014f0c8))

# [2.6.0](https://github.com/apache/casbin-pycasbin/compare/v2.5.0...v2.6.0) (2025-11-06)


### Features

* fix enforce_ex() API returning empty explanations for allow rules in deny models ([#412](https://github.com/apache/casbin-pycasbin/issues/412)) ([dbd28b7](https://github.com/apache/casbin-pycasbin/commit/dbd28b728c617c28f34478bd9dde3f712fc1c37e))

# [2.5.0](https://github.com/apache/casbin-pycasbin/compare/v2.4.0...v2.5.0) (2025-11-06)


### Features

* only run CI for Python "3.12", "3.13" ([2e5783c](https://github.com/apache/casbin-pycasbin/commit/2e5783cd1c9131c57da78dcacc992d637985b3c9))
* update CI Node.js version to 20 ([5bd7a08](https://github.com/apache/casbin-pycasbin/commit/5bd7a081bb2c1da1415fdfc7b904105de79ef38e))

# [2.4.0](https://github.com/apache/casbin-pycasbin/compare/v2.3.0...v2.4.0) (2025-10-14)


### Features

* fix inconsistent async handling bug for watcher.update() API ([#406](https://github.com/apache/casbin-pycasbin/issues/406)) ([7875d02](https://github.com/apache/casbin-pycasbin/commit/7875d022249cf94338ef7921a8253f577fafa7ee))

# [2.3.0](https://github.com/apache/casbin-pycasbin/compare/v2.2.0...v2.3.0) (2025-10-04)


### Features

* use wcmatch.glob for glob_match with "**" support ([#402](https://github.com/apache/casbin-pycasbin/issues/402)) ([0ff7cd8](https://github.com/apache/casbin-pycasbin/commit/0ff7cd86b6d5756a39e1a6ed37e4e505c81210d0))

# [2.2.0](https://github.com/apache/casbin-pycasbin/compare/v2.1.0...v2.2.0) (2025-08-24)


### Features

* fix bug that get_all_subjects() and similar APIs get wrong result ([#399](https://github.com/apache/casbin-pycasbin/issues/399)) ([cd76b7c](https://github.com/apache/casbin-pycasbin/commit/cd76b7cc6f01146a70258146d326e36cb08de991))

# [2.1.0](https://github.com/apache/casbin-pycasbin/compare/v2.0.0...v2.1.0) (2025-08-19)


### Features

* align add_policy API with Golang Casbin ([#398](https://github.com/apache/casbin-pycasbin/issues/398)) ([937b649](https://github.com/apache/casbin-pycasbin/commit/937b64936cdce128ebd9f967b263549f26f1f42f))

# [2.0.0](https://github.com/apache/casbin-pycasbin/compare/v1.50.0...v2.0.0) (2025-08-10)


### Features

* update README.md status badges and improve TestFastEnforcer() ([#396](https://github.com/apache/casbin-pycasbin/issues/396)) ([79105a0](https://github.com/apache/casbin-pycasbin/commit/79105a0e6fad65ee8d8b736557246f7cd21f2371)), closes [#395](https://github.com/apache/casbin-pycasbin/issues/395)


### BREAKING CHANGES

* this work for release PyCasbin v2

* docs: change status badge

# [1.50.0](https://github.com/apache/casbin-pycasbin/compare/v1.49.0...v1.50.0) (2025-08-09)


### Features

* upgrade dependencies to latest ([#393](https://github.com/apache/casbin-pycasbin/issues/393)) ([731fcac](https://github.com/apache/casbin-pycasbin/commit/731fcacf5a262a795ce0b931065a0ae8fa67a903))

# [1.49.0](https://github.com/apache/casbin-pycasbin/compare/v1.48.0...v1.49.0) (2025-08-06)


### Features

* add add_grouping_policies_ex and add_named_grouping_policies_ex APIs ([#392](https://github.com/apache/casbin-pycasbin/issues/392)) ([cc34db6](https://github.com/apache/casbin-pycasbin/commit/cc34db6218fb4a13b12672ae5971cfa14a9658f1))

# [1.48.0](https://github.com/apache/casbin-pycasbin/compare/v1.47.0...v1.48.0) (2025-08-01)


### Features

* add new APIs: add_policies_ex() and add_named_policies_ex() ([#391](https://github.com/apache/casbin-pycasbin/issues/391)) ([e0a64f9](https://github.com/apache/casbin-pycasbin/commit/e0a64f92463b56e17c1acf49b26d82d166d19c37))

# [1.47.0](https://github.com/apache/casbin-pycasbin/compare/v1.46.0...v1.47.0) (2025-07-26)


### Features

* fix the bug that add_policies does not update policy_map ([#390](https://github.com/apache/casbin-pycasbin/issues/390)) ([c0c6065](https://github.com/apache/casbin-pycasbin/commit/c0c6065e038224bc9e06c89d0782a6bf01664d8e))

# [1.46.0](https://github.com/apache/casbin-pycasbin/compare/v1.45.0...v1.46.0) (2025-07-20)


### Features

* upgrade Python version to 3.8~3.13 ([#387](https://github.com/apache/casbin-pycasbin/issues/387)) ([7c2f2f5](https://github.com/apache/casbin-pycasbin/commit/7c2f2f5303b5f7eea692ea9de4ff62845633a6c1))

# [1.45.0](https://github.com/apache/casbin-pycasbin/compare/v1.44.0...v1.45.0) (2025-06-07)


### Features

* Optimize `load_policy_line` to avoid quadratic individual-character loop ([#355](https://github.com/apache/casbin-pycasbin/issues/355)) ([d3149e8](https://github.com/apache/casbin-pycasbin/commit/d3149e81c36d29e96ebdf3484897461ab86d8afb))

# [1.44.0](https://github.com/apache/casbin-pycasbin/compare/v1.43.0...v1.44.0) (2025-06-07)


### Features

* update info ([ed77f0e](https://github.com/apache/casbin-pycasbin/commit/ed77f0e153357e32ca5c50319ea82cdb34da3338))

# [1.43.0](https://github.com/apache/casbin-pycasbin/compare/v1.42.0...v1.43.0) (2025-05-10)


### Features

* fix CI error ([20719ab](https://github.com/apache/casbin-pycasbin/commit/20719ab63528edcb6243f3d66e26729e5be42679))

# [1.42.0](https://github.com/apache/casbin-pycasbin/compare/v1.41.0...v1.42.0) (2025-04-21)


### Features

* fix missing await in load_increment_filtered_policy() in async_internal_enforcer.py ([#378](https://github.com/apache/casbin-pycasbin/issues/378)) ([ca26402](https://github.com/apache/casbin-pycasbin/commit/ca264023f60ab83c2f852578ccfb8e567b0d7e0c))

# [1.41.0](https://github.com/apache/casbin-pycasbin/compare/v1.40.0...v1.41.0) (2025-03-15)


### Features

* add "logging_config" for PyCasbin logging ([#376](https://github.com/apache/casbin-pycasbin/issues/376)) ([f39ace2](https://github.com/apache/casbin-pycasbin/commit/f39ace2f0a185bccd2a3722f0265c488f304f200))

# [1.40.0](https://github.com/apache/casbin-pycasbin/compare/v1.39.0...v1.40.0) (2025-03-13)


### Features

* fix bug that "!=" in policies is replaced with "not=" ([#375](https://github.com/apache/casbin-pycasbin/issues/375)) ([54208b6](https://github.com/apache/casbin-pycasbin/commit/54208b66d3fd920adaeac2db37a78e74fa9d3b76))

# [1.39.0](https://github.com/apache/casbin-pycasbin/compare/v1.38.0...v1.39.0) (2025-03-11)


### Features

* Port get_allowed_object_conditions() from Golang to Python ([#373](https://github.com/apache/casbin-pycasbin/issues/373)) ([c433a59](https://github.com/apache/casbin-pycasbin/commit/c433a5996f5819f750f628625fd2a1f8f556e8db))

# [1.38.0](https://github.com/apache/casbin-pycasbin/compare/v1.37.0...v1.38.0) (2025-01-12)


### Features

* add StringAdapter's statement in init.py ([#367](https://github.com/apache/casbin-pycasbin/issues/367)) ([bf84eed](https://github.com/apache/casbin-pycasbin/commit/bf84eed7305d22338aae185a7d65e0d429927e89))

# [1.37.0](https://github.com/apache/casbin-pycasbin/compare/v1.36.3...v1.37.0) (2024-11-25)


### Features

* enhance FilteredFileAdapter to handle flexible filtering for policies and roles ([#360](https://github.com/apache/casbin-pycasbin/issues/360)) ([936d5f6](https://github.com/apache/casbin-pycasbin/commit/936d5f68df1d60b233f411489cc69f8b095c899a))

## [1.36.3](https://github.com/apache/casbin-pycasbin/compare/v1.36.2...v1.36.3) (2024-06-24)


### Bug Fixes

* KeyError: 'g' when build_role_links ([bf9cb44](https://github.com/apache/casbin-pycasbin/commit/bf9cb4403f290b1313a86a2dce1c81eb36a043b0))

## [1.36.2](https://github.com/apache/casbin-pycasbin/compare/v1.36.1...v1.36.2) (2024-06-11)


### Bug Fixes

* field_index is incorrect in RBAC with domains mode ([#345](https://github.com/apache/casbin-pycasbin/issues/345)) ([#346](https://github.com/apache/casbin-pycasbin/issues/346)) ([9f6a379](https://github.com/apache/casbin-pycasbin/commit/9f6a379d27d69366c156c8536ec48904c8b321ab))

## [1.36.1](https://github.com/apache/casbin-pycasbin/compare/v1.36.0...v1.36.1) (2024-05-21)


### Bug Fixes

* FastEnforcer not fast ([#344](https://github.com/apache/casbin-pycasbin/issues/344)) ([8aef43b](https://github.com/apache/casbin-pycasbin/commit/8aef43bcd03943a860c2cb530f499e67eac38375))

# [1.36.0](https://github.com/apache/casbin-pycasbin/compare/v1.35.0...v1.36.0) (2024-02-09)


### Features

* Added support for async watcher callbacks [#340](https://github.com/apache/casbin-pycasbin/issues/340) ([#341](https://github.com/apache/casbin-pycasbin/issues/341)) ([c04d832](https://github.com/apache/casbin-pycasbin/commit/c04d83237264178624780d70ab6dee89854ac87b))

# [1.35.0](https://github.com/apache/casbin-pycasbin/compare/v1.34.0...v1.35.0) (2024-01-11)


### Features

* support up to Python 3.12 ([6dea204](https://github.com/apache/casbin-pycasbin/commit/6dea20476328b947cf1e4e837acf340e371655c6))

# [1.34.0](https://github.com/apache/casbin-pycasbin/compare/v1.33.0...v1.34.0) (2023-12-28)


### Features

* add interface stubs for async adapters ([#335](https://github.com/apache/casbin-pycasbin/issues/335)) ([d557189](https://github.com/apache/casbin-pycasbin/commit/d557189eecee788e81d20ceae3cb1dee16a84ae7))

# [1.33.0](https://github.com/apache/casbin-pycasbin/compare/v1.32.0...v1.33.0) (2023-10-25)


### Features

* change log level to warning ([#329](https://github.com/apache/casbin-pycasbin/issues/329)) ([124d2c0](https://github.com/apache/casbin-pycasbin/commit/124d2c05a69d61c17fe16c4ef0ad1423f62e0bbb))

# [1.32.0](https://github.com/apache/casbin-pycasbin/compare/v1.31.2...v1.32.0) (2023-10-18)


### Features

* fix integer priority sorting ([#327](https://github.com/apache/casbin-pycasbin/issues/327)) ([d5cd58a](https://github.com/apache/casbin-pycasbin/commit/d5cd58a738ad8e8ad0a5010f9cff904736e1719a))

## [1.31.2](https://github.com/apache/casbin-pycasbin/compare/v1.31.1...v1.31.2) (2023-10-06)


### Bug Fixes

* use pre defined member ([#325](https://github.com/apache/casbin-pycasbin/issues/325)) ([4f191f0](https://github.com/apache/casbin-pycasbin/commit/4f191f09a48a61b597fb73b62a841a69407dd292))

## [1.31.1](https://github.com/apache/casbin-pycasbin/compare/v1.31.0...v1.31.1) (2023-09-30)


### Bug Fixes

* disabled all logger ([#324](https://github.com/apache/casbin-pycasbin/issues/324)) ([ae81a52](https://github.com/apache/casbin-pycasbin/commit/ae81a5225b4a045c6eba4f3bae6dade68b92b78a))

# [1.31.0](https://github.com/apache/casbin-pycasbin/compare/v1.30.0...v1.31.0) (2023-09-24)


### Features

* add temporal role model ([#320](https://github.com/apache/casbin-pycasbin/issues/320)) ([09ff119](https://github.com/apache/casbin-pycasbin/commit/09ff1191856345b69026e5fa86a361dd5df8bab5))

# [1.30.0](https://github.com/apache/casbin-pycasbin/compare/v1.29.0...v1.30.0) (2023-09-23)


### Features

* disable logger when log is not enabled ([#321](https://github.com/apache/casbin-pycasbin/issues/321)) ([952c208](https://github.com/apache/casbin-pycasbin/commit/952c208a9d423a86ac4ae6c7fa5ed15bc94e00dc))

# [1.29.0](https://github.com/apache/casbin-pycasbin/compare/v1.28.0...v1.29.0) (2023-09-23)


### Features

* Fixed the `subjectPriority` sorting algorithm and support for checking the subject role link loop ([#322](https://github.com/apache/casbin-pycasbin/issues/322)) ([f964e2a](https://github.com/apache/casbin-pycasbin/commit/f964e2aecbee28e4f9b8d1b4fba0d68cad0879fa))

# [1.28.0](https://github.com/apache/casbin-pycasbin/compare/v1.27.0...v1.28.0) (2023-09-16)


### Features

* port fastbin to casbin ([#318](https://github.com/apache/casbin-pycasbin/issues/318)) ([67537d6](https://github.com/apache/casbin-pycasbin/commit/67537d6799d04266f5d27bc3f86fa44db1676821))

# [1.27.0](https://github.com/apache/casbin-pycasbin/compare/v1.26.0...v1.27.0) (2023-09-03)


### Features

* add get_implicit_users_for_resource api ([#317](https://github.com/apache/casbin-pycasbin/issues/317)) ([8172097](https://github.com/apache/casbin-pycasbin/commit/817209768528f249644bbe7ac30f1d235bd192da))

# [1.26.0](https://github.com/apache/casbin-pycasbin/compare/v1.25.0...v1.26.0) (2023-08-31)


### Features

* add get_all_roles_by_domain api ([#316](https://github.com/apache/casbin-pycasbin/issues/316)) ([22507ca](https://github.com/apache/casbin-pycasbin/commit/22507ca7cc47746a03a97b1d051e209ea4ef96d1))

# [1.25.0](https://github.com/apache/casbin-pycasbin/compare/v1.24.0...v1.25.0) (2023-08-30)


### Features

* add key_match5 function for matcher ([#315](https://github.com/apache/casbin-pycasbin/issues/315)) ([7d29109](https://github.com/apache/casbin-pycasbin/commit/7d29109d67d8f60c6be9fca6b4aaff523a8c156e))

# [1.24.0](https://github.com/apache/casbin-pycasbin/compare/v1.23.1...v1.24.0) (2023-08-27)


### Features

* add field_index_map and constant ([#314](https://github.com/apache/casbin-pycasbin/issues/314)) ([e42f3da](https://github.com/apache/casbin-pycasbin/commit/e42f3da582f6d864c1c70b00679af9da560fe0f4))

## [1.23.1](https://github.com/apache/casbin-pycasbin/compare/v1.23.0...v1.23.1) (2023-08-10)


### Bug Fixes

* fix bug in add policy for priority effectors ([#313](https://github.com/apache/casbin-pycasbin/issues/313)) ([8d30537](https://github.com/apache/casbin-pycasbin/commit/8d30537149eeea433441ca62802f3bf06e1fd42c))

# [1.23.0](https://github.com/apache/casbin-pycasbin/compare/v1.22.0...v1.23.0) (2023-08-06)


### Features

* add AsyncEnforcer to pycasbin ([#307](https://github.com/apache/casbin-pycasbin/issues/307)) ([4192dc2](https://github.com/apache/casbin-pycasbin/commit/4192dc22dab3673b44c87d7dee059bd790c12c60))

# [1.22.0](https://github.com/apache/casbin-pycasbin/compare/v1.21.0...v1.22.0) (2023-07-14)


### Features

* update logger for more precise log level and format control ([#306](https://github.com/apache/casbin-pycasbin/issues/306)) ([5c688d7](https://github.com/apache/casbin-pycasbin/commit/5c688d7db2c7f5139e2192a0a21d3b2ba3f0807b))

# [1.21.0](https://github.com/apache/casbin-pycasbin/compare/v1.20.0...v1.21.0) (2023-07-10)


### Features

* add string adapter ([#304](https://github.com/apache/casbin-pycasbin/issues/304)) ([784a46f](https://github.com/apache/casbin-pycasbin/commit/784a46f8f403cf18572c22c8779dc1e3dca315ca))

# [1.20.0](https://github.com/apache/casbin-pycasbin/compare/v1.19.0...v1.20.0) (2023-07-07)


### Features

* add auto_notify_watcher to core enforcer ([#303](https://github.com/apache/casbin-pycasbin/issues/303)) ([15de222](https://github.com/apache/casbin-pycasbin/commit/15de2223d08e4d53555e747a4e549c327344412c))

# [1.19.0](https://github.com/apache/casbin-pycasbin/compare/v1.18.3...v1.19.0) (2023-05-24)


### Features

* Add batch_enforce() API ([#298](https://github.com/apache/casbin-pycasbin/issues/298)) ([361af9b](https://github.com/apache/casbin-pycasbin/commit/361af9bc76492b975d454d9f479b3703248fc509))

## [1.18.3](https://github.com/apache/casbin-pycasbin/compare/v1.18.2...v1.18.3) (2023-05-22)


### Bug Fixes

* Exclude tests from package ([#297](https://github.com/apache/casbin-pycasbin/issues/297)) ([9b014a2](https://github.com/apache/casbin-pycasbin/commit/9b014a226058947424f87408ea14176f20183031))
* Stop including README as top-level data file in package ([#296](https://github.com/apache/casbin-pycasbin/issues/296)) ([e85e9b9](https://github.com/apache/casbin-pycasbin/commit/e85e9b91aca3007fc4aab292689302eaae27cf02))

## [1.18.2](https://github.com/apache/casbin-pycasbin/compare/v1.18.1...v1.18.2) (2023-04-06)


### Bug Fixes

* load policy rule without splitting custom functions ([#293](https://github.com/apache/casbin-pycasbin/issues/293)) ([fbc4261](https://github.com/apache/casbin-pycasbin/commit/fbc42616620fcbe089cfcf459ec9eaa441fc33e1))

## [1.18.1](https://github.com/apache/casbin-pycasbin/compare/v1.18.0...v1.18.1) (2023-04-01)


### Bug Fixes

* support escaping comma inside quote in load_policy_line()'s CSV parsing ([#292](https://github.com/apache/casbin-pycasbin/issues/292)) ([51e6e7c](https://github.com/apache/casbin-pycasbin/commit/51e6e7c34d8ebcef666d34a6f10f457bfc0c31d0))

# [1.18.0](https://github.com/apache/casbin-pycasbin/compare/v1.17.6...v1.18.0) (2023-03-07)


### Features

* revert "fix: avoid duplicate adapter entries ([#259](https://github.com/apache/casbin-pycasbin/issues/259))" ([#290](https://github.com/apache/casbin-pycasbin/issues/290)) ([b573041](https://github.com/apache/casbin-pycasbin/commit/b573041270acbc9e217ee673792b31e74239b7c7))

## [1.17.6](https://github.com/apache/casbin-pycasbin/compare/v1.17.5...v1.17.6) (2023-02-09)


### Bug Fixes

* fix typo in remove_grouping_policies() API ([#287](https://github.com/apache/casbin-pycasbin/issues/287)) ([747f71d](https://github.com/apache/casbin-pycasbin/commit/747f71d2f629affa4aa0d15115e5cb61b4f4b732))

## [1.17.5](https://github.com/apache/casbin-pycasbin/compare/v1.17.4...v1.17.5) (2022-12-05)


### Bug Fixes

* polish import grammar and remove some useless package ([#282](https://github.com/apache/casbin-pycasbin/issues/282)) ([be53e0b](https://github.com/apache/casbin-pycasbin/commit/be53e0b9e0d8863919de4cdd5f0185f5eea0779d))

## [1.17.4](https://github.com/apache/casbin-pycasbin/compare/v1.17.3...v1.17.4) (2022-11-01)


### Bug Fixes

* fix bug in autoloader error handling ([#275](https://github.com/apache/casbin-pycasbin/issues/275)) ([e6f03ce](https://github.com/apache/casbin-pycasbin/commit/e6f03ce165d447534dcd2149928115eb5afed51e))

## [1.17.3](https://github.com/apache/casbin-pycasbin/compare/v1.17.2...v1.17.3) (2022-11-01)


### Bug Fixes

* load_policy changed the old model ([#277](https://github.com/apache/casbin-pycasbin/issues/277)) ([f247231](https://github.com/apache/casbin-pycasbin/commit/f247231f1f18aae87773c02739d0b15fb9164c0a))

## [1.17.2](https://github.com/apache/casbin-pycasbin/compare/v1.17.1...v1.17.2) (2022-10-20)


### Bug Fixes

* catch exceptions in synced enforcer thread ([#272](https://github.com/apache/casbin-pycasbin/issues/272)) ([ff35627](https://github.com/apache/casbin-pycasbin/commit/ff3562764343f08030fe13fcd884bbe169945b87))

## [1.17.1](https://github.com/apache/casbin-pycasbin/compare/v1.17.0...v1.17.1) (2022-08-28)


### Bug Fixes

* some typos ([#270](https://github.com/apache/casbin-pycasbin/issues/270)) ([7705e25](https://github.com/apache/casbin-pycasbin/commit/7705e25fe33d59877d54116ad9855795ebaeaf51))

# [1.17.0](https://github.com/apache/casbin-pycasbin/compare/v1.16.11...v1.17.0) (2022-08-08)


### Features

* add watcher-ex call ([#269](https://github.com/apache/casbin-pycasbin/issues/269)) ([f4bc0c0](https://github.com/apache/casbin-pycasbin/commit/f4bc0c05b6578c6d08410410d7bc54dfd690e6e5))

## [1.16.11](https://github.com/apache/casbin-pycasbin/compare/v1.16.10...v1.16.11) (2022-07-30)


### Bug Fixes

* update support python version ([#268](https://github.com/apache/casbin-pycasbin/issues/268)) ([b4ddcbb](https://github.com/apache/casbin-pycasbin/commit/b4ddcbb7a36896b231f589ea04271e52630e7bb2))

## [1.16.10](https://github.com/apache/casbin-pycasbin/compare/v1.16.9...v1.16.10) (2022-07-30)


### Bug Fixes

* add key_get() for builtin_operators ([#267](https://github.com/apache/casbin-pycasbin/issues/267)) ([29d3e39](https://github.com/apache/casbin-pycasbin/commit/29d3e3944953590eaea59a9a0ab042d097d09d97))

## [1.16.9](https://github.com/apache/casbin-pycasbin/compare/v1.16.8...v1.16.9) (2022-07-10)


### Bug Fixes

* add benchmark for glob match ([#265](https://github.com/apache/casbin-pycasbin/issues/265)) ([0c6b09f](https://github.com/apache/casbin-pycasbin/commit/0c6b09fbd342a29913ec0fda3550fc8271f287b3))

## [1.16.8](https://github.com/apache/casbin-pycasbin/compare/v1.16.7...v1.16.8) (2022-06-26)


### Bug Fixes

* add dependency for benchmark ([#262](https://github.com/apache/casbin-pycasbin/issues/262)) ([4f3e71f](https://github.com/apache/casbin-pycasbin/commit/4f3e71fadb17cf41381e3315b795a23e007bf23b))
* add more example of globmatch and add unit test for it ([#263](https://github.com/apache/casbin-pycasbin/issues/263)) ([42d65d2](https://github.com/apache/casbin-pycasbin/commit/42d65d2b74b22cc1b10b9dc96a8fc960e8af3f72))

## [1.16.7](https://github.com/apache/casbin-pycasbin/compare/v1.16.6...v1.16.7) (2022-06-26)


### Bug Fixes

* add import statement in tests module ([#264](https://github.com/apache/casbin-pycasbin/issues/264)) ([8d83b84](https://github.com/apache/casbin-pycasbin/commit/8d83b8461af74b9dd39e2e9652921d969d735c7c))

## [1.16.6](https://github.com/apache/casbin-pycasbin/compare/v1.16.5...v1.16.6) (2022-06-22)


### Bug Fixes

* Set the default log level to warning ([#261](https://github.com/apache/casbin-pycasbin/issues/261)) ([9a48e5d](https://github.com/apache/casbin-pycasbin/commit/9a48e5d89a49c09fcd6bde445a1f11aaca1da5b9))

## [1.16.5](https://github.com/apache/casbin-pycasbin/compare/v1.16.4...v1.16.5) (2022-05-20)


### Bug Fixes

* avoid duplicate adapter entries ([#259](https://github.com/apache/casbin-pycasbin/issues/259)) ([8d74386](https://github.com/apache/casbin-pycasbin/commit/8d7438687518f58ba945c822b36d1c9e5188316e))

## [1.16.4](https://github.com/apache/casbin-pycasbin/compare/v1.16.3...v1.16.4) (2022-05-13)


### Bug Fixes

* avoid raising exception in remove_grouping_policy ([#257](https://github.com/apache/casbin-pycasbin/issues/257)) ([39e17b4](https://github.com/apache/casbin-pycasbin/commit/39e17b45cf8880a0db9e30f84def55801bf199d7)), closes [#250](https://github.com/apache/casbin-pycasbin/issues/250) [#250](https://github.com/apache/casbin-pycasbin/issues/250)

## [1.16.3](https://github.com/apache/casbin-pycasbin/compare/v1.16.2...v1.16.3) (2022-04-30)


### Bug Fixes

* different behavior of glob_match from other casbin ([#254](https://github.com/apache/casbin-pycasbin/issues/254)) ([49b6a04](https://github.com/apache/casbin-pycasbin/commit/49b6a0467ff4e84838a4b61ee79fe66af0e9de25))

## [1.16.2](https://github.com/apache/casbin-pycasbin/compare/v1.16.1...v1.16.2) (2022-04-30)


### Bug Fixes

* allow permissions management to use additional p-types ([#256](https://github.com/apache/casbin-pycasbin/issues/256)) ([37892e1](https://github.com/apache/casbin-pycasbin/commit/37892e1b1578db42543ec81e0120ebda3492afc7))

## [1.16.1](https://github.com/apache/casbin-pycasbin/compare/v1.16.0...v1.16.1) (2022-04-29)


### Bug Fixes

* add lint config ([#255](https://github.com/apache/casbin-pycasbin/issues/255)) ([4890433](https://github.com/apache/casbin-pycasbin/commit/4890433f8d828ca94233b0fe005af56617409b64))

# [1.16.0](https://github.com/apache/casbin-pycasbin/compare/v1.15.5...v1.16.0) (2022-04-27)


### Features

* update_filtered_policies ([#249](https://github.com/apache/casbin-pycasbin/issues/249)) ([ca84dac](https://github.com/apache/casbin-pycasbin/commit/ca84dac37292457b12647611e1f6a63358daf9c6))

## [1.15.5](https://github.com/apache/casbin-pycasbin/compare/v1.15.4...v1.15.5) (2022-04-16)


### Bug Fixes

* load policy override role manager ([#252](https://github.com/apache/casbin-pycasbin/issues/252)) ([97280c5](https://github.com/apache/casbin-pycasbin/commit/97280c549b7a151a60d15fea63f4e0b141eb2c24))

## [1.15.4](https://github.com/apache/casbin-pycasbin/compare/v1.15.3...v1.15.4) (2022-01-13)


### Bug Fixes

* [#238](https://github.com/apache/casbin-pycasbin/issues/238), avoid calling has_eval in enforcing loop ([#240](https://github.com/apache/casbin-pycasbin/issues/240)) ([8188b27](https://github.com/apache/casbin-pycasbin/commit/8188b274e7954838c0717c10f2b772b47130b1e8))

## [1.15.3](https://github.com/apache/casbin-pycasbin/compare/v1.15.2...v1.15.3) (2022-01-13)


### Bug Fixes

* [#239](https://github.com/apache/casbin-pycasbin/issues/239), not allowing more than 9 types of policies/requests ([dcf4392](https://github.com/apache/casbin-pycasbin/commit/dcf43924bbdd59901d1b6632a5a1796ad546cc09))

## [1.15.2](https://github.com/apache/casbin-pycasbin/compare/v1.15.1...v1.15.2) (2021-12-17)


### Bug Fixes

* Apache 2.0 license headers ([#233](https://github.com/apache/casbin-pycasbin/issues/233)) ([16e4f0a](https://github.com/apache/casbin-pycasbin/commit/16e4f0a0f82ac93688e1b735b3da173929524107))
* disabled casbin should allow all requests ([#235](https://github.com/apache/casbin-pycasbin/issues/235)) ([ecd4ff8](https://github.com/apache/casbin-pycasbin/commit/ecd4ff8cbee8dede7923eb7d617cc251e0de5582))


### Performance Improvements

* judge whether use domain_matching_func ([#232](https://github.com/apache/casbin-pycasbin/issues/232)) ([bb12c0f](https://github.com/apache/casbin-pycasbin/commit/bb12c0f03c1a30cfb8e3cf3e77b4d1b6c0aad1d4))

## [1.15.2](https://github.com/apache/casbin-pycasbin/compare/v1.15.1...v1.15.2) (2021-12-15)


### Bug Fixes

* Apache 2.0 license headers ([#233](https://github.com/apache/casbin-pycasbin/issues/233)) ([16e4f0a](https://github.com/apache/casbin-pycasbin/commit/16e4f0a0f82ac93688e1b735b3da173929524107))

## [1.15.1](https://github.com/apache/casbin-pycasbin/compare/v1.15.0...v1.15.1) (2021-12-13)


### Performance Improvements

* add pytest-benchmark and judge whether use regex in rabc ([#228](https://github.com/apache/casbin-pycasbin/issues/228)) ([252c288](https://github.com/apache/casbin-pycasbin/commit/252c288e20c138b97b7cd58aa3c47d4434b0c742))

# [1.15.0](https://github.com/apache/casbin-pycasbin/compare/v1.14.0...v1.15.0) (2021-12-11)


### Features

* subject priority ([#231](https://github.com/apache/casbin-pycasbin/issues/231)) ([b38169d](https://github.com/apache/casbin-pycasbin/commit/b38169dbf3d122e17d764e058ef13915a1861eec))

# [1.14.0](https://github.com/apache/casbin-pycasbin/compare/v1.13.0...v1.14.0) (2021-12-09)


### Features

* casbin_js_get_permission_for_user ([#229](https://github.com/apache/casbin-pycasbin/issues/229)) ([075ca10](https://github.com/apache/casbin-pycasbin/commit/075ca1078ea850498bc058767524468cdf05458d))

# [1.13.0](https://github.com/apache/casbin-pycasbin/compare/v1.12.0...v1.13.0) (2021-12-08)


### Features

* get implicit permissions filter policies domain by matching function ([#226](https://github.com/apache/casbin-pycasbin/issues/226)) ([e16dfb3](https://github.com/apache/casbin-pycasbin/commit/e16dfb3c2992b0195b99b2aa07f30569d5d273af))

# [1.12.0](https://github.com/apache/casbin-pycasbin/compare/v1.11.1...v1.12.0) (2021-11-27)


### Features

* support matching functions to filter policies ([#222](https://github.com/apache/casbin-pycasbin/issues/222)) ([9d0528d](https://github.com/apache/casbin-pycasbin/commit/9d0528db85b8aedfc6b337f3d98bad19c64103e7))

## [1.11.1](https://github.com/apache/casbin-pycasbin/compare/v1.11.0...v1.11.1) (2021-11-21)


### Bug Fixes

* add glob_match() test cases from Go to Python ([658d3bb](https://github.com/apache/casbin-pycasbin/commit/658d3bb189749a06089c678f708d546e26aebe11))

# [1.11.0](https://github.com/apache/casbin-pycasbin/compare/v1.10.1...v1.11.0) (2021-11-21)


### Features

* ignore policies with domain when get_implicit_permissions_for_user ([5ca47b7](https://github.com/apache/casbin-pycasbin/commit/5ca47b7224299d07c19d80c9e2e4846a4135f151))

## [1.10.1](https://github.com/apache/casbin-pycasbin/compare/v1.10.0...v1.10.1) (2021-11-21)


### Bug Fixes

* linter bug in test_enforcer.py ([782f229](https://github.com/apache/casbin-pycasbin/commit/782f229f3bc39d8743731a0ce860d827dba14dab))

# [1.10.0](https://github.com/apache/casbin-pycasbin/compare/v1.9.7...v1.10.0) (2021-11-20)


### Features

* port the test case of add_function() example to pycasbin ([#217](https://github.com/apache/casbin-pycasbin/issues/217)) ([c19d065](https://github.com/apache/casbin-pycasbin/commit/c19d0658687bfb4e0a59c7323024c2842b226d56))

## [1.9.7](https://github.com/apache/casbin-pycasbin/compare/v1.9.6...v1.9.7) (2021-11-18)


### Bug Fixes

* reimplement default role manager ([b8f7fa7](https://github.com/apache/casbin-pycasbin/commit/b8f7fa7fd515e70b685a4d044fa3d568935ae337))

## [1.9.6](https://github.com/apache/casbin-pycasbin/compare/v1.9.5...v1.9.6) (2021-11-12)


### Bug Fixes

* replace build_role_links with build_incremental_role_links ([1d60cd3](https://github.com/apache/casbin-pycasbin/commit/1d60cd36887995b034dca7561179e13e9aae0c9f))

## [1.9.5](https://github.com/apache/casbin-pycasbin/compare/v1.9.4...v1.9.5) (2021-11-12)


### Bug Fixes

* remove_filtered_policy_returns_effects inconsistent input with remove_filtered_policy ([#211](https://github.com/apache/casbin-pycasbin/issues/211)) ([e7e6696](https://github.com/apache/casbin-pycasbin/commit/e7e669675c4d4225b96a3d391da04433926f9726))

## [1.9.4](https://github.com/apache/casbin-pycasbin/compare/v1.9.3...v1.9.4) (2021-10-29)


### Bug Fixes

* load_policy_line function load error ([bca7eed](https://github.com/apache/casbin-pycasbin/commit/bca7eed0cf61ecab381ed462921b776ec6aa7e3c))

## [1.9.3](https://github.com/apache/casbin-pycasbin/compare/v1.9.2...v1.9.3) (2021-10-24)


### Bug Fixes

* update simpleeval version to 0.9.11 ([79fdf21](https://github.com/apache/casbin-pycasbin/commit/79fdf212639263c44be4c27b545017e3b50863b0))

## [1.9.2](https://github.com/apache/casbin-pycasbin/compare/v1.9.1...v1.9.2) (2021-09-29)


### Bug Fixes

* 'keyMatch4' not defined([#198](https://github.com/apache/casbin-pycasbin/issues/198)) ([#199](https://github.com/apache/casbin-pycasbin/issues/199)) ([b888965](https://github.com/apache/casbin-pycasbin/commit/b888965c080df08c6415f45e606a24ba45698b90))

## [1.9.1](https://github.com/apache/casbin-pycasbin/compare/v1.9.0...v1.9.1) (2021-09-28)


### Bug Fixes

* added utf8 encoding ([#194](https://github.com/apache/casbin-pycasbin/issues/194)) ([6b42210](https://github.com/apache/casbin-pycasbin/commit/6b42210031ce7383823f17a2b8134a58f5f5a71d))

# [1.9.0](https://github.com/apache/casbin-pycasbin/compare/v1.8.1...v1.9.0) (2021-09-25)


### Features

* add explicit priority support ([#190](https://github.com/apache/casbin-pycasbin/issues/190)) ([9445086](https://github.com/apache/casbin-pycasbin/commit/94450866a6e3103df8a42fc76893f91e0cb555a4))

## [1.8.1](https://github.com/apache/casbin-pycasbin/compare/v1.8.0...v1.8.1) (2021-09-16)


### Bug Fixes

* fm instance property ([#189](https://github.com/apache/casbin-pycasbin/issues/189)) ([e06078a](https://github.com/apache/casbin-pycasbin/commit/e06078ada44ba9b3d794367bc8f52c1547dd2249))

# [1.8.0](https://github.com/apache/casbin-pycasbin/compare/v1.7.0...v1.8.0) (2021-08-31)


### Features

* PyCasbin Watcher interfaces added ([#186](https://github.com/apache/casbin-pycasbin/issues/186)) ([d98429f](https://github.com/apache/casbin-pycasbin/commit/d98429f02ac130fc5b7c4ad1448d967998c3d891))

# [1.7.0](https://github.com/apache/casbin-pycasbin/compare/v1.6.0...v1.7.0) (2021-08-29)


### Features

* support in operator on list/set and other compound types ([3f6ee8f](https://github.com/apache/casbin-pycasbin/commit/3f6ee8f0069ce0a3e0554b5143403a28c6afdfc1))

# [1.6.0](https://github.com/apache/casbin-pycasbin/compare/v1.5.0...v1.6.0) (2021-08-27)


### Features

* key_match4 builtin operator added ([#183](https://github.com/apache/casbin-pycasbin/issues/183)) ([ef127b3](https://github.com/apache/casbin-pycasbin/commit/ef127b352313fb17b3010d5a9bb5029e732c1546))

# [1.5.0](https://github.com/apache/casbin-pycasbin/compare/v1.4.0...v1.5.0) (2021-08-17)


### Features

* multiple request, policy, effect, matcher type support ([#181](https://github.com/apache/casbin-pycasbin/issues/181)) ([468503b](https://github.com/apache/casbin-pycasbin/commit/468503b1c573ac835e55eb4d0d6d23b638030c63))

# [1.4.0](https://github.com/apache/casbin-pycasbin/compare/v1.3.0...v1.4.0) (2021-07-19)


### Features

* finish up UpdateAdapter ([#177](https://github.com/apache/casbin-pycasbin/issues/177)) ([d69a2df](https://github.com/apache/casbin-pycasbin/commit/d69a2dfa7711aebcf7cec880fa724f5d3b3d3944))

# [1.3.0](https://github.com/apache/casbin-pycasbin/compare/v1.2.1...v1.3.0) (2021-07-04)


### Features

* add API for role manager besides "g" ([#173](https://github.com/apache/casbin-pycasbin/issues/173)) ([23d39a5](https://github.com/apache/casbin-pycasbin/commit/23d39a56da06968ab76659a30b430054c45db14b))

## [1.2.1](https://github.com/apache/casbin-pycasbin/compare/v1.2.0...v1.2.1) (2021-06-30)


### Bug Fixes

* matching_func works with multiply match ([#172](https://github.com/apache/casbin-pycasbin/issues/172)) ([bbe45ad](https://github.com/apache/casbin-pycasbin/commit/bbe45ad8a526477d0c0ca3c3915896e85cbfb2f4))

# [1.2.0](https://github.com/apache/casbin-pycasbin/compare/v1.1.3...v1.2.0) (2021-06-27)


### Features

* add support for add_domain_matching_function ([#165](https://github.com/apache/casbin-pycasbin/issues/165)) ([19b9503](https://github.com/apache/casbin-pycasbin/commit/19b9503ced6e75ec9a818e2fb1803319ea997166))

## [1.1.3](https://github.com/apache/casbin-pycasbin/compare/v1.1.2...v1.1.3) (2021-06-16)


### Bug Fixes

* get_implicit_users_for_permission() ([#168](https://github.com/apache/casbin-pycasbin/issues/168)) ([92e1110](https://github.com/apache/casbin-pycasbin/commit/92e1110e18b73cf993935bbf9db3bfb79be59e67))

## [1.1.2](https://github.com/apache/casbin-pycasbin/compare/v1.1.1...v1.1.2) (2021-06-07)


### Bug Fixes

* start auto loading policy for SyncedEnforcer ([4724f7a](https://github.com/apache/casbin-pycasbin/commit/4724f7a2c137ba5357634aee1eebc1b1c28959f9))

## [1.1.1](https://github.com/apache/casbin-pycasbin/compare/v1.1.0...v1.1.1) (2021-05-24)


### Bug Fixes

* function 'keyMatch3' not defined ([e97bb6a](https://github.com/apache/casbin-pycasbin/commit/e97bb6aadc58faca33d6c606d9bae31adfbd2259))

# [1.1.0](https://github.com/apache/casbin-pycasbin/compare/v1.0.6...v1.1.0) (2021-05-23)


### Bug Fixes

* enforce_ex now works fine when it was disabled ([15f58c9](https://github.com/apache/casbin-pycasbin/commit/15f58c9af82b10e1a6dd4ce584ea39f1235031b9))


### Features

* Use named loggers ([#153](https://github.com/apache/casbin-pycasbin/issues/153)) ([40e7f00](https://github.com/apache/casbin-pycasbin/commit/40e7f001c77034854e0916dba13bc87f30c2ce7d))

## [1.0.6](https://github.com/apache/casbin-pycasbin/compare/v1.0.5...v1.0.6) (2021-05-13)


### Bug Fixes

* optimized install_requires parsing process ([34d3a4f](https://github.com/apache/casbin-pycasbin/commit/34d3a4f5cfb120e0b074c557e831c74fb0e3101f))

## [1.0.5](https://github.com/apache/casbin-pycasbin/compare/v1.0.4...v1.0.5) (2021-05-12)


### Bug Fixes

* replace fnmatch with wcmatch for glob match, keep same behavior with Go Casbin ([#149](https://github.com/apache/casbin-pycasbin/issues/149)) ([906f40c](https://github.com/apache/casbin-pycasbin/commit/906f40c6c6b0d9e31104ca3ea92e4a8498c30619))

## [1.0.4](https://github.com/apache/casbin-pycasbin/compare/v1.0.3...v1.0.4) (2021-04-24)


### Performance Improvements

* remove unused variable ([e642898](https://github.com/apache/casbin-pycasbin/commit/e642898c5a0b9a8ccefb2104321985b82f420aa4))

## [1.0.3](https://github.com/apache/casbin-pycasbin/compare/v1.0.2...v1.0.3) (2021-04-23)


### Bug Fixes

* r.user.name -> r_user_name instead of r_user.name in ABAC model ([192529e](https://github.com/apache/casbin-pycasbin/commit/192529e11a8ddc848f3f2ee22c448c8afaf41f1b))

## [1.0.2](https://github.com/apache/casbin-pycasbin/compare/v1.0.1...v1.0.2) (2021-04-12)


### Bug Fixes

* rename enforceEx() to enforce_ex() ([#143](https://github.com/apache/casbin-pycasbin/issues/143)) ([e52351a](https://github.com/apache/casbin-pycasbin/commit/e52351a41c91d2546dddbc4f448c59ff70e9de1a))

## [1.0.1](https://github.com/apache/casbin-pycasbin/compare/v1.0.0...v1.0.1) (2021-04-09)


### Bug Fixes

* wrong domain length judge and bug in build_incremental_role_links() ([#139](https://github.com/apache/casbin-pycasbin/issues/139)) ([51b8833](https://github.com/apache/casbin-pycasbin/commit/51b883301e0f2c104ef31658e2074ac6ca586451))

# [1.0.0](https://github.com/apache/casbin-pycasbin/compare/v0.20.0...v1.0.0) (2021-04-06)


### Features

* add EnforceEx ([#134](https://github.com/apache/casbin-pycasbin/issues/134)) ([c577e1d](https://github.com/apache/casbin-pycasbin/commit/c577e1da65e3ddf4cf360d851f9f9a5ef6c94650))


### BREAKING CHANGES

* Custom effectors will need a rewrite

Signed-off-by: Andreas Bichinger <andreas.bichinger@gmail.com>

Co-authored-by: Andreas Bichinger <andreas.bichinger@gmail.com>

# [0.20.0](https://github.com/apache/casbin-pycasbin/compare/v0.19.2...v0.20.0) (2021-04-06)


### Features

* added distributed enforcer file along with respective unit tests ([f167ebf](https://github.com/apache/casbin-pycasbin/commit/f167ebf40f5d170745a3f48692d2185e205f3449))

## [0.19.2](https://github.com/apache/casbin-pycasbin/compare/v0.19.1...v0.19.2) (2021-04-01)


### Bug Fixes

* Added checks in init_with_model_and_adapter in CoreEnforcer ([1c55727](https://github.com/apache/casbin-pycasbin/commit/1c55727661616edc62865f4ffd15e3f262ddf1d5))

## [0.19.1](https://github.com/apache/casbin-pycasbin/compare/v0.19.0...v0.19.1) (2021-03-18)


### Bug Fixes

* relocate unittest and fix file path ([5ed07b2](https://github.com/apache/casbin-pycasbin/commit/5ed07b2f2aef9137a35048d3921d9986bae3254c))

# [0.19.0](https://github.com/apache/casbin-pycasbin/compare/v0.18.4...v0.19.0) (2021-03-18)


### Features

* Added dispatcher class ([5c4a992](https://github.com/apache/casbin-pycasbin/commit/5c4a992971a492874cfd32dc4eb94a3d61dbfcd7))

## [0.18.4](https://github.com/apache/casbin-pycasbin/compare/v0.18.3...v0.18.4) (2021-03-17)


### Performance Improvements

* Added code to convert config value to different types ([c87fdfa](https://github.com/apache/casbin-pycasbin/commit/c87fdfa37f68e9c32e198e044862a9a2f1cb36b7))

## [0.18.3](https://github.com/apache/casbin-pycasbin/compare/v0.18.2...v0.18.3) (2021-03-12)


### Performance Improvements

* refacto & improve performance ([ff7f288](https://github.com/apache/casbin-pycasbin/commit/ff7f288f487f5eab6b29898eb81f68257e6eb508))

## [0.18.2](https://github.com/apache/casbin-pycasbin/compare/v0.18.1...v0.18.2) (2021-03-02)


### Bug Fixes

* typo ([32a572f](https://github.com/apache/casbin-pycasbin/commit/32a572fcc4b114d93ffd59508a85e90297fd9744))

## [0.18.1](https://github.com/apache/casbin-pycasbin/compare/v0.18.0...v0.18.1) (2021-02-25)


### Performance Improvements

* reposition build_role_links() ([396ef7a](https://github.com/apache/casbin-pycasbin/commit/396ef7ae5a650a102751dd602aed4ddd2775efba))

# [0.18.0](https://github.com/apache/casbin-pycasbin/compare/v0.17.0...v0.18.0) (2021-02-23)


### Features

* add AddNamedDomainMatchingFunc and AddNamedMatchingFunc to enforcer ([#122](https://github.com/apache/casbin-pycasbin/issues/122)) ([e01f393](https://github.com/apache/casbin-pycasbin/commit/e01f393c8c41a954b201ecf9de2ad2350f87b651))

# [0.17.0](https://github.com/apache/casbin-pycasbin/compare/v0.16.2...v0.17.0) (2021-02-19)


### Features

* add update_policy() ([7f7d26f](https://github.com/apache/casbin-pycasbin/commit/7f7d26fe3f6cddcf54a2e42cef83565eb21e202c))

## [0.16.2](https://github.com/apache/casbin-pycasbin/compare/v0.16.1...v0.16.2) (2021-02-03)


### Performance Improvements

* remove duplicated check ([#117](https://github.com/apache/casbin-pycasbin/issues/117)) ([6aebadf](https://github.com/apache/casbin-pycasbin/commit/6aebadf0a344e453ca2a1e9c0ae3b0d2f1c3d2c7))

## [0.16.1](https://github.com/apache/casbin-pycasbin/compare/v0.16.0...v0.16.1) (2021-01-29)


### Bug Fixes

* role manager with matching_func ([8079cda](https://github.com/apache/casbin-pycasbin/commit/8079cda8a28409e9502508fe2bdf9b0bddac3f98))

# [0.16.0](https://github.com/apache/casbin-pycasbin/compare/v0.15.0...v0.16.0) (2021-01-09)


### Features

* add batch api to SyncedEnforcer ([9191ccd](https://github.com/apache/casbin-pycasbin/commit/9191ccd72cbeed6e36303d4cbf0407b626718421))
* add batch_adapter ([9470c3e](https://github.com/apache/casbin-pycasbin/commit/9470c3ebf678ac4c64bffea623fb9a974f4f2e95))

# [0.15.0](https://github.com/apache/casbin-pycasbin/compare/v0.14.0...v0.15.0) (2020-12-26)


### Features

* add filtered_adapter ([ee817b5](https://github.com/apache/casbin-pycasbin/commit/ee817b521b94aaf90533906efd158c761b25f9f4))

# [0.14.0](https://github.com/apache/casbin-pycasbin/compare/v0.13.0...v0.14.0) (2020-12-23)


### Features

* add function get_role_manager ([7fb1879](https://github.com/apache/casbin-pycasbin/commit/7fb1879e3bbdc77ea5e01ac46f96d81f917cb6fe))
* add SyncedEnforcer ([9439272](https://github.com/apache/casbin-pycasbin/commit/94392722a1fd4680a7f4072ae20b176e8225be15))

# [0.13.0](https://github.com/apache/casbin-pycasbin/compare/v0.12.0...v0.13.0) (2020-12-14)


### Features

* add glob pattern matching using fnmatch module ([41ba828](https://github.com/apache/casbin-pycasbin/commit/41ba828b2cecd21df79a5ec905d9d4de9506b918))

# [0.12.0](https://github.com/apache/casbin-pycasbin/compare/v0.11.0...v0.12.0) (2020-12-07)


### Features

* add semantic-release-pypi plugin ([e53d842](https://github.com/apache/casbin-pycasbin/commit/e53d84283952b3b66720e6d50ae91030880fe839))

# [0.11.0](https://github.com/apache/casbin-pycasbin/compare/v0.10.0...v0.11.0) (2020-12-01)


### Features

* add eval function ([9604fbf](https://github.com/apache/casbin-pycasbin/commit/9604fbf91a22149dab531183576c8a4e7078a4d0))

# [0.10.0](https://github.com/apache/casbin-pycasbin/compare/v0.9.0...v0.10.0) (2020-11-10)


### Bug Fixes

* improve KeyMatch and add tests ([f62a2b2](https://github.com/apache/casbin-pycasbin/commit/f62a2b2920e870a879d004148117019137805c09))


### Features

* support semantic-release ([f346ab4](https://github.com/apache/casbin-pycasbin/commit/f346ab45602d0820e88de5c3febfea4a6a5cc7b1))
