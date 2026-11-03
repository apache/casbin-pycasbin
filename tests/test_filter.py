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

import os
from unittest import TestCase
import casbin
from tests.test_enforcer import get_examples, get_examples_copy
from casbin.persist.adapters import FilteredFileAdapter
from casbin.persist.adapters.filtered_file_adapter import filter_line, filter_words


class Filter:
    # P,G are strings
    P = []
    G = []


class TestFilteredFileAdapter(TestCase):
    def test_init_filtered_adapter(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        self.assertFalse(e.has_policy(["admin", "domain1", "data1", "read"]))

    def test_load_filtered_policy(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        with self.assertRaises(RuntimeError):
            e.save_policy()

        with self.assertRaises(RuntimeError):
            e.get_adapter().save_policy(e.get_model())

    def test_append_filtered_policy(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        filter.P = ["", "domain2"]
        filter.G = ["", "", "domain2"]
        try:
            e.load_increment_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_filtered_policy_invalid_filter(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = ["", "domain1"]

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(filter)

    def test_filtered_policy_empty_filter(self):
        adapter = FilteredFileAdapter(get_examples_copy("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        try:
            e.load_filtered_policy(None)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if e.is_filtered():
            raise RuntimeError("adapter did not reset the filtered flag correctly")

        try:
            e.save_policy()
        except:
            raise RuntimeError("unexpected error in SavePolicy")

    def test_unsupported_filtered_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        with self.assertRaises(ValueError):
            e.load_filtered_policy(filter)

    def test_filtered_adapter_empty_filepath(self):
        adapter = FilteredFileAdapter("")
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)

    def test_filtered_adapter_invalid_filepath(self):
        adapter = FilteredFileAdapter(get_examples("does_not_exist_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)

    def test_empty_filter_array(self):
        """Test filter for empty array."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = []
        filter.G = []

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_empty_string_filter(self):
        """Test the filter for all empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "", ""]
        filter.G = ["", "", ""]

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_mixed_empty_filter(self):
        """Test the filter for mixed empty and non-empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1", ""]
        filter.G = ["", "", "domain1"]

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_nonexistent_domain_filter(self):
        """Testing the filter for a non-existent domain."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain3"]
        filter.G = ["", "", "domain3"]

        e.load_filtered_policy(filter)
        self.assertFalse(e.has_policy(["admin", "domain3", "data3", "read"]))

    def test_empty_filter_array(self):
        """Test filter for empty array."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = []
        filter.G = []

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with empty filter arrays")

        self.assertFalse(e.is_filtered(), "Adapter should not be marked as filtered with empty filters")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_empty_string_filter(self):
        """Test the filter for all empty strings."""
        adapter = FilteredFileAdapter(get_examples_copy("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "", ""]
        filter.G = ["", "", ""]

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with empty string filters")

        self.assertFalse(e.is_filtered(), "Adapter should not be marked as filtered with empty string filters")

        try:
            e.save_policy()
        except:
            raise RuntimeError("unexpected error in SavePolicy with empty string filters")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_mixed_empty_filter(self):
        """Test the filter for mixed empty and non-empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1", ""]
        filter.G = ["", "", "domain1"]

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with mixed empty filters")

        self.assertTrue(e.is_filtered(), "Adapter should be marked as filtered")

        with self.assertRaises(RuntimeError):
            e.save_policy()

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_whitespace_filter(self):
        """Test the filter for all blank characters."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = [" ", "  ", "\t"]
        filter.G = ["\n", " ", "  "]

        e.load_filtered_policy(filter)

        self.assertFalse(e.is_filtered())
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_filter_line_edge_cases(self):
        """Test the boundary cases of the filter_line function."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))

        self.assertFalse(filter_line("", [[""], [""]]))

        self.assertFalse(filter_line("invalid_line", [[""], [""]]))

        self.assertFalse(filter_line("p, admin, domain1, data1, read", None))

    def test_filter_words_edge_cases(self):
        """Test the boundary cases of the filter_words function."""
        self.assertTrue(filter_words(["p"], ["filter1", "filter2"]))

        self.assertFalse(filter_words(["p", "admin", "domain1"], []))

        line = ["admin", "domain1", "data*", "read"]
        filter = ["", "", "data1", ""]
        self.assertTrue(filter_words(line, filter))

    def test_load_filtered_policy_with_comments(self):
        """Test loading filtering policies with comments."""
        import tempfile
        import shutil

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            with open(get_examples("rbac_with_domains_policy.csv"), "r") as source:
                shutil.copyfileobj(source, temp_file)

            temp_file.write("\n# This is a comment\np, admin, domain1, data3, read")
            temp_file.flush()

            temp_path = temp_file.name

        try:
            adapter = FilteredFileAdapter(temp_path)
            e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
            filter = Filter()
            filter.P = ["", "domain1"]
            filter.G = ["", "", "domain1"]

            e.load_filtered_policy(filter)
            self.assertTrue(e.has_policy(["admin", "domain1", "data3", "read"]))
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
