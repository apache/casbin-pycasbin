# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase

from casbin import util


class TestBuiltinOperators(TestCase):
    def test_key_match(self):
        self.assertFalse(util.key_match_func("/foo", "/"))
        self.assertTrue(util.key_match_func("/foo", "/foo"))
        self.assertTrue(util.key_match_func("/foo", "/foo*"))
        self.assertFalse(util.key_match_func("/foo", "/foo/*"))
        self.assertFalse(util.key_match_func("/foo/bar", "/foo"))
        self.assertTrue(util.key_match_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.key_match_func("/foobar", "/foo"))
        self.assertTrue(util.key_match_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match_func("/foobar", "/foo/*"))

        self.assertFalse(util.key_match2_func("/alice/all", "/:/all"))

    def test_key_get(self):
        self.assertEqual(util.key_get("/foo", "/foo"), "")
        self.assertEqual(util.key_get("/foo", "/foo*"), "")
        self.assertEqual(util.key_get("/foo", "/foo/*"), "")
        self.assertEqual(util.key_get("/foo/bar", "/foo"), "")
        self.assertEqual(util.key_get("/foo/bar", "/foo*"), "/bar")
        self.assertEqual(util.key_get("/foo/bar", "/foo/*"), "bar")
        self.assertEqual(util.key_get("/foobar", "/foo"), "")
        self.assertEqual(util.key_get("/foobar", "/foo*"), "bar")
        self.assertEqual(util.key_get("/foobar", "/foo/*"), "")

    def test_key_match2(self):
        self.assertFalse(util.key_match2_func("/foo", "/"))
        self.assertTrue(util.key_match2_func("/foo", "/foo"))
        self.assertTrue(util.key_match2_func("/foo", "/foo*"))
        self.assertFalse(util.key_match2_func("/foo", "/foo/*"))
        self.assertFalse(util.key_match2_func("/foo/bar", "/foo"))  # different with KeyMatch.
        self.assertFalse(util.key_match2_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match2_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.key_match2_func("/foobar", "/foo"))  # different with KeyMatch.
        self.assertFalse(util.key_match2_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match2_func("/foobar", "/foo/*"))

        self.assertFalse(util.key_match2_func("/", "/:resource"))
        self.assertTrue(util.key_match2_func("/resource1", "/:resource"))
        self.assertFalse(util.key_match2_func("/myid", "/:id/using/:resId"))
        self.assertTrue(util.key_match2_func("/myid/using/myresid", "/:id/using/:resId"))

        self.assertFalse(util.key_match2_func("/proxy/myid", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res/res2", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res/res2/res3", "/proxy/:id/*"))
        self.assertFalse(util.key_match2_func("/proxy/", "/proxy/:id/*"))

        self.assertTrue(util.key_match2_func("/alice", "/:id"))
        self.assertTrue(util.key_match2_func("/alice/all", "/:id/all"))
        self.assertFalse(util.key_match2_func("/alice", "/:id/all"))
        self.assertFalse(util.key_match2_func("/alice/all", "/:id"))

        self.assertFalse(util.key_match2_func("/alice/all", "/:/all"))

    def test_key_match2_multiple_wildcards(self):
        self.assertTrue(util.key_match2_func("/api/a/b/c/detail", "/api/*/*/*/detail"))
        self.assertTrue(util.key_match2_func("/api////detail", "/api/*/*/*/detail"))
        self.assertTrue(util.key_match2_func("/api/a/b/c/d/1/detail", "/api/*/*/:id/detail"))
        self.assertFalse(util.key_match2_func("/api/a/b/detail", "/api/*/*/*/detail"))
        self.assertFalse(util.key_match2_func("/api/a/b/c/detail/x", "/api/*/*/*/detail"))
        # used to take minutes because of regex backtracking
        self.assertFalse(util.key_match2_func("/api/" + "/" * 5000, "/api/*/*/*/detail"))

    def test_key_get2(self):
        self.assertEqual(util.key_get2("/foo", "/foo", "id"), "")
        self.assertEqual(util.key_get2("/foo", "/foo*", "id"), "")
        self.assertEqual(util.key_get2("/foo", "/foo/*", "id"), "")
        self.assertEqual(util.key_get2("/foo/bar", "/foo", "id"), "")
        self.assertEqual(util.key_get2("/foo/bar", "/foo*", "id"), "")
        self.assertEqual(util.key_get2("/foo/bar", "/foo/*", "id"), "")
        self.assertEqual(util.key_get2("/foobar", "/foo", "id"), "")
        self.assertEqual(util.key_get2("/foobar", "/foo*", "id"), "")
        self.assertEqual(util.key_get2("/foobar", "/foo/*", "id"), "")

        self.assertEqual(util.key_get2("/", "/:resource", "resource"), "")
        self.assertEqual(util.key_get2("/resource1", "/:resource", "resource"), "resource1")
        self.assertEqual(util.key_get2("/myid", "/:id/using/:resId", "id"), "")
        self.assertEqual(util.key_get2("/myid/using/myresid", "/:id/using/:resId", "id"), "myid")
        self.assertEqual(util.key_get2("/myid/using/myresid", "/:id/using/:resId", "resId"), "myresid")

        self.assertEqual(util.key_get2("/proxy/myid", "/proxy/:id/*", "id"), "")
        self.assertEqual(util.key_get2("/proxy/myid/", "/proxy/:id/*", "id"), "myid")
        self.assertEqual(util.key_get2("/proxy/myid/res", "/proxy/:id/*", "id"), "myid")
        self.assertEqual(util.key_get2("/proxy/myid/res/res2", "/proxy/:id/*", "id"), "myid")
        self.assertEqual(util.key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id"), "myid")
        self.assertEqual(util.key_get2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id"), "myid")
        self.assertEqual(util.key_get2("/proxy/", "/proxy/:id/*", "id"), "")

        self.assertEqual(util.key_get2("/alice", "/:id", "id"), "alice")
        self.assertEqual(util.key_get2("/alice/all", "/:id/all", "id"), "alice")
        self.assertEqual(util.key_get2("/alice", "/:id/all", "id"), "")
        self.assertEqual(util.key_get2("/alice/all", "/:id", "id"), "")

        self.assertEqual(util.key_get2("/alice/all", "/:/all", ""), "")

    def test_key_match3(self):
        self.assertTrue(util.key_match3_func("/foo", "/foo"))
        self.assertTrue(util.key_match3_func("/foo", "/foo*"))
        self.assertFalse(util.key_match3_func("/foo", "/foo/*"))
        self.assertFalse(util.key_match3_func("/foo/bar", "/foo"))
        self.assertFalse(util.key_match3_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match3_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.key_match3_func("/foobar", "/foo"))
        self.assertFalse(util.key_match3_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match3_func("/foobar", "/foo/*"))

        self.assertFalse(util.key_match3_func("/", "/{resource}"))
        self.assertTrue(util.key_match3_func("/resource1", "/{resource}"))
        self.assertFalse(util.key_match3_func("/myid", "/{id}/using/{resId}"))
        self.assertTrue(util.key_match3_func("/myid/using/myresid", "/{id}/using/{resId}"))

        self.assertFalse(util.key_match3_func("/proxy/myid", "/proxy/{id}/*"))
        self.assertTrue(util.key_match3_func("/proxy/myid/", "/proxy/{id}/*"))
        self.assertTrue(util.key_match3_func("/proxy/myid/res", "/proxy/{id}/*"))
        self.assertTrue(util.key_match3_func("/proxy/myid/res/res2", "/proxy/{id}/*"))
        self.assertTrue(util.key_match3_func("/proxy/myid/res/res2/res3", "/proxy/{id}/*"))
        self.assertFalse(util.key_match3_func("/proxy/", "/proxy/{id}/*"))

        self.assertFalse(util.key_match3_func("/myid/using/myresid", "/{id/using/{resId}"))

    def test_key_get3(self):
        self.assertEqual(util.key_get3("/foo", "/foo", "id"), "")
        self.assertEqual(util.key_get3("/foo", "/foo*", "id"), "")
        self.assertEqual(util.key_get3("/foo", "/foo/*", "id"), "")
        self.assertEqual(util.key_get3("/foo/bar", "/foo", "id"), "")
        self.assertEqual(util.key_get3("/foo/bar", "/foo*", "id"), "")
        self.assertEqual(util.key_get3("/foo/bar", "/foo/*", "id"), "")
        self.assertEqual(util.key_get3("/foobar", "/foo", "id"), "")
        self.assertEqual(util.key_get3("/foobar", "/foo*", "id"), "")
        self.assertEqual(util.key_get3("/foobar", "/foo/*", "id"), "")

        self.assertEqual(util.key_get3("/", "/{resource}", "resource"), "")
        self.assertEqual(util.key_get3("/resource1", "/{resource}", "resource"), "resource1")
        self.assertEqual(util.key_get3("/myid", "/{id}/using/{resId}", "id"), "")
        self.assertEqual(util.key_get3("/myid/using/myresid", "/{id}/using/{resId}", "id"), "myid")
        self.assertEqual(util.key_get3("/myid/using/myresid", "/{id}/using/{resId}", "resId"), "myresid")

        self.assertEqual(util.key_get3("/proxy/myid", "/proxy/{id}/*", "id"), "")
        self.assertEqual(util.key_get3("/proxy/myid/", "/proxy/{id}/*", "id"), "myid")
        self.assertEqual(util.key_get3("/proxy/myid/res", "/proxy/{id}/*", "id"), "myid")
        self.assertEqual(util.key_get3("/proxy/myid/res/res2", "/proxy/{id}/*", "id"), "myid")
        self.assertEqual(util.key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id"), "myid")
        self.assertEqual(util.key_get3("/proxy/", "/proxy/{id}/*", "id"), "")

        self.assertEqual(
            util.key_get3("/api/group1_group_name/project1_admin/info", "/api/{proj}_admin/info", "proj"), ""
        )
        self.assertEqual(util.key_get3("/{id/using/myresid", "/{id/using/{resId}", "resId"), "myresid")
        self.assertEqual(util.key_get3("/{id/using/myresid/status}", "/{id/using/{resId}/status}", "resId"), "myresid")

        self.assertEqual(util.key_get3("/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res"), "res3")
        self.assertEqual(util.key_get3("/api/project1_admin/info", "/api/{proj}_admin/info", "proj"), "project1")
        self.assertEqual(
            util.key_get3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "g"),
            "group1",
        )
        self.assertEqual(
            util.key_get3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "gn"),
            "group_name",
        )
        self.assertEqual(
            util.key_get3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "proj"),
            "project1",
        )

    def test_key_match4(self):
        self.assertTrue(util.key_match4_func("/parent/123/child/123", "/parent/{id}/child/{id}"))
        self.assertFalse(util.key_match4_func("/parent/123/child/456", "/parent/{id}/child/{id}"))

        self.assertTrue(util.key_match4_func("/parent/123/child/123", "/parent/{id}/child/{another_id}"))
        self.assertTrue(util.key_match4_func("/parent/123/child/456", "/parent/{id}/child/{another_id}"))

        self.assertTrue(util.key_match4_func("/parent/123/child/456", "/parent/{id}/child/{another_id}"))
        self.assertFalse(util.key_match4_func("/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}"))
        self.assertFalse(util.key_match4_func("/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}"))
        self.assertFalse(util.key_match4_func("/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}"))
        self.assertFalse(util.key_match4_func("/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}"))

        self.assertFalse(util.key_match4_func("/parent/123/child/123", "/parent/{i/d}/child/{i/d}"))

    def test_key_match5_func(self):
        self.assertTrue(util.key_match5_func("/parent/child?status=1&type=2", "/parent/child"))
        self.assertFalse(util.key_match5_func("/parent?status=1&type=2", "/parent/child"))

        self.assertTrue(util.key_match5_func("/parent/child/?status=1&type=2", "/parent/child/"))
        self.assertFalse(util.key_match5_func("/parent/child/?status=1&type=2", "/parent/child"))
        self.assertFalse(util.key_match5_func("/parent/child?status=1&type=2", "/parent/child/"))

        self.assertTrue(util.key_match5_func("/foo", "/foo"))
        self.assertTrue(util.key_match5_func("/foo", "/foo*"))
        self.assertFalse(util.key_match5_func("/foo", "/foo/*"))
        self.assertFalse(util.key_match5_func("/foo/bar", "/foo"))
        self.assertFalse(util.key_match5_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match5_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.key_match5_func("/foobar", "/foo"))
        self.assertFalse(util.key_match5_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match5_func("/foobar", "/foo/*"))

        self.assertFalse(util.key_match5_func("/", "/{resource}"))
        self.assertTrue(util.key_match5_func("/resource1", "/{resource}"))
        self.assertFalse(util.key_match5_func("/myid", "/{id}/using/{resId}"))
        self.assertTrue(util.key_match5_func("/myid/using/myresid", "/{id}/using/{resId}"))

        self.assertFalse(util.key_match5_func("/proxy/myid", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res/res2", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res/res2/res3", "/proxy/{id}/*"))
        self.assertFalse(util.key_match5_func("/proxy/", "/proxy/{id}/*"))

        self.assertFalse(util.key_match5_func("/proxy/myid?status=1&type=2", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res?status=1&type=2", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res/res2?status=1&type=2", "/proxy/{id}/*"))
        self.assertTrue(util.key_match5_func("/proxy/myid/res/res2/res3?status=1&type=2", "/proxy/{id}/*"))
        self.assertFalse(util.key_match5_func("/proxy/", "/proxy/{id}/*"))

    def test_regex_match(self):
        self.assertTrue(util.regex_match_func("/topic/create", "/topic/create"))
        self.assertTrue(util.regex_match_func("/topic/create/123", "/topic/create"))
        self.assertFalse(util.regex_match_func("/topic/delete", "/topic/create"))
        self.assertFalse(util.regex_match_func("/topic/edit", "/topic/edit/[0-9]+"))
        self.assertTrue(util.regex_match_func("/topic/edit/123", "/topic/edit/[0-9]+"))
        self.assertFalse(util.regex_match_func("/topic/edit/abc", "/topic/edit/[0-9]+"))
        self.assertFalse(util.regex_match_func("/foo/delete/123", "/topic/delete/[0-9]+"))
        self.assertTrue(util.regex_match_func("/topic/delete/0", "/topic/delete/[0-9]+"))
        self.assertFalse(util.regex_match_func("/topic/edit/123s", "/topic/delete/[0-9]+"))

    def test_glob_match(self):
        self.assertTrue(util.glob_match_func("/foo", "/foo"))
        self.assertTrue(util.glob_match_func("/foo", "/foo*"))
        self.assertFalse(util.glob_match_func("/foo", "/foo/*"))
        self.assertFalse(util.glob_match_func("/foo/bar", "/foo"))
        self.assertFalse(util.glob_match_func("/foo/bar", "/foo*"))
        self.assertTrue(util.glob_match_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.glob_match_func("/foobar", "/foo"))
        self.assertTrue(util.glob_match_func("/foobar", "/foo*"))
        self.assertFalse(util.glob_match_func("/foobar", "/foo/*"))

        self.assertTrue(util.glob_match_func("/foo", "*/foo"))
        self.assertTrue(util.glob_match_func("/foo", "*/foo*"))
        self.assertFalse(util.glob_match_func("/foo", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/foo/bar", "*/foo"))
        self.assertFalse(util.glob_match_func("/foo/bar", "*/foo*"))
        self.assertTrue(util.glob_match_func("/foo/bar", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/foobar", "*/foo"))
        self.assertTrue(util.glob_match_func("/foobar", "*/foo*"))
        self.assertFalse(util.glob_match_func("/foobar", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "*/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "*/foo"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "*/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "*/foo/*"))

        self.assertTrue(util.glob_match_func("/foo", "**/foo"))
        self.assertTrue(util.glob_match_func("/foo", "**/foo**"))
        self.assertTrue(util.glob_match_func("/foo", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/foo/bar", "**/foo"))
        self.assertFalse(util.glob_match_func("/foo/bar", "**/foo**"))
        self.assertTrue(util.glob_match_func("/foo/bar", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/foobar", "**/foo"))
        self.assertTrue(util.glob_match_func("/foobar", "**/foo**"))
        self.assertFalse(util.glob_match_func("/foobar", "**/foo/**"))

        self.assertTrue(util.glob_match_func("/prefix/foo", "**/foo"))
        self.assertTrue(util.glob_match_func("/prefix/foo", "**/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/foo", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "**/foo"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "**/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/foo/bar", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "**/foo"))
        self.assertTrue(util.glob_match_func("/prefix/foobar", "**/foo**"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "**/foo/**"))

        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo", "**/foo"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo", "**/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "**/foo"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "**/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo/bar", "**/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "**/foo"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foobar", "**/foo**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "**/foo/**"))

        self.assertTrue(util.glob_match_func("/foo", "*/foo**"))
        self.assertTrue(util.glob_match_func("/foo", "**/foo*"))
        self.assertTrue(util.glob_match_func("/foo", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/foo", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/foo/bar", "*/foo**"))
        self.assertFalse(util.glob_match_func("/foo/bar", "**/foo*"))
        self.assertTrue(util.glob_match_func("/foo/bar", "*/foo/**"))
        self.assertTrue(util.glob_match_func("/foo/bar", "**/foo/*"))
        self.assertTrue(util.glob_match_func("/foobar", "*/foo**"))
        self.assertTrue(util.glob_match_func("/foobar", "**/foo*"))
        self.assertFalse(util.glob_match_func("/foobar", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/foobar", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "*/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/foo", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/foo", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "*/foo**"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foo/bar", "*/foo/**"))
        self.assertTrue(util.glob_match_func("/prefix/foo/bar", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "*/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/foobar", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/foobar", "**/foo/*"))

        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "*/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "*/foo**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foo/bar", "*/foo/**"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foo/bar", "**/foo/*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "*/foo**"))
        self.assertTrue(util.glob_match_func("/prefix/subprefix/foobar", "**/foo*"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "*/foo/**"))
        self.assertFalse(util.glob_match_func("/prefix/subprefix/foobar", "**/foo/*"))

        self.assertTrue(util.glob_match_func("/f", "/?"))
        self.assertTrue(util.glob_match_func("/foobar", "/foo?ar"))
        self.assertFalse(util.glob_match_func("/fooar", "/foo?ar"))
        self.assertTrue(util.glob_match_func("/foobbar", "/foo??ar"))
        self.assertTrue(util.glob_match_func("/foobbbbar", "/foo????ar"))
        self.assertTrue(util.glob_match_func("/foobar", "/foo[bc]ar"))
        self.assertFalse(util.glob_match_func("/fooaar", "/foo[bc]ar"))
        self.assertFalse(util.glob_match_func("/foodar", "/foo[bc]ar"))
        self.assertTrue(util.glob_match_func("/foobar", "/foo[b-b]ar"))
        self.assertFalse(util.glob_match_func("/fooaar", "/foo[b-c]ar"))
        self.assertTrue(util.glob_match_func("/foobar", "/foo[b-c]ar"))
        self.assertTrue(util.glob_match_func("/foocar", "/foo[b-c]ar"))
        self.assertFalse(util.glob_match_func("/foodar", "/foo[b-c]ar"))
        self.assertTrue(util.glob_match_func("/foo1ar", "/foo[!234]ar"))
        self.assertFalse(util.glob_match_func("/foo3ar", "/foo[!234]ar"))
        self.assertTrue(util.glob_match_func("/foo5ar", "/foo[!234]ar"))
        self.assertTrue(util.glob_match_func("/foo1ar", "/foo[!2-5]ar"))
        self.assertFalse(util.glob_match_func("/foo2ar", "/foo[!2-5]ar"))
        self.assertTrue(util.glob_match_func("/foo1ar", "/foo[^234]ar"))
        self.assertFalse(util.glob_match_func("/foo3ar", "/foo[^234]ar"))
        self.assertTrue(util.glob_match_func("/foo5ar", "/foo[^234]ar"))
        self.assertTrue(util.glob_match_func("/foo1ar", "/foo[^2-5]ar"))
        self.assertFalse(util.glob_match_func("/foo2ar", "/foo[^2-5]ar"))

        self.assertTrue(util.glob_match_func("\\", "\\\\"))
        self.assertTrue(util.glob_match_func("/a", "/\\a"))
        self.assertTrue(util.glob_match_func("/*", "/\\*"))
        self.assertFalse(util.glob_match_func("a", "\\?"))
        self.assertTrue(util.glob_match_func("?", "\\?"))
        self.assertTrue(util.glob_match_func("\n", "\n"))
        self.assertFalse(util.glob_match_func("\n", "\\n"))
        self.assertTrue(util.glob_match_func("[", "\\["))
        self.assertTrue(util.glob_match_func("*", "\\*"))
        self.assertTrue(util.glob_match_func("\\*", "\\\\\\*"))

    def test_ip_match(self):
        self.assertTrue(util.ip_match_func("192.168.2.123", "192.168.2.0/24"))
        self.assertFalse(util.ip_match_func("192.168.2.123", "192.168.3.0/24"))
        self.assertTrue(util.ip_match_func("192.168.2.123", "192.168.2.0/16"))
        self.assertTrue(util.ip_match_func("192.168.2.123", "192.168.2.123"))
        self.assertTrue(util.ip_match_func("192.168.2.123", "192.168.2.123/32"))
        self.assertTrue(util.ip_match_func("10.0.0.11", "10.0.0.0/8"))
        self.assertFalse(util.ip_match_func("11.0.0.123", "10.0.0.0/8"))

    def test_time_match(self):
        self.assertFalse(util.time_match_func("0001-01-01 00:00:00", "0001-01-02 00:00:00"))
        self.assertTrue(util.time_match_func("0001-01-01 00:00:00", "9999-12-30 00:00:00"))
        self.assertTrue(util.time_match_func("_", "_"))
        self.assertTrue(util.time_match_func("_", "9999-12-30 00:00:00"))
        self.assertFalse(util.time_match_func("_", "0001-01-02 00:00:00"))
        self.assertTrue(util.time_match_func("0001-01-01 00:00:00", "_"))
        self.assertFalse(util.time_match_func("9999-12-30 00:00:00", "_"))
