"""The indexer client: credentials, TLS switches, 429, errors."""

import os
import shutil
import tempfile
import unittest

import fake_indexer as F

from rmig.api import client as C


class TestCredentials(unittest.TestCase):
    def test_from_environment(self):
        env = {C.ENV_URL: "https://idx:9200", C.ENV_USER: "u", C.ENV_PASSWORD: "p"}
        self.assertEqual(C.resolve_connection(env=env), ("https://idx:9200", "u", "p"))

    def test_url_argument_wins(self):
        env = {C.ENV_URL: "https://idx:9200", C.ENV_USER: "u", C.ENV_PASSWORD: "p"}
        self.assertEqual(C.resolve_connection("https://other:9200", env=env)[0], "https://other:9200")

    def test_from_file(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "creds")
            with open(path, "w") as fh:
                fh.write("admin:pa:ss\n")
            self.assertEqual(C.resolve_connection("https://x", path, env={}), ("https://x", "admin", "pa:ss"))
            with open(path, "w") as fh:
                fh.write("no-separator\n")
            with self.assertRaises(C.CredentialsError):
                C.resolve_connection("https://x", path, env={})
        finally:
            shutil.rmtree(d)

    def test_missing_names_what_without_values(self):
        with self.assertRaises(C.CredentialsError) as cm:
            C.resolve_connection(env={C.ENV_URL: "https://x", C.ENV_USER: "u"})
        self.assertIn(C.ENV_PASSWORD, str(cm.exception))
        with self.assertRaises(C.CredentialsError):
            C.resolve_connection(env={})

    def test_repr_hides_the_secret(self):
        c = C.Client("https://x:9200/", "u", "s3cr3t-value")
        self.assertNotIn("s3cr3t-value", repr(c))
        self.assertNotIn("s3cr3t-value", str(vars(c).get("user")))


class TestTls(unittest.TestCase):
    def test_verified_by_default_and_insecure_only_when_asked(self):
        import importlib

        ssl = importlib.import_module("ssl")
        c = C.Client("https://x:9200", "u", "p")
        ctx = c._context(ssl)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        c = C.Client("https://x:9200", "u", "p", insecure=True)
        ctx = c._context(ssl)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_missing_ca_file_is_an_environment_error(self):
        fake = F.FakeIndexer().start()
        work = F.make_workdir()
        try:
            code, out = F.run_command(fake, ["apply", "--ca", "/nonexistent/ca.pem"], work)
            self.assertEqual(code, 2)
            self.assertIn("CA file", out)
        finally:
            fake.stop()
            shutil.rmtree(work)


class TestRequests(unittest.TestCase):
    def setUp(self):
        self.fake = F.FakeIndexer().start()
        self.sleeps = []
        self.c = C.Client(self.fake.url, "tester", "pw-not-logged", sleep=self.sleeps.append)

    def tearDown(self):
        self.fake.stop()

    def test_429_is_retried_with_a_wait(self):
        self.fake.answer_429 = 2
        res = self.c.request("POST", "/_plugins/_content_manager/integrations", {"resource": {
            "metadata": {"title": "t", "author": "a"}, "category": "other"}})
        self.assertTrue(res["message"])
        self.assertEqual(self.sleeps, [0.5, 1.0])

    def test_429_backoff_is_exponential_and_bounded(self):
        self.fake.answer_429 = 99
        with self.assertRaises(C.ApiError) as cm:
            self.c.request("POST", "/_plugins/_content_manager/integrations", {"resource": {}})
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(self.sleeps[:5], [0.5, 1.0, 2.0, 4.0, 8.0])
        self.assertLessEqual(sum(self.sleeps), C.RETRY_BUDGET)
        self.assertGreaterEqual(sum(self.sleeps), C.RETRY_BUDGET - C.RETRY_MAX_WAIT)

    def test_429_gives_up(self):
        self.fake.answer_429 = 99
        c = C.Client(self.fake.url, "tester", "pw", retries=2, sleep=lambda s: None)
        with self.assertRaises(C.ApiError) as cm:
            c.request("POST", "/_plugins/_content_manager/integrations", {"resource": {}})
        self.assertEqual(cm.exception.status, 429)

    def test_error_carries_method_path_status_and_body(self):
        with self.assertRaises(C.ApiError) as cm:
            self.c.request("POST", "/_plugins/_content_manager/rules", {"integration": "nope", "resource": {}})
        e = cm.exception
        self.assertEqual((e.method, e.path, e.status), ("POST", "/_plugins/_content_manager/rules", 400))
        self.assertIn("Integration [nope] not found.", str(e))
        self.assertNotIn("pw-not-logged", str(e))

    def test_failed_shards_are_an_error(self):
        orig = self.fake.search

        def bad(rtype, body):
            status, obj = orig(rtype, body)
            obj["_shards"]["failed"] = 1
            return status, obj

        self.fake.search = bad
        with self.assertRaises(C.ApiError):
            self.c.request("POST", "/wazuh-threatintel-rules/_search", {"query": {"term": {"space.name": {"value": "draft"}}}})

    def test_unreachable(self):
        c = C.Client("http://127.0.0.1:9", "u", "p", timeout=2)
        with self.assertRaises(C.ConnectionFailed):
            c.request("GET", "/")


class TestTransport(unittest.TestCase):
    def test_redirect_is_never_followed(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = []

        class Other(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/steal" % other.server_address[1])
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET

        other = ThreadingHTTPServer(("127.0.0.1", 0), Other)
        red = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        for srv in (other, red):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = C.Client("http://127.0.0.1:%d" % red.server_address[1], "u", "pw-secret")
            for method in ("GET", "POST"):
                with self.assertRaises(C.RedirectRefused) as cm:
                    c.call(method, "/x", {"a": 1} if method == "POST" else None)
                self.assertNotIn("pw-secret", str(cm.exception))
            self.assertEqual(seen, [])
        finally:
            other.shutdown()
            other.server_close()
            red.shutdown()
            red.server_close()

    def test_url_with_userinfo_or_other_scheme_is_refused(self):
        env = {C.ENV_USER: "u", C.ENV_PASSWORD: "p"}
        for url in ("https://admin:S3cret@127.0.0.1:9200", "https://admin@h", "file:///etc/passwd", "ftp://h"):
            with self.assertRaises(C.CredentialsError) as cm:
                C.resolve_connection(url, env=env)
            self.assertNotIn("S3cret", str(cm.exception))
        self.assertEqual(C.resolve_connection("HTTPS://h:9200", env=env)[0], "HTTPS://h:9200")

    def test_userinfo_never_printed(self):
        c = C.Client("http://admin:S3cret@127.0.0.1:9", "u", "p", timeout=2)
        with self.assertRaises(C.ConnectionFailed) as cm:
            c.request("GET", "/")
        self.assertNotIn("S3cret", str(cm.exception))
        self.assertNotIn("S3cret", repr(c))

    def test_http_and_insecure_are_warned(self):
        self.assertEqual(C.transport_warnings("https://h", False), [])
        self.assertEqual(len(C.transport_warnings("http://h", False)), 1)
        self.assertEqual(len(C.transport_warnings("HTTP://h", True)), 2)
        fake = F.FakeIndexer().start()
        work = F.make_workdir()
        try:
            _code, out = F.run_command(fake, ["apply", "--dry-run"], work)
            self.assertIn("plain http", out)
        finally:
            fake.stop()
            shutil.rmtree(work)


class TestSecretsNeverWritten(unittest.TestCase):
    def test_no_secret_in_workdir_nor_output(self):
        fake = F.FakeIndexer().start()
        work = F.make_workdir()
        secret = "Very-Secret-Value-42"
        try:
            code, out = F.run_command(fake, ["apply"], work, {"WAZUH_INDEXER_PASSWORD": secret})
            self.assertEqual(code, 0, out)
            self.assertNotIn(secret, out)
            for base, _d, files in os.walk(work):
                for name in files:
                    with open(os.path.join(base, name), "rb") as fh:
                        self.assertNotIn(secret.encode(), fh.read(), name)
        finally:
            fake.stop()
            shutil.rmtree(work)


if __name__ == "__main__":
    unittest.main()
