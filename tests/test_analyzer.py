import unittest

import pandas as pd

from safeline_log_anal.analyzer import analyze_alerts, detect_malicious_payload


class AnalyzerTests(unittest.TestCase):
    def test_detect_malicious_payload_identifies_sql_injection(self):
        malicious, signature, description = detect_malicious_payload(
            "id=1 UNION SELECT password FROM users"
        )
        self.assertTrue(malicious)
        self.assertEqual("sql_union", signature)
        self.assertIn("SQL", description or "")

    def test_detect_malicious_payload_handles_url_encoding(self):
        payload = "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
        malicious, signature, _ = detect_malicious_payload(payload)
        self.assertTrue(malicious)
        self.assertIn(signature, {"xss_script", "xss_alert"})

    def test_analyze_alerts_marks_benign_entries(self):
        df = pd.DataFrame(
            {
                "payload": [
                    "normal=1",
                    "<script>alert('xss')</script>",
                    "../../etc/passwd",
                ]
            }
        )

        annotated_df, benign_df = analyze_alerts(df)

        self.assertEqual(len(annotated_df), 3)
        self.assertListEqual(
            annotated_df["analysis_is_malicious"].tolist(), [False, True, True]
        )
        self.assertEqual(benign_df.shape[0], 1)
        self.assertEqual(benign_df.iloc[0]["payload"], "normal=1")

    def test_detect_malicious_payload_handles_additional_signatures(self):
        samples = {
            "';print(md5(31337));$a": "hash_md5",
            "convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','1453111982')))": "mssql_hashbytes",
            "extractvalue(1,concat(char(126),md5(1198361388)))": "mysql_xml_extractvalue",
            "&nslookup -q=cname hitxoupqnqawzb05ac.bxss.me&": "command_injection",
            '";onmouseover=\'ytH7(93984)\'bad="': "xss_event_handler",
        }

        for sample, expected_signature in samples.items():
            malicious, signature, _ = detect_malicious_payload(sample)
            with self.subTest(sample=sample):
                self.assertTrue(malicious)
                self.assertEqual(expected_signature, signature)

    def test_detect_malicious_payload_covers_requested_categories(self):
        payloads = {
            "csrf_token=abcdef": "csrf_indicator",
            "url=http://169.254.169.254/latest/meta-data": "ssrf_internal",
            "ping -n 6000 127.0.0.1": "denial_of_service",
            "c99shell": "backdoor_shell",
            "Runtime.getRuntime().exec(\"calc\")": "code_execution_runtime",
            "new Function(\"return this\")": "code_injection_dynamic",
            "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"": "file_upload_attempt",
            "require_once(\"/var/www/html/config.php\")": "file_include",
            "window.location=\"http://evil.com\"": "open_redirect",
            "chmod 777 /var/www/html": "permission_misconfiguration",
            "aws_access_key_id=AKIA123456789": "information_disclosure",
            "GET /admin/console HTTP/1.1": "unauthorized_access_attempt",
            "GET /.git/config HTTP/1.1": "insecure_configuration",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>": "xxe_attack",
            "' or contains(name(),'admin')": "xpath_injection",
            "User-Agent: wpscan": "scanner_activity",
            "switch_user=admin": "horizontal_privilege_bypass",
            "is_admin=1": "vertical_privilege_bypass",
            "echo hacked > /var/www/html/index.php": "file_modification",
            "type C:\\Windows\\system32\\drivers\\etc\\hosts": "file_reading",
            "del /f secret.txt": "file_deletion",
            "price=0&quantity=999": "logic_manipulation",
            "%0d%0aSet-Cookie: session=evil": "crlf_injection",
            "{{7*7}}": "generic_template_injection",
            "<iframe src=\"http://evil.com\" style=\"opacity:0;position:absolute\"></iframe>": "clickjacking",
            "{}".format("A" * 120): "buffer_overflow",
            "2147483648": "integer_overflow",
            "AAAA %x %x %x %x": "format_string",
            "toctou /tmp/lock": "race_condition",
        }

        for payload, expected_signature in payloads.items():
            malicious, signature, _ = detect_malicious_payload(payload)
            with self.subTest(payload=payload):
                self.assertTrue(malicious)
                self.assertEqual(expected_signature, signature)


if __name__ == "__main__":
    unittest.main()
