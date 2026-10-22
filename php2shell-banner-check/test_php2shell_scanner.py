import unittest
from unittest.mock import patch
from email.message import Message
import urllib.error
import php2shell_scanner as s


class ScannerTests(unittest.TestCase):
    def test_boundaries(self):
        for branch, fixed in s.FIXED.items():
            good = '.'.join(map(str, fixed))
            bad = '.'.join(map(str, (*branch, fixed[2] - 1)))
            self.assertEqual(s.evaluate('PHP/' + good)[1], 'No (by version)')
            self.assertEqual(s.evaluate('PHP/' + bad)[1], 'Yes (by version)')

    def test_unknowns(self):
        for banner in ('nginx', 'PHP/8.3', 'PHP/8.3.36RC1', 'PHP/8.3.1-ubuntu',
                       'PHP/8.3.1; PHP/8.3.36', 'PHP/9.0.0', 'PHP/5.3.29'):
            self.assertEqual(s.evaluate(banner)[1], 'Unknown')

    def test_legacy(self):
        for version in ('5.4.0', '7.3.33', '7.4.33', '8.1.34'):
            self.assertEqual(s.evaluate('PHP/' + version)[1], 'Yes (by version)')

    def test_normalize(self):
        self.assertEqual(s.normalize('https://example.com/a.php?q=1'),
                         ('example.com', 'example.com', '/a.php?q=1'))
        self.assertEqual(s.normalize('2001:db8::1')[1], '[2001:db8::1]')
        for value in ('ftp://example.com', 'https://u:p@example.com', 'example.com:8080', 'bad\nname'):
            with self.assertRaises(ValueError):
                s.normalize(value)

    def test_csv_injection(self):
        self.assertTrue(s.csv_safe(' =1+1').startswith("'"))

    def test_redirect_disabled(self):
        self.assertIsNone(s.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://other/'))

    def test_exactly_one_request_without_banner(self):
        job = ('example.com', 'example.com', '/', 'http', 80)
        with patch.object(s, 'fetch', return_value=(200, 'Server: nginx', '')) as fetch:
            result = s.scan(job, 1, False)
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.args[2], 'HEAD')
        self.assertEqual(result['Vulnerable'], 'Unknown')

    def test_get_is_explicit_and_single(self):
        job = ('example.com', 'example.com', '/', 'http', 80)
        with patch.object(s, 'fetch', return_value=(200, 'PHP/8.3.35', '')) as fetch:
            result = s.scan(job, 1, False, 'GET')
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.args[2], 'GET')
        self.assertEqual(result['Vulnerable'], 'Yes (by version)')

    def test_no_fallback_on_405(self):
        job = ('example.com', 'example.com', '/', 'http', 80)
        with patch.object(s, 'fetch', return_value=(405, '', '')) as fetch:
            result = s.scan(job, 1, False)
        fetch.assert_called_once()
        self.assertEqual(result['HTTP'], '405')
        self.assertEqual(result['Vulnerable'], 'Unknown')

    def test_redirect_stays_indeterminate(self):
        job = ('example.com', 'example.com', '/', 'http', 80)
        with patch.object(s, 'fetch', return_value=(302, '', 'https://other.example/')) as fetch:
            result = s.scan(job, 1, False)
        fetch.assert_called_once()
        self.assertEqual(result['Redirect'], 'https://other.example/')
        self.assertEqual(result['Vulnerable'], 'Unknown')

    def test_response_body_never_read(self):
        from unittest.mock import Mock
        response = Mock()
        response.headers = Message()
        response.headers['Server'] = 'PHP/8.5.12'
        response.code = 200
        client = Mock()
        client.open.return_value = response
        s.fetch(client, 'http://example.com', 'GET', 1)
        response.read.assert_not_called()
        response.close.assert_called_once()

    def test_failure_retained(self):
        job = ('example.com', 'example.com', '/', 'https', 443)
        with patch.object(s, 'fetch', side_effect=urllib.error.URLError('TLS certificate failed')):
            result = s.scan(job, 1, False)
        self.assertEqual(result['Vulnerable'], 'Unknown')
        self.assertIn('TLS certificate failed', result['Details'])

    def test_http_error_headers(self):
        headers = Message()
        headers['X-Powered-By'] = 'PHP/8.4.27'
        error = urllib.error.HTTPError('http://example.com', 403, 'Forbidden', headers, None)
        class Client:
            def open(self, *args, **kwargs):
                raise error
        code, evidence, _ = s.fetch(Client(), 'http://example.com', 'HEAD', 1)
        self.assertEqual(code, 403)
        self.assertIn('PHP/8.4.27', evidence)


    def test_cli_protocols_and_csv(self):
        import contextlib
        import csv
        import io
        import tempfile
        from pathlib import Path
        for selection, expected in [('both', 2), ('http', 1), ('https', 1)]:
            with self.subTest(protocol=selection), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'results.csv'
                argv = ['scanner', 'example.com', '--protocol', selection, '-o', str(output)]
                with patch.object(s.sys, 'argv', argv), patch.object(s, 'fetch', return_value=(200, 'PHP/8.5.12', '')) as fetch:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        s.main()
                self.assertEqual(fetch.call_count, expected)
                with output.open(encoding='utf-8-sig', newline='') as stream:
                    rows = list(csv.DictReader(stream))
                self.assertEqual(len(rows), expected)
                self.assertTrue(all(row['Method'] == 'HEAD' for row in rows))
                self.assertTrue(all(row['Vulnerable'] == 'No (by version)' for row in rows))
                if selection != 'both':
                    self.assertEqual(rows[0]['Protocol'], selection.upper())

    def test_tls_defaults(self):
        import ssl
        client = s.opener(False)
        handler = next(h for h in client.handlers if isinstance(h, s.urllib.request.HTTPSHandler))
        self.assertTrue(handler._context.check_hostname)
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)

    def test_error_does_not_retry(self):
        job = ('example.com', 'example.com', '/', 'https', 443)
        with patch.object(s, 'fetch', side_effect=urllib.error.URLError('unreachable')) as fetch:
            result = s.scan(job, 1, False)
        fetch.assert_called_once()
        self.assertEqual(result['HTTP'], 'No HTTP response')


    def test_console_status_labels(self):
        job = ('example.com', 'example.com', '/', 'https', 443)
        for banner, label in [('PHP/8.3.35', 'VULNERABLE*'),
                              ('PHP/8.5.12', 'NOT AFFECTED*'), ('', 'UNKNOWN')]:
            with patch.object(s, 'fetch', return_value=(200, banner, '')):
                row = s.scan(job, 1, False)
            line = s.console_line(row)
            self.assertIn(label, line)
            self.assertIn('https:443', line)
            self.assertNotIn('\033', line)

    def test_console_eol_marker(self):
        job = ('example.com', 'example.com', '/', 'http', 80)
        with patch.object(s, 'fetch', return_value=(200, 'PHP/7.4.33', '')):
            row = s.scan(job, 1, False)
        self.assertIn('[EOL]', s.console_line(row))
        row['PHP Version'] = '8.3.35'
        self.assertNotIn('[EOL]', s.console_line(row))

    def test_console_colors_forced(self):
        self.assertEqual(s.paint('hello', '91', True), '\033[91mhello\033[0m')
        self.assertEqual(s.paint('hello', '91', False), 'hello')
        self.assertTrue(s.colors_enabled('always'))
        self.assertFalse(s.colors_enabled('never'))

    def test_no_color_environment(self):
        with patch.dict(s.os.environ, {'NO_COLOR': ''}), patch.object(s.sys.stdout, 'isatty', return_value=True):
            self.assertFalse(s.colors_enabled('auto'))

    def test_console_controls_removed(self):
        row = dict.fromkeys(s.COLUMNS, '')
        row.update({'Server': 'host\033[31m', 'Protocol': 'HTTPS', 'Port': '443',
                    'PHP Version': 'Not disclosed', 'Vulnerable': 'Unknown',
                    'Upgrade To': 'check\nnow', 'HTTP': '200'})
        line = s.console_line(row)
        self.assertNotIn('\033', line)
        self.assertNotIn('\n', line)

    def test_console_and_table_csv_parity(self):
        import contextlib
        import io
        import tempfile
        from pathlib import Path
        saved = []
        for mode in ('console', 'table'):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'result.csv'
                argv = ['scanner', 'example.com', '--format', mode, '--color', 'never', '-o', str(output)]
                stdout = io.StringIO()
                with patch.object(s.sys, 'argv', argv), patch.object(s, 'fetch', return_value=(200, 'PHP/8.3.35', '')) as fetch:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                        s.main()
                self.assertEqual(fetch.call_count, 2)
                self.assertNotIn('\033', stdout.getvalue())
                self.assertIn('VULNERABLE*: 2', stdout.getvalue())
                import csv
                with output.open(encoding='utf-8-sig', newline='') as stream:
                    rows = list(csv.DictReader(stream))
                for row in rows:
                    row.pop('Timestamp UTC')
                saved.append(rows)
        self.assertEqual(saved[0], saved[1])


    def test_english_csv_schema_and_values(self):
        expected = ['Server', 'URL', 'Protocol', 'Port', 'HTTP', 'Method',
                    'PHP Version', 'Vulnerable', 'Upgrade To', 'Evidence',
                    'Redirect', 'TLS', 'Details', 'Timestamp UTC']
        self.assertEqual(s.COLUMNS, expected)
        self.assertEqual(s.evaluate('PHP/8.3.35')[1], 'Yes (by version)')
        self.assertEqual(s.evaluate('PHP/8.3.36')[1], 'No (by version)')
        self.assertEqual(s.evaluate('')[0:2], ('Not disclosed', 'Unknown'))


if __name__ == '__main__':
    unittest.main()
