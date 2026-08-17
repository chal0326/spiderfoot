# test_spiderfootapikeys.py
import os
import tempfile
import unittest

import pytest

from spiderfoot.apikeys import SpiderFootApiKeys


@pytest.mark.usefixtures
class TestSpiderFootApiKeys(unittest.TestCase):

    def test_env_var_name_strips_module_prefix(self):
        self.assertEqual(
            "SPIDERFOOT_SHODAN_API_KEY",
            SpiderFootApiKeys.envVarName("sfp_shodan", "api_key")
        )

    def test_env_var_name_collapses_repeated_module_name(self):
        self.assertEqual(
            "SPIDERFOOT_BING_API_KEY",
            SpiderFootApiKeys.envVarName("sfp_bing", "bing_api_key")
        )

    def test_env_var_name_handles_multi_field_credentials(self):
        self.assertEqual(
            "SPIDERFOOT_CENSYS_API_KEY_UID",
            SpiderFootApiKeys.envVarName("sfp_censys", "censys_api_key_uid")
        )

    def test_env_var_name_invalid_module_should_raise(self):
        with self.assertRaises(TypeError):
            SpiderFootApiKeys.envVarName(None, "api_key")

    def test_env_var_name_invalid_opt_should_raise(self):
        with self.assertRaises(TypeError):
            SpiderFootApiKeys.envVarName("sfp_shodan", None)

    def test_parse_env_file(self):
        content = (
            "# a comment\n"
            "\n"
            "PLAIN=value1\n"
            "DOUBLE=\"value 2\"\n"
            "SINGLE='value 3'\n"
            "export EXPORTED=value4\n"
            "  SPACED = value5 \n"
            "EMPTY=\n"
            "NOEQUALS\n"
            "URL=https://example.com/?a=b\n"
        )

        with tempfile.NamedTemporaryFile('w', suffix='.env', delete=False) as f:
            f.write(content)
            path = f.name

        try:
            env = SpiderFootApiKeys.parseEnvFile(path)
        finally:
            os.unlink(path)

        self.assertEqual("value1", env['PLAIN'])
        self.assertEqual("value 2", env['DOUBLE'])
        self.assertEqual("value 3", env['SINGLE'])
        self.assertEqual("value4", env['EXPORTED'])
        self.assertEqual("value5", env['SPACED'])
        self.assertEqual("", env['EMPTY'])
        self.assertNotIn('NOEQUALS', env)
        # Values containing '=' must survive intact.
        self.assertEqual("https://example.com/?a=b", env['URL'])

    def test_parse_env_file_invalid_path_should_raise(self):
        with self.assertRaises(TypeError):
            SpiderFootApiKeys.parseEnvFile(None)

        with self.assertRaises(IOError):
            SpiderFootApiKeys.parseEnvFile("/nonexistent/path/to/file.env")

    def test_credential_opts_selects_only_secrets(self):
        opts = {
            'api_key': "",
            'api_key_password': "",
            'username': "",
            'netblocklookup': True,     # bool, not a credential
            'maxnetblock': 24,          # int, not a credential
            'delay': 1,
            'search_string': "",        # no credential keyword
            'api_hostname': "",         # explicitly excluded
            '_priority': "",            # private
        }

        self.assertEqual(
            ['api_key', 'api_key_password', 'username'],
            SpiderFootApiKeys.credentialOpts(opts)
        )

    def test_credential_opts_invalid_input_returns_list(self):
        self.assertEqual([], SpiderFootApiKeys.credentialOpts(None))

    def test_discover_returns_free_auth_providers(self):
        providers = SpiderFootApiKeys.discover()

        self.assertIsInstance(providers, list)
        self.assertTrue(len(providers) > 0)

        modules = [p['module'] for p in providers]
        self.assertIn('sfp_shodan', modules)

        for provider in providers:
            self.assertIn(provider['model'], SpiderFootApiKeys.FREE_AUTH_MODELS)
            self.assertTrue(provider['options'])
            for option in provider['options']:
                self.assertTrue(option['config_key'].startswith(f"{provider['module']}:"))
                self.assertTrue(option['env_var'].startswith("SPIDERFOOT_"))

    def test_discover_excludes_commercial_by_default(self):
        free = SpiderFootApiKeys.discover(freeOnly=True)
        every = SpiderFootApiKeys.discover(freeOnly=False)

        self.assertTrue(len(every) > len(free))
        self.assertNotIn(
            'COMMERCIAL_ONLY', [p['model'] for p in free]
        )

    def test_resolve_matches_env_vars_and_aliases(self):
        providers = [{
            'module': 'sfp_shodan',
            'name': 'SHODAN',
            'website': 'https://shodan.io',
            'instructions': [],
            'options': [{
                'opt': 'api_key',
                'desc': '',
                'config_key': 'sfp_shodan:api_key',
                'env_var': 'SPIDERFOOT_SHODAN_API_KEY',
            }],
        }]

        optMap, missing = SpiderFootApiKeys.resolve(
            providers, {'SPIDERFOOT_SHODAN_API_KEY': 'prefixed'}
        )
        self.assertEqual({'sfp_shodan:api_key': 'prefixed'}, optMap)
        self.assertEqual([], missing)

        # The un-prefixed alias is accepted too.
        optMap, missing = SpiderFootApiKeys.resolve(
            providers, {'SHODAN_API_KEY': 'alias'}
        )
        self.assertEqual({'sfp_shodan:api_key': 'alias'}, optMap)

        # An empty value counts as missing, not as a key.
        optMap, missing = SpiderFootApiKeys.resolve(
            providers, {'SPIDERFOOT_SHODAN_API_KEY': '   '}
        )
        self.assertEqual({}, optMap)
        self.assertEqual(1, len(missing))

    def test_resolve_invalid_input_should_raise(self):
        with self.assertRaises(TypeError):
            SpiderFootApiKeys.resolve(None, {})

        with self.assertRaises(TypeError):
            SpiderFootApiKeys.resolve([], None)

    def test_expand_events_resolves_groups_and_raw_types(self):
        self.assertIn("IP_ADDRESS", SpiderFootApiKeys.expandEvents(['ip']))
        self.assertIn("EMAILADDR", SpiderFootApiKeys.expandEvents(['email']))

        # Group names are case-insensitive and raw event types pass through.
        both = SpiderFootApiKeys.expandEvents(['IP', 'PHONE_NUMBER'])
        self.assertIn("IP_ADDRESS", both)
        self.assertIn("PHONE_NUMBER", both)

        self.assertEqual(set(), SpiderFootApiKeys.expandEvents(None))
        self.assertEqual(set(), SpiderFootApiKeys.expandEvents([' ']))

    def test_extract_events_returns_watched_types(self):
        path = os.path.join(SpiderFootApiKeys.modulePath(), "sfp_shodan.py")

        watched = SpiderFootApiKeys.extractEvents(path, "watchedEvents")
        self.assertIn("IP_ADDRESS", watched)

        produced = SpiderFootApiKeys.extractEvents(path, "producedEvents")
        self.assertIsInstance(produced, list)
        self.assertTrue(produced)

    def test_extract_events_missing_file_returns_list(self):
        self.assertEqual(
            [], SpiderFootApiKeys.extractEvents("/nonexistent/module.py")
        )

    def test_discover_filters_by_event_group(self):
        every = SpiderFootApiKeys.discover()
        ipOnly = SpiderFootApiKeys.discover(events=['ip'])

        self.assertTrue(0 < len(ipOnly) < len(every))

        modules = [p['module'] for p in ipOnly]
        self.assertIn('sfp_shodan', modules)

        # Every provider returned must actually watch an IP event type.
        wanted = SpiderFootApiKeys.expandEvents(['ip'])
        for provider in ipOnly:
            watched = set(provider['watched'])
            self.assertTrue(
                "*" in watched or wanted.intersection(watched),
                f"{provider['module']} does not watch an IP event"
            )

    def test_discover_filters_by_module_name(self):
        picked = SpiderFootApiKeys.discover(modules=['shodan', 'sfp_emailrep'])

        self.assertEqual(
            ['sfp_emailrep', 'sfp_shodan'],
            sorted(p['module'] for p in picked)
        )

        # An unknown module simply yields nothing rather than raising.
        self.assertEqual([], SpiderFootApiKeys.discover(modules=['nope_xyz']))

    def test_discover_tools_reports_path_option(self):
        tools = SpiderFootApiKeys.discoverTools()

        self.assertTrue(tools)

        modules = [t['module'] for t in tools]
        self.assertIn('sfp_tool_nmap', modules)

        for tool in tools:
            self.assertTrue(tool['config_key'].startswith(f"{tool['module']}:"))
            self.assertTrue(tool['binaries'])
            self.assertIsInstance(tool['installed'], bool)
            # A tool reported as installed must have a real path.
            if tool['installed']:
                self.assertTrue(os.path.exists(tool['path']))

    def test_discover_tools_ip_only_is_a_subset(self):
        every = SpiderFootApiKeys.discoverTools()
        ipOnly = SpiderFootApiKeys.discoverTools(ipOnly=True)

        self.assertTrue(0 < len(ipOnly) < len(every))
        for tool in ipOnly:
            self.assertIn(tool['module'], SpiderFootApiKeys.TOOL_IP_FOCUSED)

    def test_find_binary_locates_known_executable(self):
        # 'sh' exists on every supported platform.
        self.assertTrue(SpiderFootApiKeys.findBinary(['sh']).endswith("sh"))

        # Falls through the candidate list to the one that exists.
        self.assertTrue(SpiderFootApiKeys.findBinary(['nope_xyz_123', 'sh']))

        self.assertEqual("", SpiderFootApiKeys.findBinary(['nope_xyz_123']))

    def test_mask_hides_all_but_last_four(self):
        self.assertEqual("********cret", SpiderFootApiKeys.mask("abc123secret"))
        self.assertEqual("***", SpiderFootApiKeys.mask("abc"))
        self.assertEqual("", SpiderFootApiKeys.mask(""))
        self.assertEqual("", SpiderFootApiKeys.mask(None))
