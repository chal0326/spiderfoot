# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        apikeys
# Purpose:     Inventory the modules which require API keys, and load those keys
#              from a .env file into the SpiderFoot configuration.
#
# Licence:     MIT
# -------------------------------------------------------------------------------

import ast
import os
import re


class SpiderFootApiKeys:
    """Discover which modules need API keys and populate them from a .env file.

    Module metadata already records whether a data source is free, whether it
    needs authentication, and how to obtain a key. This reads that metadata to
    produce a signup worklist, and maps environment variables back onto module
    options so keys can be applied to the configuration in one step.
    """

    # dataSource 'model' values which describe a source that is free to use but
    # still requires registration to obtain a key.
    FREE_AUTH_MODELS = ("FREE_AUTH_LIMITED", "FREE_AUTH_UNLIMITED")

    # Option names matching this are treated as credentials to be sourced from
    # the environment rather than configured by hand.
    CREDENTIAL_OPT_REGEX = re.compile(
        r"(api|key|token|secret|password|passwd|login|username|user_id|client_id|credential)",
        re.IGNORECASE
    )

    # Credential-looking options which are not actually secrets.
    CREDENTIAL_OPT_EXCLUDE = ("api_hostname",)

    @staticmethod
    def modulePath() -> str:
        """Return the path to the bundled modules directory.

        Returns:
            str: absolute path to the modules directory
        """
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules"
        )

    @staticmethod
    def envVarName(modName: str, opt: str) -> str:
        """Build the environment variable name for a module option.

        The 'sfp_' prefix is dropped and any module-name prefix repeated in the
        option is collapsed, so sfp_shodan/api_key becomes SPIDERFOOT_SHODAN_API_KEY
        and sfp_bing/bing_api_key becomes SPIDERFOOT_BING_API_KEY.

        Args:
            modName (str): module name, e.g. sfp_shodan
            opt (str): option name, e.g. api_key

        Returns:
            str: environment variable name

        Raises:
            TypeError: arg type was invalid
        """
        if not isinstance(modName, str):
            raise TypeError(f"modName is {type(modName)}; expected str()") from None
        if not isinstance(opt, str):
            raise TypeError(f"opt is {type(opt)}; expected str()") from None

        stem = modName[4:] if modName.startswith("sfp_") else modName
        if opt.lower().startswith(f"{stem.lower()}_"):
            opt = opt[len(stem) + 1:]

        return f"SPIDERFOOT_{stem}_{opt}".upper()

    @staticmethod
    def parseEnvFile(path: str) -> dict:
        """Parse a .env file into a dict.

        Supports 'KEY=value', optional 'export ' prefixes, '#' comments, blank
        lines, and single or double quoted values.

        Args:
            path (str): path to the .env file

        Returns:
            dict: environment variables

        Raises:
            TypeError: arg type was invalid
            IOError: file could not be read
        """
        if not isinstance(path, str):
            raise TypeError(f"path is {type(path)}; expected str()") from None

        env = dict()

        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            raise IOError(f"Unable to read env file {path}") from e

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if line.startswith('export '):
                line = line[7:].strip()

            if '=' not in line:
                continue

            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip()

            if len(val) > 1 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]

            if key:
                env[key] = val

        return env

    @classmethod
    def extractMeta(cls, path: str) -> dict:
        """Extract a module's meta dict without importing the module.

        Modules are parsed rather than imported so that the inventory works
        without every module's third-party dependencies being installed.

        Args:
            path (str): path to the module source file

        Returns:
            dict: the module's meta dict, or an empty dict if unavailable
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
        except Exception:
            return dict()

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "meta":
                        try:
                            return ast.literal_eval(item.value)
                        except Exception:
                            return dict()

        return dict()

    @classmethod
    def extractOpts(cls, path: str) -> tuple:
        """Extract a module's opts and optdescs dicts without importing it.

        Args:
            path (str): path to the module source file

        Returns:
            tuple: (opts dict, optdescs dict)
        """
        opts = dict()
        optdescs = dict()

        try:
            with open(path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
        except Exception:
            return (opts, optdescs)

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id not in ("opts", "optdescs"):
                        continue
                    try:
                        value = ast.literal_eval(item.value)
                    except Exception:
                        continue
                    if not isinstance(value, dict):
                        continue
                    if target.id == "opts":
                        opts = value
                    else:
                        optdescs = value

        return (opts, optdescs)

    @classmethod
    def credentialOpts(cls, opts: dict) -> list:
        """Return the option names which look like credentials.

        Args:
            opts (dict): a module's opts dict

        Returns:
            list: credential option names, sorted
        """
        if not isinstance(opts, dict):
            return list()

        found = list()

        for opt in opts:
            if opt.startswith('_'):
                continue
            if opt in cls.CREDENTIAL_OPT_EXCLUDE:
                continue
            # Credentials default to an empty string; booleans and ints matching
            # the name pattern (e.g. 'checktokens') are configuration, not keys.
            if not isinstance(opts[opt], str):
                continue
            if cls.CREDENTIAL_OPT_REGEX.search(opt):
                found.append(opt)

        return sorted(found)

    @classmethod
    def discover(cls, modulesDir: str = None, freeOnly: bool = True) -> list:
        """Inventory the modules which require API keys.

        Args:
            modulesDir (str): path to the modules directory; defaults to bundled
            freeOnly (bool): only report sources which are free but need signup

        Returns:
            list: provider dicts, sorted by module name
        """
        if modulesDir is None:
            modulesDir = cls.modulePath()

        providers = list()

        try:
            filenames = sorted(os.listdir(modulesDir))
        except Exception:
            return providers

        for filename in filenames:
            if not filename.startswith("sfp_") or not filename.endswith(".py"):
                continue

            modName = filename[:-3]
            path = os.path.join(modulesDir, filename)

            meta = cls.extractMeta(path)
            if not meta:
                continue

            dataSource = meta.get('dataSource') or dict()
            model = dataSource.get('model', "")

            if freeOnly and model not in cls.FREE_AUTH_MODELS:
                continue

            opts, optdescs = cls.extractOpts(path)
            credOpts = cls.credentialOpts(opts)

            if not credOpts:
                continue

            providers.append({
                'module': modName,
                'name': meta.get('name', modName),
                'model': model,
                'website': dataSource.get('website', ""),
                'instructions': dataSource.get('apiKeyInstructions') or list(),
                'summary': meta.get('summary', ""),
                'options': [
                    {
                        'opt': opt,
                        'desc': optdescs.get(opt, ""),
                        'config_key': f"{modName}:{opt}",
                        'env_var': cls.envVarName(modName, opt),
                    }
                    for opt in credOpts
                ],
            })

        return providers

    @classmethod
    def resolve(cls, providers: list, env: dict) -> tuple:
        """Match environment variables against provider options.

        Args:
            providers (list): providers as returned by discover()
            env (dict): environment variables

        Returns:
            tuple: (optMap of config key to value, list of unresolved options)

        Raises:
            TypeError: arg type was invalid
        """
        if not isinstance(providers, list):
            raise TypeError(f"providers is {type(providers)}; expected list()") from None
        if not isinstance(env, dict):
            raise TypeError(f"env is {type(env)}; expected dict()") from None

        optMap = dict()
        missing = list()

        for provider in providers:
            for option in provider['options']:
                envVar = option['env_var']
                # Also accept the name without the SPIDERFOOT_ prefix.
                alias = envVar[len("SPIDERFOOT_"):]

                val = env.get(envVar, env.get(alias, "")).strip()

                if val:
                    optMap[option['config_key']] = val
                else:
                    missing.append({
                        'module': provider['module'],
                        'name': provider['name'],
                        'env_var': envVar,
                        'website': provider['website'],
                        'instructions': provider['instructions'],
                    })

        return (optMap, missing)

    @staticmethod
    def mask(value: str) -> str:
        """Mask a secret for display.

        Args:
            value (str): the secret

        Returns:
            str: masked value showing only the last 4 characters
        """
        if not isinstance(value, str) or not value:
            return ""
        if len(value) <= 4:
            return "*" * len(value)
        return f"{'*' * (len(value) - 4)}{value[-4:]}"
