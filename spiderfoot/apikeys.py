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
import shutil


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

    # Named groups of event types, so a scan focused on particular kinds of
    # entity can be narrowed to only the providers which act on them.
    EVENT_GROUPS = {
        'ip': (
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_OWNER",
            "NETBLOCKV6_MEMBER",
        ),
        'email': (
            "EMAILADDR",
            "EMAILADDR_GENERIC",
            "EMAILADDR_COMPROMISED",
            "EMAILADDR_DELIVERABLE",
            "EMAILADDR_UNDELIVERABLE",
            "EMAILADDR_DISPOSABLE",
            "AFFILIATE_EMAILADDR",
        ),
        'domain': (
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
        ),
        'phone': (
            "PHONE_NUMBER",
        ),
        'person': (
            "HUMAN_NAME",
            "USERNAME",
            "SOCIAL_MEDIA",
        ),
    }

    # Bundled 'Tool - ' modules shell out to a locally installed binary. The
    # executable is usually named after the module, so only the exceptions are
    # listed here; candidates are tried in order.
    TOOL_BINARIES = {
        'sfp_tool_testsslsh': ("testssl.sh", "testssl"),
        'sfp_tool_retirejs': ("retire",),
        'sfp_tool_cmseek': ("cmseek.py", "cmseek"),
        'sfp_tool_wappalyzer': ("wappalyzer",),
        'sfp_tool_nuclei': ("nuclei",),
    }

    # Directories searched in addition to PATH. 'go install', 'pip --user' and
    # 'npm -g' commonly install to locations a login shell has not picked up.
    TOOL_EXTRA_DIRS = (
        "~/go/bin",
        "~/.local/bin",
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/snap/bin",
    )

    # Tool modules which act on IP addresses or hosts, as opposed to web
    # content, source repositories or domain names.
    TOOL_IP_FOCUSED = (
        'sfp_tool_nmap',
        'sfp_tool_nbtscan',
        'sfp_tool_onesixtyone',
        'sfp_tool_nuclei',
        'sfp_tool_testsslsh',
    )

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
    def extractEvents(cls, path: str, funcName: str = "watchedEvents") -> list:
        """Extract the event types a module watches or produces.

        Args:
            path (str): path to the module source file
            funcName (str): 'watchedEvents' or 'producedEvents'

        Returns:
            list: event type names, empty if they could not be determined
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
        except Exception:
            return list()

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != funcName:
                continue
            for stmt in ast.walk(node):
                if not isinstance(stmt, ast.Return):
                    continue
                try:
                    value = ast.literal_eval(stmt.value)
                except Exception:
                    return list()
                if isinstance(value, (list, tuple)):
                    return [e for e in value if isinstance(e, str)]

        return list()

    @classmethod
    def expandEvents(cls, names) -> set:
        """Expand group names and event names into a set of event types.

        Args:
            names: iterable of group names (e.g. 'ip') or event types

        Returns:
            set: event type names
        """
        events = set()

        for name in names or ():
            key = name.strip()
            if not key:
                continue
            if key.lower() in cls.EVENT_GROUPS:
                events.update(cls.EVENT_GROUPS[key.lower()])
            else:
                events.add(key.upper())

        return events

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
    def discover(cls, modulesDir: str = None, freeOnly: bool = True,
                 events=None, modules=None) -> list:
        """Inventory the modules which require API keys.

        Args:
            modulesDir (str): path to the modules directory; defaults to bundled
            freeOnly (bool): only report sources which are free but need signup
            events: optional iterable of event types or group names ('ip',
                'email', ...); only providers acting on one of them are reported
            modules: optional iterable of module names to restrict to, with or
                without the 'sfp_' prefix

        Returns:
            list: provider dicts, sorted by module name
        """
        wanted = cls.expandEvents(events) if events else None

        only = None
        if modules:
            only = {
                m if m.startswith("sfp_") else f"sfp_{m}"
                for m in (n.strip() for n in modules) if m
            }
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

            if only is not None and modName not in only:
                continue

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

            watched = cls.extractEvents(path, "watchedEvents")

            if wanted is not None:
                # '*' means the module watches everything, so it always applies.
                if "*" not in watched and not wanted.intersection(watched):
                    continue

            providers.append({
                'module': modName,
                'name': meta.get('name', modName),
                'model': model,
                'website': dataSource.get('website', ""),
                'instructions': dataSource.get('apiKeyInstructions') or list(),
                'summary': meta.get('summary', ""),
                'watched': watched,
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
    def findBinary(cls, names) -> str:
        """Locate an executable on PATH or in the common install directories.

        Args:
            names: iterable of candidate executable names, tried in order

        Returns:
            str: full path to the executable, or an empty string
        """
        extra = list()
        for directory in cls.TOOL_EXTRA_DIRS:
            expanded = os.path.expanduser(directory)
            if os.path.isdir(expanded):
                extra.append(expanded)

        # GOPATH is only known by asking go, so honour the variable if set.
        goPath = os.environ.get('GOPATH', "")
        if goPath:
            goBin = os.path.join(goPath, "bin")
            if os.path.isdir(goBin) and goBin not in extra:
                extra.append(goBin)

        searchPath = os.pathsep.join(
            [os.environ.get('PATH', "")] + extra
        )

        for name in names:
            located = shutil.which(name, path=searchPath)
            if located:
                return located

        return ""

    @classmethod
    def discoverTools(cls, modulesDir: str = None, ipOnly: bool = False) -> list:
        """Inventory the bundled modules which shell out to a local binary.

        Args:
            modulesDir (str): path to the modules directory; defaults to bundled
            ipOnly (bool): only report the tools which act on IPs and hosts

        Returns:
            list: tool dicts, sorted by module name
        """
        if modulesDir is None:
            modulesDir = cls.modulePath()

        tools = list()

        try:
            filenames = sorted(os.listdir(modulesDir))
        except Exception:
            return tools

        for filename in filenames:
            if not filename.startswith("sfp_tool_") or not filename.endswith(".py"):
                continue

            modName = filename[:-3]

            if ipOnly and modName not in cls.TOOL_IP_FOCUSED:
                continue

            path = os.path.join(modulesDir, filename)
            opts, _ = cls.extractOpts(path)

            # The binary location is the path option left empty by default;
            # options like 'pythonpath' ship with a working default.
            pathOpt = None
            for opt in opts:
                if 'path' in opt.lower() and opts[opt] == "":
                    pathOpt = opt
                    break

            if not pathOpt:
                continue

            stem = modName[len("sfp_tool_"):]
            candidates = cls.TOOL_BINARIES.get(modName, (stem,))

            found = cls.findBinary(candidates)

            meta = cls.extractMeta(path)

            tools.append({
                'module': modName,
                'name': meta.get('name', modName),
                'binaries': list(candidates),
                'opt': pathOpt,
                'config_key': f"{modName}:{pathOpt}",
                'path': found,
                'installed': bool(found),
            })

        return tools

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
