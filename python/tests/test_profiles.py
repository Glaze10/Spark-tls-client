"""The autocomplete names (spark_tls.ios26.*, spark_tls.chrome_151) match the built-ins."""
import inspect

import spark_tls
from spark_tls import _profiles


def _all_names():
    out = {}
    for ns in _profiles.__all__:
        obj = getattr(_profiles, ns)
        if inspect.isclass(obj):
            out.update({f"{ns}.{k}": v for k, v in vars(obj).items() if not k.startswith("_")})
        else:
            out[ns] = obj
    return out


def test_every_builtin_has_a_name():
    builtins = {p["name"] for p in spark_tls.profiles()}
    assert set(_all_names().values()) == builtins


def test_every_name_opens_a_session():
    for attr, profile in _all_names().items():
        with spark_tls.Session(profile) as s:
            assert s.profile == profile, attr


def test_names_reachable_from_package():
    assert spark_tls.ios26.native_apple == "IOS-26-native-apple"
    assert spark_tls.ios26.safari == "ios-safari-26"
    assert spark_tls.chrome_151 == "chrome-151"
