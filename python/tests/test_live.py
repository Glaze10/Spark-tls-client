"""Live tests against public echo servers. Run: pytest python/tests -v"""
import asyncio
import glob
import os

import pytest

import spark_tls

PEET = "https://tls.peet.ws/api/all"
HTTPBIN = "https://httpbin.org"

CHROME_JA4_PREFIX = "t13d1516h2_8daaf6152771_"
CHROME_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
IOS_JA4_PREFIX = "t13d2013h2_a09f3c656075_"
IOS_AKAMAI = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"


@pytest.mark.parametrize("profile,ja4,akamai", [
    ("chrome", CHROME_JA4_PREFIX, CHROME_AKAMAI),
    ("ios", IOS_JA4_PREFIX, IOS_AKAMAI),
])
def test_fingerprint(profile, ja4, akamai):
    with spark_tls.Session(profile) as s:
        d = s.get(PEET).json()
    assert d["tls"]["ja4"].startswith(ja4)
    assert d["http2"]["akamai_fingerprint"] == akamai


def test_header_order_kept():
    with spark_tls.Session("chrome") as s:
        s.headers["user-agent"] = "custom-ua"      # edit in place: position kept
        d = s.get(PEET, headers={"x-first": "1", "x-second": "2"}).json()
    names = [h.split(": ")[0] for f in d["http2"]["sent_frames"] if f["frame_type"] == "HEADERS"
             for h in f["headers"]]
    assert names.index("user-agent") < names.index("accept") < names.index("x-first") < names.index("x-second")
    assert d["user_agent"] == "custom-ua"


def test_post_json_and_form():
    with spark_tls.Session() as s:
        r = s.post(f"{HTTPBIN}/post", json={"a": 1, "b": "ü"})
        assert r.json()["json"] == {"a": 1, "b": "ü"}
        r = s.post(f"{HTTPBIN}/post", data={"x": "1"}, params={"q": "z"})
        body = r.json()
        assert body["form"] == {"x": "1"} and body["args"] == {"q": "z"}


def test_cookies_and_redirects():
    with spark_tls.Session() as s:
        r = s.get(f"{HTTPBIN}/cookies/set?sid=abc")
        assert r.history and r.json()["cookies"] == {"sid": "abc"}
        assert s.get_cookies(HTTPBIN) == {"sid": "abc"}
        s.set_cookies(HTTPBIN, {"manual": "1"})
        assert s.get(f"{HTTPBIN}/cookies").json()["cookies"] == {"sid": "abc", "manual": "1"}
        r = s.get(f"{HTTPBIN}/redirect/2", allow_redirects=False)
        assert r.status_code == 302


def test_timeout_error():
    with spark_tls.Session() as s:
        with pytest.raises(spark_tls.Timeout):
            s.get(f"{HTTPBIN}/delay/5", timeout=1)


def test_profile_switch_shares_cookies():
    """An app flow that opens a webview: same cookies, different fingerprint."""
    with spark_tls.Session("ios") as s:
        s.set_cookies("https://tls.peet.ws", {"flow": "1"})
        app = s.get(PEET).json()
        web = s.get(PEET, profile="chrome").json()
    assert app["tls"]["ja4"].startswith(IOS_JA4_PREFIX)
    assert web["tls"]["ja4"].startswith(CHROME_JA4_PREFIX)
    assert "Chrome/151" in web["user_agent"]


CLOAK_EXPORTS = glob.glob(os.path.expanduser(r"~/AppData/Local/Temp/cloak-fp/*.json"))


@pytest.mark.skipif(not CLOAK_EXPORTS, reason="no Cloak exports on this machine")
@pytest.mark.parametrize("path", CLOAK_EXPORTS)
def test_cloak_export_loads(path):
    with spark_tls.Session(path) as s:
        r = s.get(PEET)
    assert r.status_code == 200


def test_async_gather():
    async def main():
        async with spark_tls.AsyncSession("chrome") as s:
            rs = await asyncio.gather(*[s.get(f"{HTTPBIN}/get?i={i}") for i in range(25)])
            return [r.json()["args"]["i"] for r in rs]
    assert asyncio.run(main()) == [str(i) for i in range(25)]


def test_async_cancel():
    async def main():
        async with spark_tls.AsyncSession() as s:
            task = asyncio.ensure_future(s.get(f"{HTTPBIN}/delay/10"))
            await asyncio.sleep(0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            # session still usable afterwards
            return (await s.get(f"{HTTPBIN}/get")).status_code
    assert asyncio.run(main()) == 200


def test_sync_threads():
    from concurrent.futures import ThreadPoolExecutor
    with spark_tls.Session() as s, ThreadPoolExecutor(10) as ex:
        codes = list(ex.map(lambda i: s.get(f"{HTTPBIN}/get").status_code, range(20)))
    assert codes == [200] * 20
