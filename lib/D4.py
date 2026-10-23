import base64
import re
import requests

from base.spider import Spider as BaseSpider


class Spider(BaseSpider):
    def init(self, extend=""):
        self.key = (extend or "").strip()

    def getName(self):
        return "Decrypt"

    def liveContent(self, url):
        if not url:
            raise ValueError("missing cipher url")
        text = self._read_text(url)
        return self._decrypt_text(text, self.key)

    def localProxy(self, param):
        try:
            if isinstance(param, dict):
                query = dict(param)
                url = query.get("url") or query.get("u") or query.get("src")
                key = query.get("key") or query.get("ext") or self.key
            elif isinstance(param, str):
                url = param
                key = self.key
            else:
                url = None
                key = self.key

            if not url:
                return [400, "text/plain; charset=utf-8", "decrypt: missing url"]
            if not key:
                return [400, "text/plain; charset=utf-8", "decrypt: missing key"]

            content = self._decrypt_text(self._read_text(url), key)
            return [200, "text/plain; charset=utf-8", content]

        except Exception as error:
            return [502, "text/plain; charset=utf-8", "decrypt: " + str(error)]

    @staticmethod
    def _read_text(url):
        if not url:
            raise ValueError("missing url")
        url = str(url).strip()
        if re.match(r"^https?://", url, re.IGNORECASE):
            response = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
            response.raise_for_status()
            return response.text
        return url

    @staticmethod
    def _decrypt_text(text, key):
        key = str(key or "").strip()
        compact = str(text or "").strip()

        if not compact:
            return ""
        if not key:
            raise ValueError("missing key")

        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
            return compact

        try:
            try:
                raw = base64.b64decode(compact, validate=True)
            except Exception:
                padded = compact + "=" * ((4 - len(compact) % 4) % 4)
                raw = base64.b64decode(padded, validate=False)

            # 关键：先按 JS 同样方式，decode 成字符串，再逐字符 XOR
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw.decode("utf-8", errors="replace")

            out = []
            for i, ch in enumerate(decoded):
                out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
            return "".join(out)

        except Exception:
            return compact
