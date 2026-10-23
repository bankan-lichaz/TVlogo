import base64
import re
import requests

from base.spider import Spider as BaseSpider


class Spider(BaseSpider):
    def init(self, extend=""):
        # extend = ext 内容，例如 "key1"
        self.key = (extend or "").strip()

    def getName(self):
        return "Decrypt"

    def liveContent(self, url):
        if not url:
            raise ValueError("missing cipher url")
        text = self._read_text(url)
        return self._try_decrypt(text, True, self.key)

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

            content = self._try_decrypt(self._read_text(url), True, key)
            return [200, "text/plain; charset=utf-8", content]
        except Exception as error:
            return [502, "text/plain; charset=utf-8", "decrypt: " + str(error)]

    @staticmethod
    def _read_text(url):
        if not url:
            raise ValueError("missing url")
        url = str(url).strip()
        if re.match(r"^https?://", url, re.IGNORECASE):
            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            response.raise_for_status()
            return response.text
        return url

    @staticmethod
    def _try_decrypt(text, decrypt, key):
        # 对应 JS:
        # if (!decrypt || !key) return text;
        if not decrypt or not key:
            return text

        key = str(key).strip()
        compact = str(text or "").strip()

        # 对应 JS 过滤条件
        if (
            not compact
            or len(compact) < 8
            or "\n" in compact
            or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact)
            or len(compact) % 4 != 0
        ):
            return text

        try:
            # 先 base64 decode
            try:
                binary = base64.b64decode(compact, validate=True)
            except Exception:
                padded = compact + "=" * ((4 - len(compact) % 4) % 4)
                binary = base64.b64decode(padded, validate=False)

            key_bytes = key.encode("utf-8")

            # 再按 JS 的思路逐字节 XOR
            decoded = bytes(
                b ^ key_bytes[i % len(key_bytes)]
                for i, b in enumerate(binary)
            )

            return decoded.decode("utf-8")
        except Exception:
            return text
