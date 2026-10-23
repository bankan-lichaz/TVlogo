import base64
import re
import requests

from base.spider import Spider as BaseSpider


class Spider(BaseSpider):
    def init(self, extend=""):
        # extend 传入的是 ext 的值；例如 "key1"
        self.key = (extend or "").strip()

    def getName(self):
        return "Decrypt"

    def liveContent(self, url):
        # TVBox 里 url 是加密内容的地址，ext 是 key
        if not url:
            raise ValueError("missing cipher url")
        cipher = self._read_text(url)
        return self._decrypt(cipher, self.key)

    def localProxy(self, param):
        try:
            # 兼容 TVBox 直接传参形式
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

            content = self._decrypt(self._read_text(url), key)
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
    def _xor_bytes(data: bytes, key: str) -> bytes:
        if not key:
            raise ValueError("missing key")
        key_bytes = key.encode("utf-8")
        return bytes(
            b ^ key_bytes[i % len(key_bytes)]
            for i, b in enumerate(data)
        )

    def _decrypt(self, cipher, key):
        key = str(key or "").strip()
        cipher = str(cipher or "").strip()
        if not key:
            raise ValueError("missing key")
        if not cipher:
            raise ValueError("missing cipher")

        try:
            decoded = base64.b64decode(cipher, validate=True)
        except Exception:
            # 兼容无 padding 或非严格 base64
            pad = "=" * ((4 - len(cipher) % 4) % 4)
            decoded = base64.b64decode(cipher + pad, validate=False)

        plain = self._xor_bytes(decoded, key)
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError:
            return plain.decode("utf-8", errors="replace")
