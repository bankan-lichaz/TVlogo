import base64
import re
import requests

from base.spider import Spider as BaseSpider


class Spider(BaseSpider):
    def init(self, extend=""):
        # extend = ext 里的值，比如 "key1"
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
            response = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            response.raise_for_status()
            return response.text
        return url

    @staticmethod
    def _decrypt_text(text, key):
        compact = str(text or "").strip()
        key = str(key or "").strip()

        if not compact:
            return ""
        if not key:
            raise ValueError("missing key")

        # 只处理标准 Base64 字符串
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
            return compact

        try:
            # Base64 -> bytes
            try:
                binary = base64.b64decode(compact, validate=True)
            except Exception:
                padded = compact + "=" * ((4 - len(compact) % 4) % 4)
                binary = base64.b64decode(padded, validate=False)

            # XOR 解密
            key_bytes = key.encode("utf-8")
            plain = bytes(
                b ^ key_bytes[i % len(key_bytes)]
                for i, b in enumerate(binary)
            )

            # 直接返回明文，不做 JSON 格式化
            try:
                return plain.decode("utf-8")
            except UnicodeDecodeError:
                return plain.decode("utf-8", errors="replace")
        except Exception:
            # 解不出来就原样返回
            return compact
