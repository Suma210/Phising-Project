import ipaddress
import re
import socket
from datetime import date
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois


class FeatureExtraction:
    """Extract the 30 features in the order expected by this project.

    Note: several features depend on external websites/services and use fallback
    values when those services fail. These are heuristic features, not a safety
    guarantee.
    """

    SHORTENER_RE = re.compile(
        r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|"
        r"tr\.im|is\.gd|cli\.gs|tiny\.cc|url4\.eu|snipurl|short\.to|budurl|"
        r"ping\.fm|post\.ly|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
        r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|adf\.ly|"
        r"cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|u\.to|j\.mp|cutt\.us|yourls\.org|"
        r"scrnch\.me|v\.gd|link\.zip\.net)",
        re.IGNORECASE,
    )

    SUSPICIOUS_IP_RE = re.compile(
        r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|"
        r"78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|"
        r"83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|"
        r"64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|"
        r"119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
        r"118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|"
        r"175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|"
        r"103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|"
        r"103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|"
        r"62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
        r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|"
        r"192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|"
        r"52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|"
        r"104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|54\.82\.156\.19|"
        r"37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42"
    )

    def __init__(self, url):
        self.features = []
        self.url = self._normalize_url(str(url).strip())
        self.urlparse = urlparse(self.url)
        self.domain = self.urlparse.hostname or ""
        self.response = None
        self.soup = BeautifulSoup("", "html.parser")
        self.whois_response = None

        try:
            self.response = requests.get(
                self.url,
                timeout=8,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
            )
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except requests.RequestException:
            pass

        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except Exception:
            pass

        # Keep this order aligned with the model's 30 input features.
        self.features = [
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Hppts(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport(),
        ]

    @staticmethod
    def _normalize_url(url):
        if not url.startswith(("http://", "https://")):
            return "https://" + url
        return url

    @staticmethod
    def _date_value(value):
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if isinstance(value, str):
            try:
                from dateutil.parser import parse
                value = parse(value)
            except (ValueError, TypeError, OverflowError):
                return None
        return value if hasattr(value, "year") and hasattr(value, "month") else None

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.urlparse.hostname or "")
            return -1
        except ValueError:
            return 1

    def longUrl(self):
        length = len(self.url)
        if length < 54:
            return 1
        if length <= 75:
            return 0
        return -1

    def shortUrl(self):
        return -1 if self.SHORTENER_RE.search(self.url) else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind("//") > 6 else 1

    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    def SubDomains(self):
        parts = self.domain.split(".")
        if len(parts) <= 2:
            return 1
        if len(parts) == 3:
            return 0
        return -1

    def Hppts(self):
        return 1 if self.urlparse.scheme.lower() == "https" else -1

    def DomainRegLen(self):
        try:
            expiration = self._date_value(self.whois_response.expiration_date)
            creation = self._date_value(self.whois_response.creation_date)
            if not expiration or not creation:
                return -1
            months = (expiration.year - creation.year) * 12 + (
                expiration.month - creation.month
            )
            return 1 if months >= 12 else -1
        except Exception:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all("link", href=True):
                rel = link.get("rel", [])
                if isinstance(rel, str):
                    rel = [rel]
                href = urljoin(self.url, link["href"])
                if any("icon" in item.lower() for item in rel):
                    return 1 if urlparse(href).hostname == self.domain else -1
            return -1
        except Exception:
            return -1

    def NonStdPort(self):
        try:
            port = self.urlparse.port
            return -1 if port and port not in (80, 443) else 1
        except ValueError:
            return -1

    def HTTPSDomainURL(self):
        return -1 if "https" in self.domain.lower() else 1

    def RequestURL(self):
        try:
            tags = self.soup.find_all(["img", "audio", "embed", "iframe"], src=True)
            if not tags:
                return 1
            external = 0
            for tag in tags:
                host = urlparse(urljoin(self.url, tag.get("src", ""))).hostname
                if host and host != self.domain:
                    external += 1
            percentage = external / len(tags) * 100
            if percentage < 22:
                return 1
            if percentage < 61:
                return 0
            return -1
        except Exception:
            return 0

    def AnchorURL(self):
        try:
            links = self.soup.find_all("a", href=True)
            if not links:
                return -1
            unsafe = 0
            for anchor in links:
                href = anchor["href"].strip()
                lowered = href.lower()
                host = urlparse(urljoin(self.url, href)).hostname
                if (
                    lowered.startswith(("#", "javascript:", "mailto:"))
                    or (host is not None and host != self.domain)
                ):
                    unsafe += 1
            percentage = unsafe / len(links) * 100
            if percentage < 31:
                return 1
            if percentage < 67:
                return 0
            return -1
        except Exception:
            return -1

    def LinksInScriptTags(self):
        try:
            tags = self.soup.find_all("link", href=True) + self.soup.find_all("script", src=True)
            if not tags:
                return 0
            external = 0
            for tag in tags:
                attr = "href" if tag.name == "link" else "src"
                host = urlparse(urljoin(self.url, tag.get(attr, ""))).hostname
                if host and host != self.domain:
                    external += 1
            percentage = external / len(tags) * 100
            if percentage < 17:
                return 1
            if percentage < 81:
                return 0
            return -1
        except Exception:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all("form", action=True)
            if not forms:
                return 1
            for form in forms:
                action = form.get("action", "").strip()
                if not action or action.lower() == "about:blank":
                    return -1
                host = urlparse(urljoin(self.url, action)).hostname
                if host and host != self.domain:
                    return 0
            return 1
        except Exception:
            return -1

    def InfoEmail(self):
        try:
            if re.search(r"mailto:|mail\s*\(", str(self.soup), re.IGNORECASE):
                return -1
            return 1
        except Exception:
            return -1

    def AbnormalURL(self):
        try:
            if self.response is None:
                return -1
            final_host = urlparse(self.response.url).hostname
            return 1 if final_host == self.domain else -1
        except Exception:
            return -1

    def WebsiteForwarding(self):
        try:
            if self.response is None:
                return -1
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            if redirects <= 4:
                return 0
            return -1
        except Exception:
            return -1

    def StatusBarCust(self):
        text = self.response.text if self.response is not None else ""
        return 1 if re.search(
            r"<script[^>]*>.*?onmouseover.*?</script>",
            text,
            re.IGNORECASE | re.DOTALL,
        ) else -1

    def DisableRightClick(self):
        text = self.response.text if self.response is not None else ""
        return 1 if re.search(r"event\.button\s*==\s*2", text, re.IGNORECASE) else -1

    def UsingPopupWindow(self):
        text = self.response.text if self.response is not None else ""
        return 1 if re.search(r"alert\s*\(", text, re.IGNORECASE) else -1

    def IframeRedirection(self):
        text = self.response.text if self.response is not None else ""
        return 1 if re.search(r"<iframe\b|<frameborder\b", text, re.IGNORECASE) else -1

    def AgeofDomain(self):
        try:
            creation = self._date_value(self.whois_response.creation_date)
            if not creation:
                return -1
            months = (date.today().year - creation.year) * 12 + (
                date.today().month - creation.month
            )
            return 1 if months >= 6 else -1
        except Exception:
            return -1

    def DNSRecording(self):
        # Preserves the legacy project's use of domain age as a proxy.
        return self.AgeofDomain()

    def WebsiteTraffic(self):
        # Alexa's old ranking service is retired; use a neutral fallback.
        return -1

    def PageRank(self):
        # The legacy PageRank endpoint is unreliable/unavailable.
        return -1

    def GoogleIndex(self):
        try:
            results = search(self.url, num_results=1)
            return 1 if next(iter(results), None) else -1
        except Exception:
            return 1

    def LinksPointingToPage(self):
        text = self.response.text if self.response is not None else ""
        count = len(re.findall(r"<a\s+href\s*=", text, re.IGNORECASE))
        if count == 0:
            return 1
        if count <= 2:
            return 0
        return -1

    def StatsReport(self):
        try:
            if re.search(
                r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|"
                r"hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
                self.url,
                re.IGNORECASE,
            ):
                return -1
            ip_address = socket.gethostbyname(self.domain)
            return -1 if self.SUSPICIOUS_IP_RE.search(ip_address) else 1
        except Exception:
            return 1

    def getFeaturesList(self):
        return self.features
