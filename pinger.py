# enhanced_subdomain_checker.py
# Python 3.10+ önerilir
# pip install aiohttp xlsxwriter aiofiles tqdm requests dnspython

import asyncio
import aiohttp
import csv
import time
import json
import logging
import ssl
import platform
import os
from datetime import datetime, timezone
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import socket

try:
    import xlsxwriter
except ImportError:
    print("⚠ xlsxwriter not found. Install with: pip install xlsxwriter")
    xlsxwriter = None

try:
    import aiofiles
except ImportError:
    print("⚠ aiofiles not found. Install with: pip install aiofiles")
    aiofiles = None

try:
    from tqdm.asyncio import tqdm
except ImportError:
    print("⚠ tqdm not found. Install with: pip install tqdm")
    def tqdm(iterable, *args, **kwargs):
        return iterable

try:
    import dns.resolver
except ImportError:
    print("⚠ dnspython not found. Install with: pip install dnspython")
    dns = None

try:
    import requests
except ImportError:
    print("⚠ requests not found. Install with: pip install requests")
    requests = None

# Konfigürasyon
@dataclass
class Config:
    concurrency: int = 20
    timeout: float = 8.0
    delay: float = 0.02
    max_retries: int = 2
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    output_dir: str = "results"
    enable_dns_check: bool = True
    enable_ssl_check: bool = True
    check_technologies: bool = True
    verbose: bool = False
    # Proxy ayarları
    proxy_url: Optional[str] = None
    proxy_auth: Optional[Tuple[str, str]] = None
    proxy_list: Optional[List[str]] = None
    # Rotating User-Agent
    rotate_user_agents: bool = False
    custom_headers: Optional[Dict[str, str]] = None
    # Gizlilik ve Anonimlik
    tor_proxy: bool = False
    random_delay_range: Optional[Tuple[float, float]] = None
    spoof_headers: bool = False
    disable_fingerprinting: bool = False
    use_different_dns: Optional[str] = None
    random_order: bool = False
    clear_cookies: bool = True
    fake_referer: bool = False
    rotate_proxy_per_request: bool = False
    enable_noise_requests: bool = False
    obfuscate_timing: bool = False

@dataclass
class CheckResult:
    domain: str
    status: str
    method: str
    http_status: Optional[int] = None
    latency_ms: Optional[int] = None
    ssl_valid: Optional[bool] = None
    ssl_expires: Optional[str] = None
    dns_records: Optional[Dict] = None
    technologies: Optional[List[str]] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    error_message: Optional[str] = None
    checked_at: str = ""

class EnhancedSubdomainChecker:
    def __init__(self, config: Config):
        self.config = config
        self.system_os = platform.system()
        self.setup_output_dir()
        self.setup_logging()
        
        # DNS resolver'ı güvenli şekilde ayarla
        if dns:
            self.dns_resolver = dns.resolver.Resolver()
            self.dns_resolver.timeout = config.timeout / 2
            self.dns_resolver.lifetime = config.timeout
        else:
            self.dns_resolver = None
            self.config.enable_dns_check = False
            self.logger.warning("DNS checking disabled - dnspython not available")
        
        # User-Agent pool
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]
        self.current_ua_index = 0
        self.current_proxy_index = 0
        
        self.setup_privacy_settings()
        self.setup_dns_resolver()
        if config.proxy_url or config.proxy_list or config.tor_proxy:
            self.setup_proxy()

    def detect_os_commands(self):
        """İşletim sistemine göre komut desteği"""
        if self.system_os == "Windows":
            return {
                'clear': 'cls',
                'ping': 'ping -n 1',
                'path_sep': '\\'
            }
        else:  # Linux/Unix/macOS
            return {
                'clear': 'clear',
                'ping': 'ping -c 1',
                'path_sep': '/'
            }

    def setup_privacy_settings(self):
        """Gizlilik ayarlarını yapılandır"""
        if self.config.tor_proxy:
            self.config.proxy_url = "socks5://127.0.0.1:9050"
            self.logger.info("Tor proxy enabled (127.0.0.1:9050)")

    def setup_dns_resolver(self):
        """DNS ayarlarını yapılandır"""
        if self.config.use_different_dns and self.dns_resolver:
            try:
                dns_servers = {
                    'cloudflare': ['1.1.1.1', '1.0.0.1'],
                    'google': ['8.8.8.8', '8.8.4.4'],
                    'quad9': ['9.9.9.9', '149.112.112.112'],
                    'opendns': ['208.67.222.222', '208.67.220.220']
                }
                
                if self.config.use_different_dns in dns_servers:
                    self.dns_resolver.nameservers = dns_servers[self.config.use_different_dns]
                    self.logger.info(f"Using {self.config.use_different_dns} DNS servers")
                else:
                    # IP adresi kontrolü
                    import ipaddress
                    try:
                        ipaddress.ip_address(self.config.use_different_dns)
                        self.dns_resolver.nameservers = [self.config.use_different_dns]
                        self.logger.info(f"Using custom DNS: {self.config.use_different_dns}")
                    except ValueError:
                        self.logger.warning(f"Invalid DNS server address: {self.config.use_different_dns}")
            except Exception as e:
                self.logger.warning(f"DNS setup failed: {e}")

    def setup_proxy(self):
        """Proxy ayarlarını yapılandır"""
        try:
            from urllib.parse import urlparse
            proxy_to_check = self.config.proxy_url or (self.config.proxy_list[0] if self.config.proxy_list else None)
            if not proxy_to_check:
                return
                
            parsed = urlparse(proxy_to_check)
            if parsed.scheme not in ['http', 'https', 'socks4', 'socks5']:
                self.logger.error(f"Unsupported proxy scheme: {parsed.scheme}")
                return
            
            if self.config.proxy_list:
                self.logger.info(f"Using proxy rotation with {len(self.config.proxy_list)} proxies")
            else:
                self.logger.info(f"Using proxy: {parsed.scheme}://{parsed.hostname}:{parsed.port}")
                
        except Exception as e:
            self.logger.error(f"Invalid proxy configuration: {e}")
            self.config.proxy_url = None
            self.config.proxy_list = None

    def setup_logging(self):
        """Logging yapılandırması"""
        log_level = logging.DEBUG if self.config.verbose else logging.INFO
        
        # Platform bağımsız log formatı
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        handlers = [logging.StreamHandler()]
        
        try:
            # Platform bağımsız dosya yolu
            commands = self.detect_os_commands()
            log_file = os.path.join(self.config.output_dir, 'checker.log')
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)
        except Exception as e:
            print(f"Warning: Could not create log file: {e}")
        
        # Mevcut loggerları temizle
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=handlers,
            force=True
        )
        
        self.logger = logging.getLogger(__name__)

    def setup_output_dir(self):
        """Çıktı dizinini oluştur"""
        output_path = Path(self.config.output_dir)
        try:
            output_path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="subdomain_check_")
            self.config.output_dir = temp_dir
            print(f"Warning: Permission denied. Using temporary directory: {temp_dir}")
        except Exception as e:
            print(f"Error: Could not create output directory: {e}")
            self.config.output_dir = "."

    def get_current_proxy(self) -> Optional[str]:
        """Geçerli proxy URL'ini döndür"""
        if self.config.tor_proxy:
            return "socks5://127.0.0.1:9050"
        
        if self.config.proxy_list:
            if self.config.rotate_proxy_per_request:
                import random
                return random.choice(self.config.proxy_list)
            else:
                proxy = self.config.proxy_list[self.current_proxy_index % len(self.config.proxy_list)]
                self.current_proxy_index += 1
                return proxy
        return self.config.proxy_url

    def get_headers(self) -> Dict[str, str]:
        """HTTP header'larını hazırla"""
        headers = {}
        
        if self.config.rotate_user_agents:
            headers['User-Agent'] = self.user_agents[self.current_ua_index % len(self.user_agents)]
            self.current_ua_index += 1
        else:
            headers['User-Agent'] = self.config.user_agent
        
        base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if self.config.disable_fingerprinting:
            base_headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'DNT': '1'
            })
        
        if self.config.fake_referer:
            import random
            fake_referers = [
                'https://www.google.com/search?q=site+analysis',
                'https://www.bing.com/search?q=website+checker',
                'https://duckduckgo.com/?q=domain+scanner',
            ]
            headers['Referer'] = random.choice(fake_referers)
        
        # Base headers'ı ekle
        for key, value in base_headers.items():
            if key not in headers:
                headers[key] = value
        
        # Custom headers varsa ekle
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
            
        return headers

    def get_random_delay(self) -> float:
        """Random delay döndür"""
        if self.config.random_delay_range:
            import random
            return random.uniform(self.config.random_delay_range[0], self.config.random_delay_range[1])
        return self.config.delay

    async def dns_lookup(self, domain: str) -> Optional[Dict]:
        """DNS kayıtlarını kontrol et"""
        if not self.config.enable_dns_check or not self.dns_resolver:
            return None
            
        try:
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                try:
                    # Timeout kontrolü ile DNS sorgusu
                    future = loop.run_in_executor(
                        executor, 
                        lambda: [str(r) for r in self.dns_resolver.resolve(domain, 'A')]
                    )
                    a_records = await asyncio.wait_for(future, timeout=self.config.timeout / 2)
                    return {'A': a_records} if a_records else None
                except asyncio.TimeoutError:
                    self.logger.debug(f"DNS lookup timeout for {domain}")
                    return None
                except Exception as e:
                    self.logger.debug(f"DNS lookup error for {domain}: {e}")
                    return None
        except Exception as e:
            self.logger.debug(f"DNS lookup failed for {domain}: {e}")
            return None

    async def check_ssl_certificate(self, domain: str) -> Tuple[Optional[bool], Optional[str]]:
        """SSL sertifika kontrolü"""
        if not self.config.enable_ssl_check:
            return None, None
            
        try:
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                def get_ssl_info():
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((domain, 443), timeout=self.config.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                cert = ssock.getpeercert()
                                if not cert:
                                    return False, None
                                    
                                not_after = cert.get('notAfter')
                                if not_after:
                                    try:
                                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                        return True, expire_date.isoformat()
                                    except ValueError:
                                        return True, not_after
                                return True, None
                    except Exception:
                        return False, None
                
                future = loop.run_in_executor(executor, get_ssl_info)
                return await asyncio.wait_for(future, timeout=self.config.timeout)
        except asyncio.TimeoutError:
            self.logger.debug(f"SSL check timeout for {domain}")
            return False, None
        except Exception as e:
            self.logger.debug(f"SSL check failed for {domain}: {e}")
            return False, None

    def detect_technologies(self, headers: Dict[str, str], html_content: str = "") -> List[str]:
        """Web teknolojilerini tespit et"""
        if not self.config.check_technologies:
            return []
            
        technologies = []
        
        # Server header kontrolü
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        elif 'microsoft-iis' in server:
            technologies.append('IIS')
        
        # X-Powered-By kontrolü
        if headers.get('x-powered-by'):
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
        
        # CDN kontrolü
        header_str = str(headers).lower()
        if any(cdn in header_str for cdn in ['cloudflare', 'cloudfront', 'fastly', 'maxcdn']):
            technologies.append('CDN')
        
        # HTML içerik analizi (basit)
        if html_content:
            html_lower = html_content.lower()
            if 'wordpress' in html_lower or 'wp-content' in html_lower:
                technologies.append('WordPress')
            elif 'drupal' in html_lower:
                technologies.append('Drupal')
            elif 'joomla' in html_lower:
                technologies.append('Joomla')
            
        return list(set(technologies))  # Duplikatları kaldır

    async def advanced_http_check(self, session: aiohttp.ClientSession, url: str, timeout: float) -> Tuple[bool, Optional[int], Optional[float], Dict]:
        """Gelişmiş HTTP kontrolü"""
        start = time.monotonic()
        extra_info = {}
        
        headers = self.get_headers()
        
        if self.config.obfuscate_timing:
            import random
            await asyncio.sleep(random.uniform(0.01, 0.1))
        
        try:
            if self.config.clear_cookies and hasattr(session, 'cookie_jar'):
                session.cookie_jar.clear()
            
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), 
                                 allow_redirects=True, headers=headers) as resp:
                rtt_ms = (time.monotonic() - start) * 1000
                
                extra_info.update({
                    'title': None,
                    'server': resp.headers.get('Server'),
                    'content_length': resp.headers.get('Content-Length'),
                    'redirect_url': str(resp.url) if str(resp.url) != url else None,
                    'technologies': []
                })
                
                # İçerik analizi
                content_type = resp.headers.get('content-type', '').lower()
                if 'text/html' in content_type and resp.status == 200:
                    try:
                        content = await resp.text()
                        import re
                        
                        # Title çıkarma
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                        if title_match:
                            extra_info['title'] = title_match.group(1).strip()[:100]
                        
                        # Teknoloji tespiti
                        extra_info['technologies'] = self.detect_technologies(dict(resp.headers), content)
                    except Exception as e:
                        self.logger.debug(f"Content analysis failed for {url}: {e}")
                        extra_info['technologies'] = self.detect_technologies(dict(resp.headers))
                else:
                    extra_info['technologies'] = self.detect_technologies(dict(resp.headers))
                
                return True, resp.status, rtt_ms, extra_info
                
        except aiohttp.ClientResponseError as e:
            rtt_ms = (time.monotonic() - start) * 1000
            extra_info['error_message'] = f"HTTP {e.status}: {e.message}"
            return False, getattr(e, 'status', None), rtt_ms, extra_info
        except asyncio.TimeoutError:
            extra_info['error_message'] = "Connection timeout"
            return False, None, None, extra_info
        except aiohttp.ClientConnectorError as e:
            extra_info['error_message'] = f"Connection failed: {str(e)[:100]}"
            return False, None, None, extra_info
        except Exception as e:
            extra_info['error_message'] = str(e)[:200]
            return False, None, None, extra_info

    async def check_single_domain(self, domain: str, session: aiohttp.ClientSession, 
                                sem: asyncio.Semaphore) -> CheckResult:
        """Tek domain kontrolü"""
        async with sem:
            delay = self.get_random_delay()
            if delay > 0:
                await asyncio.sleep(delay)
            
            checked_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            
            domain = domain.strip()
            if not domain:
                return CheckResult(domain="", status="invalid", method="none", checked_at=checked_at)

            # Domain formatını temizle
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            if not domain:
                return CheckResult(domain="", status="invalid", method="none", checked_at=checked_at)

            result = CheckResult(domain=domain, status="down", method="none", checked_at=checked_at)
            
            # DNS kontrolü
            if self.config.enable_dns_check:
                result.dns_records = await self.dns_lookup(domain)
                
            # HTTPS kontrolü
            success, status, rtt, extra = await self.advanced_http_check(
                session, f"https://{domain}", self.config.timeout
            )
            
            if success:
                result.status = "up"
                result.method = "https"
                result.http_status = status
                result.latency_ms = round(rtt or 0)
                result.title = extra.get('title')
                result.server = extra.get('server')
                result.content_length = extra.get('content_length')
                result.redirect_url = extra.get('redirect_url')
                result.technologies = extra.get('technologies', [])
                
                # SSL kontrolü
                if self.config.enable_ssl_check:
                    ssl_valid, ssl_expires = await self.check_ssl_certificate(domain)
                    result.ssl_valid = ssl_valid
                    result.ssl_expires = ssl_expires
                
                return result

            # HTTP kontrolü (HTTPS başarısız olursa)
            success, status, rtt, extra = await self.advanced_http_check(
                session, f"http://{domain}", self.config.timeout
            )
            
            if success:
                result.status = "up"
                result.method = "http"
                result.http_status = status
                result.latency_ms = round(rtt or 0)
                result.title = extra.get('title')
                result.server = extra.get('server')
                result.content_length = extra.get('content_length')
                result.redirect_url = extra.get('redirect_url')
                result.technologies = extra.get('technologies', [])
                return result
                    
            # Hata mesajını kaydet
            if extra.get('error_message'):
                result.error_message = extra['error_message']
                
            return result

    async def run_checks(self, domains: List[str]) -> List[CheckResult]:
        """Ana kontrol döngüsü"""
        if self.config.random_order:
            import random
            domains = domains.copy()
            random.shuffle(domains)
            self.logger.info("Domain order randomized")
        
        sem = asyncio.Semaphore(self.config.concurrency)
        
        # Connector ayarları
        connector_kwargs = {
            'limit': self.config.concurrency,
            'ssl': False,
            'enable_cleanup_closed': True,
            'ttl_dns_cache': 300
        }
        
        current_proxy = self.get_current_proxy()
        connector = None
        
        # Proxy ayarları
        if current_proxy:
            try:
                if current_proxy.startswith(('socks4://', 'socks5://')):
                    try:
                        from aiohttp_socks import ProxyConnector
                        connector = ProxyConnector.from_url(current_proxy, **connector_kwargs)
                        self.logger.info(f"Using SOCKS proxy: {current_proxy}")
                    except ImportError:
                        self.logger.error("aiohttp-socks not installed. Use: pip install aiohttp-socks")
                        connector = aiohttp.TCPConnector(**connector_kwargs)
                else:
                    connector = aiohttp.TCPConnector(**connector_kwargs)
                    self.logger.info(f"Using HTTP proxy: {current_proxy}")
            except Exception as e:
                self.logger.error(f"Proxy setup failed: {e}")
                connector = aiohttp.TCPConnector(**connector_kwargs)
        
        if not connector:
            connector = aiohttp.TCPConnector(**connector_kwargs)
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        session_kwargs = {
            'connector': connector, 
            'timeout': timeout,
        }
        
        # HTTP proxy authentication
        if current_proxy and not current_proxy.startswith(('socks4://', 'socks5://')):
            if self.config.proxy_auth:
                session_kwargs['auth'] = aiohttp.BasicAuth(
                    self.config.proxy_auth[0], 
                    self.config.proxy_auth[1]
                )
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            tasks = [self.check_single_domain(domain, session, sem) for domain in domains]
            
            results = []
            proxy_info = f" via proxy" if current_proxy else ""
            print(f"\nScanning {len(domains)} domains with {self.config.concurrency} concurrent connections{proxy_info}...")
            
            if self.config.verbose:
                for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Checking domains"):
                    try:
                        result = await task
                        results.append(result)
                        
                        if result.status == "up":
                            method_emoji = "🔒" if result.method == "https" else "🌐"
                            ssl_emoji = " ✅" if result.ssl_valid else " ⚠️" if result.ssl_valid is False else ""
                            print(f"{method_emoji} {result.domain:<30} {result.latency_ms:>4}ms{ssl_emoji}")
                    except Exception as e:
                        self.logger.error(f"Task execution error: {e}")
            else:
                # Batch processing for better memory management
                chunk_size = min(200, len(tasks))
                for i in tqdm(range(0, len(tasks), chunk_size), desc="Processing batches"):
                    batch = tasks[i:i + chunk_size]
                    try:
                        batch_results = await asyncio.gather(*batch, return_exceptions=True)
                        
                        for result in batch_results:
                            if isinstance(result, Exception):
                                self.logger.error(f"Batch processing error: {result}")
                            else:
                                results.append(result)
                    except Exception as e:
                        self.logger.error(f"Batch execution error: {e}")

        return [r for r in results if r and r.domain]

    def save_csv(self, results: List[CheckResult]) -> str:
        """CSV formatında kaydet"""
        csv_file = os.path.join(self.config.output_dir, "detailed_results.csv")
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                headers = [
                    'domain', 'status', 'method', 'http_status', 'latency_ms',
                    'ssl_valid', 'ssl_expires', 'title', 'server', 'content_length',
                    'redirect_url', 'technologies', 'dns_a_records', 'error_message', 'checked_at'
                ]
                writer.writerow(headers)
                
                for result in results:
                    dns_a = ','.join(result.dns_records.get('A', [])) if result.dns_records else ''
                    tech_str = ','.join(result.technologies) if result.technologies else ''
                    
                    writer.writerow([
                        result.domain, result.status, result.method, result.http_status,
                        result.latency_ms, result.ssl_valid, result.ssl_expires,
                        result.title, result.server, result.content_length,
                        result.redirect_url, tech_str, dns_a, result.error_message, result.checked_at
                    ])
        except Exception as e:
            self.logger.error(f"Error saving CSV: {e}")
            return ""
        
        return csv_file

    def save_json(self, results: List[CheckResult]) -> str:
        """JSON formatında kaydet"""
        json_file = os.path.join(self.config.output_dir, "results.json")
        
        try:
            json_data = []
            for result in results:
                json_data.append({
                    'domain': result.domain,
                    'status': result.status,
                    'method': result.method,
                    'http_status': result.http_status,
                    'latency_ms': result.latency_ms,
                    'ssl_valid': result.ssl_valid,
                    'ssl_expires': result.ssl_expires,
                    'dns_records': result.dns_records,
                    'technologies': result.technologies,
                    'title': result.title,
                    'server': result.server,
                    'content_length': result.content_length,
                    'redirect_url': result.redirect_url,
                    'error_message': result.error_message,
                    'checked_at': result.checked_at
                })
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Error saving JSON: {e}")
            return ""
        
        return json_file

    def create_advanced_excel(self, results: List[CheckResult]) -> str:
        """Excel raporu oluştur"""
        if not xlsxwriter:
            self.logger.warning("xlsxwriter not available, skipping Excel creation")
            return ""
            
        excel_file = os.path.join(self.config.output_dir, "advanced_results.xlsx")
        try:
            workbook = xlsxwriter.Workbook(excel_file)
        except Exception as e:
            self.logger.error(f"Could not create Excel file: {e}")
            return ""
        
        # Formatları tanımla
        header_format = workbook.add_format({
            'bold': True, 'bg_color': '#366092', 'font_color': 'white',
            'border': 1, 'align': 'center'
        })
        
        up_format = workbook.add_format({
            'bg_color': '#C6EFCE', 'font_color': '#006100', 'border': 1
        })
        
        down_format = workbook.add_format({
            'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1
        })
        
        normal_format = workbook.add_format({'border': 1})
        
        # Ana sayfa
        ws_main = workbook.add_worksheet('Detailed Results')
        headers = [
            'Domain', 'Status', 'Method', 'HTTP Status', 'Latency (ms)',
            'SSL Valid', 'SSL Expires', 'Title', 'Server', 'Technologies',
            'Error Message', 'Checked At'
        ]
        
        for col, header in enumerate(headers):
            ws_main.write(0, col, header, header_format)
        
        for row, result in enumerate(results, 1):
            ws_main.write(row, 0, result.domain, normal_format)
            
            status_fmt = up_format if result.status == 'up' else down_format
            ws_main.write(row, 1, result.status, status_fmt)
            
            ws_main.write(row, 2, result.method or '', normal_format)
            ws_main.write(row, 3, result.http_status or '', normal_format)
            ws_main.write(row, 4, result.latency_ms or '', normal_format)
            ws_main.write(row, 5, 'Yes' if result.ssl_valid else 'No' if result.ssl_valid is False else '', normal_format)
            ws_main.write(row, 6, result.ssl_expires or '', normal_format)
            ws_main.write(row, 7, result.title or '', normal_format)
            ws_main.write(row, 8, result.server or '', normal_format)
            ws_main.write(row, 9, ', '.join(result.technologies) if result.technologies else '', normal_format)
            ws_main.write(row, 10, result.error_message or '', normal_format)
            ws_main.write(row, 11, result.checked_at, normal_format)
        
        # Sütun genişliklerini ayarla
        ws_main.set_column(0, 0, 30)  # Domain
        ws_main.set_column(7, 7, 40)  # Title
        
        # İstatistik sayfası
        ws_stats = workbook.add_worksheet('Statistics')
        total = len(results)
        up_count = sum(1 for r in results if r.status == 'up')
        down_count = total - up_count
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Domains', total],
            ['Active Domains', up_count],
            ['Inactive Domains', down_count],
            ['Success Rate (%)', round(up_count/total*100, 2) if total > 0 else 0],
        ]
        
        for row, (metric, value) in enumerate(stats_data):
            if row == 0:
                ws_stats.write(row, 0, metric, header_format)
                ws_stats.write(row, 1, value, header_format)
            else:
                ws_stats.write(row, 0, metric, normal_format)
                ws_stats.write(row, 1, value, normal_format)
        
        ws_stats.set_column(0, 0, 20)
        ws_stats.set_column(1, 1, 15)
        
        try:
            workbook.close()
        except Exception as e:
            self.logger.error(f"Error closing Excel file: {e}")
            return ""
            
        return excel_file

    def generate_summary_report(self, results: List[CheckResult]) -> str:
        """Özet rapor oluştur"""
        total = len(results)
        up_count = sum(1 for r in results if r.status == 'up')
        down_count = total - up_count
        
        # Ortalama gecikme hesapla
        avg_latency = 0
        latencies = [r.latency_ms for r in results if r.latency_ms]
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
        
        https_count = sum(1 for r in results if r.method == 'https')
        ssl_valid = sum(1 for r in results if r.ssl_valid)
        
        # En yaygın teknolojiler
        tech_count = {}
        for result in results:
            if result.technologies:
                for tech in result.technologies:
                    tech_count[tech] = tech_count.get(tech, 0) + 1
        
        top_techs = sorted(tech_count.items(), key=lambda x: x[1], reverse=True)[:5]
        
        report = f"""# Subdomain Checker Report
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
System: {platform.system()} {platform.release()}

## Summary
- **Total Domains Checked:** {total:,}
- **Active Domains:** {up_count:,} ({up_count/total*100:.1f}%)
- **Inactive Domains:** {down_count:,} ({down_count/total*100:.1f}%)
- **Average Response Time:** {avg_latency:.0f}ms
- **HTTPS Support:** {https_count:,} ({https_count/total*100:.1f}%)
- **Valid SSL Certificates:** {ssl_valid:,}

## Top Technologies Found
"""
        
        for tech, count in top_techs:
            report += f"- {tech}: {count} domains\n"
        
        # En hızlı domainler
        fastest_domains = sorted([r for r in results if r.status == 'up' and r.latency_ms], 
                                key=lambda x: x.latency_ms)[:5]
        
        if fastest_domains:
            report += "\n## Fastest Responding Domains\n"
            for domain in fastest_domains:
                report += f"- {domain.domain}: {domain.latency_ms}ms\n"
        
        report_file = os.path.join(self.config.output_dir, "summary_report.md")
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            return ""
        
        return report_file

def load_domains_from_file(file_path: str) -> List[str]:
    """Dosyadan domain listesi yükle"""
    domains = []
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    # URL formatını temizle
                    domain = domain.replace('http://', '').replace('https://', '')
                    domain = domain.split('/')[0]  # Path kısmını kaldır
                    if domain and '.' in domain:  # Geçerli domain formatı kontrolü
                        domains.append(domain)
                    elif domain:  # Geçersiz format uyarısı
                        print(f"Warning: Invalid domain format at line {line_num}: {domain}")
    except UnicodeDecodeError:
        # Farklı encoding dene
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        domain = domain.replace('http://', '').replace('https://', '')
                        domain = domain.split('/')[0]
                        if domain and '.' in domain:
                            domains.append(domain)
        except Exception as e:
            raise Exception(f"Could not read file with any encoding: {e}")
    except Exception as e:
        raise Exception(f"Error reading file: {e}")
    
    return list(set(domains))  # Duplikatları kaldır

def print_usage_examples():
    """Kullanım örnekleri yazdır"""
    examples = """
Usage Examples:

Basic usage:
  python pinger.py domains.txt

With increased concurrency:
  python pinger.py domains.txt --concurrency 50

With proxy:
  python pinger.py domains.txt --proxy socks5://127.0.0.1:9050

With Tor and verbose output:
  python pinger.py domains.txt --tor --verbose

With custom DNS and randomization:
  python pinger.py domains.txt --dns cloudflare --randomize

Full privacy mode:
  python pinger.py domains.txt --tor --rotate-ua --anti-fingerprint --randomize

Performance mode:
  python pinger.py domains.txt --concurrency 100 --timeout 5 --delay 0.01
"""
    print(examples)

async def main():
    parser = ArgumentParser(description="Enhanced Subdomain Checker with advanced features")
    
    # Temel argümanlar
    parser.add_argument("file", nargs='?', help="Domain list file (one per line)")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrent requests (default: 20)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8.0)")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between requests (default: 0.02)")
    parser.add_argument("--retries", type=int, default=2, help="Max retry attempts (default: 2)")
    parser.add_argument("--output-dir", default="results", help="Output directory (default: results)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # Özellik kontrolleri
    parser.add_argument("--no-dns", action="store_true", help="Disable DNS checking")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL checking")
    parser.add_argument("--no-tech", action="store_true", help="Disable technology detection")
    
    # Proxy ve User-Agent ayarları
    parser.add_argument("--proxy", help="Proxy URL (http://ip:port, socks5://ip:port)")
    parser.add_argument("--proxy-list", help="File containing proxy URLs (one per line)")
    parser.add_argument("--proxy-auth", help="Proxy authentication (username:password)")
    parser.add_argument("--user-agent", 
                       default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                       help="Custom User-Agent string")
    parser.add_argument("--rotate-ua", action="store_true", 
                       help="Rotate between multiple User-Agents")
    parser.add_argument("--custom-headers", 
                       help="Custom headers in JSON format: '{\"X-Custom\":\"value\"}'")
    
    # Gizlilik ve Anonimlik
    parser.add_argument("--tor", action="store_true", help="Use Tor proxy (127.0.0.1:9050)")
    parser.add_argument("--random-delay", help="Random delay range (min:max in seconds, e.g., 0.1:2.0)")
    parser.add_argument("--spoof-headers", action="store_true", help="Spoof browser headers")
    parser.add_argument("--anti-fingerprint", action="store_true", help="Anti-fingerprinting measures")
    parser.add_argument("--dns", help="Use different DNS server (cloudflare, google, quad9, opendns, or IP)")
    parser.add_argument("--custom-dns", help="Custom DNS server IP")
    parser.add_argument("--randomize", action="store_true", help="Randomize domain order")
    parser.add_argument("--clear-cookies", action="store_true", help="Clear cookies between requests")
    parser.add_argument("--fake-referer", action="store_true", help="Use fake referer headers")
    parser.add_argument("--rotate-proxy-per-req", action="store_true", help="Rotate proxy per request")
    parser.add_argument("--noise-requests", action="store_true", help="Send noise requests")
    parser.add_argument("--obfuscate-timing", action="store_true", help="Obfuscate request timing")
    
    # Yardım ve örnekler
    parser.add_argument("--examples", action="store_true", help="Show usage examples")

    args = parser.parse_args()
    
    # Örnekleri göster
    if args.examples:
        print_usage_examples()
        return
    
    # Dosya argümanı kontrolü
    if not args.file:
        parser.print_help()
        print("\nError: Domain file is required")
        print("Use --examples to see usage examples")
        return
    
    # Custom headers parse et
    custom_headers = None
    if args.custom_headers:
        try:
            custom_headers = json.loads(args.custom_headers)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in custom headers: {args.custom_headers}")
            return
    
    # Proxy auth parse et  
    proxy_auth = None
    if args.proxy_auth:
        if ':' in args.proxy_auth:
            username, password = args.proxy_auth.split(':', 1)
            proxy_auth = (username, password)
        else:
            print("Error: Proxy auth format should be username:password")
            return

    # Random delay parse et
    random_delay_range = None
    if args.random_delay:
        try:
            if ':' in args.random_delay:
                min_delay, max_delay = map(float, args.random_delay.split(':'))
                if min_delay >= max_delay:
                    print("Error: Min delay must be less than max delay")
                    return
                random_delay_range = (min_delay, max_delay)
            else:
                print("Error: Random delay format should be min:max (e.g., 0.1:2.0)")
                return
        except ValueError:
            print("Error: Invalid random delay values")
            return
    
    # Proxy list yükle
    proxy_list = []
    if args.proxy_list:
        try:
            with open(args.proxy_list, 'r') as f:
                proxy_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"Loaded {len(proxy_list)} proxies from {args.proxy_list}")
        except FileNotFoundError:
            print(f"Error: Proxy list file not found: {args.proxy_list}")
            return
        except Exception as e:
            print(f"Error reading proxy list: {e}")
            return
    
    # DNS ayarları
    dns_server = args.custom_dns or args.dns
    
    # Konfigürasyon oluştur
    config = Config(
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
        max_retries=args.retries,
        user_agent=args.user_agent,
        output_dir=args.output_dir,
        enable_dns_check=not args.no_dns,
        enable_ssl_check=not args.no_ssl,
        check_technologies=not args.no_tech,
        verbose=args.verbose,
        # Proxy ayarları
        proxy_url=args.proxy,
        proxy_list=proxy_list if proxy_list else None,
        proxy_auth=proxy_auth,
        rotate_user_agents=args.rotate_ua,
        custom_headers=custom_headers,
        # Gizlilik ayarları
        tor_proxy=args.tor,
        random_delay_range=random_delay_range,
        spoof_headers=args.spoof_headers,
        disable_fingerprinting=args.anti_fingerprint,
        use_different_dns=dns_server,
        random_order=args.randomize,
        clear_cookies=args.clear_cookies,
        fake_referer=args.fake_referer,
        rotate_proxy_per_request=args.rotate_proxy_per_req,
        enable_noise_requests=args.noise_requests,
        obfuscate_timing=args.obfuscate_timing,
    )
    
    try:
        # Domain listesini yükle
        print(f"Loading domains from {args.file}...")
        domains = load_domains_from_file(args.file)
        print(f"Loaded {len(domains)} unique domains")
        
        if not domains:
            print("Error: No valid domains found in file!")
            return
        
        # Checker oluştur ve çalıştır
        checker = EnhancedSubdomainChecker(config)
        
        print(f"Starting domain checks with {config.concurrency} concurrent connections...")
        start_time = time.time()
        
        results = await checker.run_checks(domains)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Sonuçları kaydet
        print("\nSaving results...")
        csv_file = checker.save_csv(results)
        json_file = checker.save_json(results)
        excel_file = checker.create_advanced_excel(results)
        report_file = checker.generate_summary_report(results)
        
        # Özet istatistikler
        total = len(results)
        up_count = sum(1 for r in results if r.status == 'up')
        down_count = total - up_count
        
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETED IN {duration:.1f} SECONDS")
        print(f"{'='*60}")
        print(f"Total Domains: {total:,}")
        print(f"Active: {up_count:,} ({up_count/total*100:.1f}%)")
        print(f"Inactive: {down_count:,} ({down_count/total*100:.1f}%)")
        print(f"Rate: {total/duration:.1f} domains/second")
        
        if results:
            latencies = [r.latency_ms for r in results if r.latency_ms]
            if latencies:
                print(f"Avg Response Time: {sum(latencies)/len(latencies):.0f}ms")
            
            https_count = sum(1 for r in results if r.method == 'https')
            ssl_valid = sum(1 for r in results if r.ssl_valid)
            print(f"HTTPS Support: {https_count:,} ({https_count/total*100:.1f}%)")
            print(f"Valid SSL: {ssl_valid:,}")
        
        print(f"\nOutput Files:")
        if csv_file:
            print(f"  • CSV: {csv_file}")
        if json_file:
            print(f"  • JSON: {json_file}")
        if excel_file:
            print(f"  • Excel: {excel_file}")
        if report_file:
            print(f"  • Report: {report_file}")
        
        # En aktif domainleri göster
        active_domains = [r for r in results if r.status == 'up']
        if active_domains:
            print(f"\nSample Active Domains:")
            for domain in sorted(active_domains, key=lambda x: x.latency_ms or 999999)[:5]:
                method_icon = "HTTPS" if domain.method == 'https' else "HTTP"
                ssl_icon = " (SSL)" if domain.ssl_valid else " (No SSL)" if domain.ssl_valid is False else ""
                tech_str = f" [{domain.technologies[0]}]" if domain.technologies else ""
                print(f"  {method_icon} {domain.domain} ({domain.latency_ms}ms){ssl_icon}{tech_str}")
        
        print(f"\nTip: Open {excel_file} for detailed analysis!" if excel_file else "")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except FileNotFoundError as e:
        print(f"\nError: {e}")
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        # Windows için event loop policy ayarla
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Fatal error: {e}")
        import sys
        sys.exit(1)