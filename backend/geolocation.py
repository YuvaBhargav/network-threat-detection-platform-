"""
IP Geolocation service for threat intelligence
Supports multiple free APIs with fallback
"""
import requests
import time
from config import get_config

class GeolocationService:
    def __init__(self):
        self.config = get_config()["geolocation"]
        self.enabled = self.config.get("enabled", True)
        self.cache = {}
        self.rate_limit_delay = 1.0  # Delay between requests to respect rate limits
        
    def get_location(self, ip_address):
        """
        Get geolocation data for an IP address
        Returns dict with: country, city, lat, lon, isp, org
        """
        if not self.enabled:
            print(f"Geolocation disabled for {ip_address}")
            return None
        
        # Normalize IP address
        ip_address = str(ip_address).strip()
        
        if not ip_address or ip_address == "N/A" or ip_address.lower() == "nan":
            return None
            
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        # Skip private/local IPs but return a meaningful response
        if ip_address.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.", 
                                   "172.18.", "172.19.", "172.20.", "172.21.", 
                                   "172.22.", "172.23.", "172.24.", "172.25.", 
                                   "172.26.", "172.27.", "172.28.", "172.29.", 
                                   "172.30.", "172.31.", "169.254.")):
            result = {
                "country": "Local",
                "country_code": "LOCAL",
                "city": "Private Network",
                "lat": None,
                "lon": None,
                "isp": "Local Network",
                "org": "Private IP Range"
            }
            self.cache[ip_address] = result
            return result
        
        provider = self.config.get("api_provider", "ipapi")
        api_key = self.config.get("api_key")
        
        # Try primary provider first
        result = None
        providers_to_try = [provider]
        
        # Add fallback providers
        if provider != "ip-api":
            providers_to_try.append("ip-api")
        if provider != "ipinfo":
            providers_to_try.append("ipinfo")
        
        for prov in providers_to_try:
            try:
                print(f"🔍 Looking up {ip_address} using {prov}...")
                if prov == "ipapi":
                    result = self._query_ipapi(ip_address, api_key)
                elif prov == "ip-api":
                    result = self._query_ipapi_com(ip_address)
                elif prov == "ipinfo":
                    result = self._query_ipinfo(ip_address, api_key)
                
                if result:
                    print(f"✅ Geolocation found for {ip_address}: {result.get('city', 'Unknown')}, {result.get('country', 'Unknown')}")
                    self.cache[ip_address] = result
                    # Only sleep if we made an actual API call (not cached)
                    if prov == provider:  # Only sleep for primary provider to avoid delays
                        time.sleep(self.rate_limit_delay)
                    return result
            except Exception as e:
                print(f"⚠️ Geolocation error for {ip_address} using {prov}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"❌ No geolocation data found for {ip_address}")
        return None
    
    def _query_ipapi(self, ip, api_key=None):
        """Query ipapi.co (free tier: 1000 requests/day)"""
        url = f"https://ipapi.co/{ip}/json/"
        if api_key:
            url += f"?key={api_key}"
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                data = response.json()
                if "error" not in data:
                    return {
                        "country": data.get("country_name", "Unknown"),
                        "country_code": data.get("country_code", ""),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "isp": data.get("org", ""),
                        "org": data.get("org", "")
                    }
                else:
                    print(f"ipapi.co error: {data.get('reason', 'Unknown error')}")
            else:
                print(f"ipapi.co HTTP {response.status_code}: {response.text[:100]}")
        except Exception as e:
            print(f"ipapi.co exception: {e}")
        return None
    
    def _query_ipapi_com(self, ip):
        """Query ip-api.com (free tier: 45 requests/minute)"""
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org"
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", "")
                    }
                else:
                    print(f"ip-api.com error: {data.get('message', 'Unknown error')}")
            else:
                print(f"ip-api.com HTTP {response.status_code}")
        except Exception as e:
            print(f"ip-api.com exception: {e}")
        return None
    
    def _query_ipinfo(self, ip, api_key=None):
        """Query ipinfo.io (free tier: 50k requests/month)"""
        url = f"https://ipinfo.io/{ip}/json"
        headers = {'User-Agent': 'Mozilla/5.0'}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                loc = data.get("loc", "")
                lat, lon = None, None
                if loc:
                    try:
                        parts = loc.split(",")
                        if len(parts) >= 2:
                            lat = float(parts[0]) if parts[0] else None
                            lon = float(parts[1]) if parts[1] else None
                    except (ValueError, IndexError):
                        pass
                
                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("country", ""),
                    "city": data.get("city", "Unknown"),
                    "lat": lat,
                    "lon": lon,
                    "isp": data.get("org", ""),
                    "org": data.get("org", "")
                }
            else:
                print(f"ipinfo.io HTTP {response.status_code}")
        except Exception as e:
            print(f"ipinfo.io exception: {e}")
        return None

# Singleton instance
_geolocation_service = None

def get_geolocation_service():
    global _geolocation_service
    if _geolocation_service is None:
        _geolocation_service = GeolocationService()
    return _geolocation_service

