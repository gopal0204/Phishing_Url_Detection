import pandas as pd
from urllib.parse import urlparse
import re
import whois
import urllib.request
import time
from bs4 import BeautifulSoup
import socket
from urllib.error import HTTPError
from datetime import datetime
import requests

class FeatureExtraction:
    def __init__(self):
        pass
    
    def getProtocol(self, url):
        return urlparse(url).scheme
    
    def getDomain(self, url):
        return urlparse(url).netloc
    
    def getPath(self, url):
        return urlparse(url).path
    
    def havingIP(self, url):
        match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                          '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                          '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)     # IPv6
        if match:
            return 1  # phishing
        else:
            return 0  # legitimate
    
    def long_url(self, url):
        if len(url) < 54:
            return 0  # legitimate
        elif len(url) >= 54 and len(url) <= 75:
            return 2  # suspicious
        else:
            return 1  # phishing
    
    def have_at_symbol(self, url):
        if "@" in url:
            return 1  # phishing
        else:
            return 0  # legitimate
    
    def redirection(self, url):
        if "//" in urlparse(url).path:
            return 1  # phishing
        else:
            return 0  # legitimate
        
    def prefix_suffix_separation(self, url):
        if "-" in urlparse(url).netloc:
            return 1  # phishing
        else:
            return 0  # legitimate
        
    def sub_domains(self, url):
        if url.count(".") < 3:
            return 0  # legitimate
        elif url.count(".") == 3:
            return 2  # suspicious
        else:
            return 1  # phishing
        
    def shortening_service(self, url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
        if match:
            return 1  # phishing
        else:
            return 0  # legitimate
    
    def google_index(self, url):
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
        headers = { 'User-Agent' : user_agent}
        query = {'q': 'info:' + url}
        google = "https://www.google.com/search?" + urllib.parse.urlencode(query)
        try:
            data = requests.get(google, headers=headers)
            data.encoding = 'ISO-8859-1'
            soup = BeautifulSoup(data.content, "html.parser")
            check = soup.find(id="rso").find("div").find("div").find("h3").find("a")
            if check.find("href" != None):
                return 0  # indexed
            else:
                return 1
        except AttributeError:
            return 1  # indexed

    def abnormal_url(self, url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1  # phishing
        else:
            hostname = domain_name.domain_name
            if hostname in url:
                return 0  # legitimate
            else:
                return 1  # phishing
    
    def web_traffic(self, url):
        try:
            rank = 10000000000000
        except TypeError:
            return 1
        except HTTPError:
            return 2
        rank = int(rank)
        if rank < 100000:
            return 0
        else:
            return 2
    
    def domain_registration_length(self, url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1  # phishing
        else:
            expiration_date = domain_name.expiration_date
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            if expiration_date is None:
                return 1
            elif type(expiration_date) is list or type(today) is list:
                return 2  # suspected website
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                    try:
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                    except:
                        return 2
                registration_length = abs((expiration_date - today).days)
                if registration_length / 365 <= 1:
                    return 1  # phishing
                else:
                    return 0  # legitimate
            
    def age_domain(self, url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1
        else:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                except:
                    return 2
            if ((expiration_date is None) or (creation_date is None)):
                return 1
            elif ((type(expiration_date) is list) or (type(creation_date) is list)):
                return 2
            else:
                ageofdomain = abs((expiration_date - creation_date).days)
                if ((ageofdomain / 30) < 6):
                    return 1
                else:
                    return 0
    
    def dns_record(self, url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1
        else:
            return 0
        
    def statistical_report(self, url):
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match = re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)  
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0
        
    def https_token(self, url):
        match = re.search('https://|http://', url)
        try:
            if match.start(0) == 0 and match.start(0) is not None:
                url = url[match.end(0):]
                match = re.search('http|https', url)
                if match:
                    return 1
                else:
                    return 0
        except:
            return 1
    def numbers_at_beginning(self, url):
        first_char = url[0] if url else ''
        if first_char.isdigit():
            return 1  # Numbers present at the beginning
        else:
            return 0  # Numbers not present at the beginning

    def getFeatures(self, url):
        try:
            features = {
                'Protocol': self.getProtocol(url),
                'Domain': self.getDomain(url),
                'Path': self.getPath(url),
                'Having_IP': self.havingIP(url),
                'URL_Length': self.long_url(url),
                'Having_@_symbol': self.have_at_symbol(url),
                'Redirection_//_symbol': self.redirection(url),
                'Prefix_suffix_separation': self.prefix_suffix_separation(url),
                'Sub_domains': self.sub_domains(url),
                'Shortening_service': self.shortening_service(url),
                'Google_index': self.google_index(url),
                'Abnormal_URL': self.abnormal_url(url),
                'Web_traffic': self.web_traffic(url),
                'Domain_registration_length': self.domain_registration_length(url),
                'Age_of_domain': self.age_domain(url),
                'DNS_record': self.dns_record(url),
                'Statistical_report': self.statistical_report(url),
                'HTTPS_token': self.https_token(url),
                'Numbers_at_beginning': self.numbers_at_beginning(url),
            }
            return features
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

if __name__ == "__main__":
    # Test the feature extraction methods using URLs from text files
    phishing_urls_file = {r"Phishing-URL-Detection-master (1)\Phishing-URL-Detection-master\raw_datasets\1000-phishing.txt"}
    legitimate_urls_file = {r"Phishing-URL-Detection-master (1)\Phishing-URL-Detection-master\raw_datasets\legitimate_urls.txt"}

    # Initialize FeatureExtraction object
    feature_extractor = FeatureExtraction()
    # Assuming legitimate_urls is already populated with legitimate URLs
    total_length = 0
    total_urls = len(legitimate_urls_file)

    for url in legitimate_urls_file:
        total_length += len(url)

    average_length = total_length / total_urls
    print("Average length of legitimate URLs:", average_length)
