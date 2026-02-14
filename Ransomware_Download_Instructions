To download Ransomwware files:
use :

Obtain an Auth-Key (Required)
In order to interact with the MalwareBazaar API, you need to obtain an Auth-Key first. If you don't have one you can get one for free here:

Authentication Portal : https://auth.abuse.ch

wget \
  --header="Auth-Key: YOUR-AUTH-KEY-HERE" \
  --header="User-Agent: malware-research-lab/1.0" \
  --post-data="query=get_file&sha256_hash=<sha256_hash_of_ransomware>" \
  https://mb-api.abuse.ch/api/v1/ \
  -O <file_name>.zip

