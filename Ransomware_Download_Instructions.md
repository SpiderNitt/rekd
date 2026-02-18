# Instructions to safely download Malware

<p> 
  <h3>Disclaimer: </h3>
  
  Dowload the malware samples with caution. Do not download it directly on your host machine use a sandbox to download and test the malware. 
</p>
<h2>Get Auth key</h2>
<p>
  <h3> In order to interact with the MalwareBazaar API, you need to obtain an Auth-Key first use the link to get an auth key <h3>
  <h3>Use: https://auth.abuse.ch/ </h3>
</p>

---
<p>
  <h3> Use the below link to get SHA256 Hash of the required Malware Sample </h3>
  <h3> Link: https://bazaar.abuse.ch/browse/ </h3>
</p>

---

<h2>Example Malware Samples </h2>
<p>
  🔹Revil - d6762eff16452434ac1acc127f082906cc1ae5b0ff026d0d4fe725711db47763
  
  🔹Babuk - bed5049fe66cfdbde47b6d4530a1512341752e6190e50ddf902121a9d9461f6b
  
  🔹Conti - ff48dd7bebddf4d5a36c8ef9f5b6057172ee738a19182a12c06bdc20129da0f2
  
</p>

---

<h2>Command to download malware samples</h2>

 ``` sh
wget --header="Auth-Key: YOUR-AUTH-KEY-HERE" --header="User-Agent: malware-research-lab/1.0" --post-data="query=get_file&sha256_hash=<sha256_hash_of_ransomware>" https://mb-api.abuse.ch/api/v1/ -O <file_name>.zip
```

<h3> The password to unzip the file is infected </h3>

