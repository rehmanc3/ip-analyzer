# IP Block Analysis Utility

A Python tool for classifying IP addresses and ranges using the [IPInfo
API](https://ipinfo.io).\
Identifies datacenter, residential, VPN, proxy, mobile, and business IPs
with JSON reporting and optional Terraform infrastructure provisioning.

------------------------------------------------------------------------

## Features

-   Classify IPs as datacenter, residential, VPN, proxy, mobile, or
    business
-   Input support: single IP, CIDR range, or bulk file
-   SQLite caching to minimize API calls
-   JSON reporting with summaries and statistics
-   Terraform config generation (AWS/GCP)
-   Threat scoring (0--100)
-   Progress indicators and multi-threaded analysis

------------------------------------------------------------------------

## Installation

### Requirements

-   Python 3.7+
-   IPInfo API token (free tier available)

### Setup

``` bash
git clone https://github.com/your-repo/ip-analysis-utility.git
cd ip-analysis-utility
pip install -r requirements.txt

cp config.json.example config.json
# Edit config.json with your IPInfo token
```

**Dependencies** (`requirements.txt`):

    requests>=2.28.0

------------------------------------------------------------------------

## Configuration

Edit `config.json`:

``` json
{
  "ipinfo_token": "your-ipinfo-token-here",
  "database_path": "ip_analysis.db",
  "output_directory": "reports",
  "rate_limit_delay": 0.1,
  "max_workers": 3
}
```

| Option           | Description                       | Default        |
|------------------|-----------------------------------|----------------|
| ipinfo_token     | Your IPInfo API token             | Required       |
| database_path    | SQLite cache database             | ip_analysis.db |
| output_directory | Directory for JSON reports        | reports        |
| rate_limit_delay | Delay between API calls (seconds) | 0.1            |
| max_workers      | Max concurrent threads            | 3              |


Get a token at [ipinfo.io](https://ipinfo.io).

------------------------------------------------------------------------

## Usage

### Basic Commands

``` bash
# Single IP
python ip_analyzer.py --ip 8.8.8.8

# CIDR range
python ip_analyzer.py --range 192.168.1.0/24

# From file
python ip_analyzer.py --file ip_list.txt

# Custom report
python ip_analyzer.py --range 10.0.0.0/28 --output my_report.json

# Generate Terraform config
python ip_analyzer.py --terraform

# Verbose logging
python ip_analyzer.py --ip 1.1.1.1 --verbose
```

### Input File Example (`ip_list.txt`)

    8.8.8.8
    1.1.1.1
    192.168.1.0/24
    # Comment lines allowed
    10.0.0.0/28

------------------------------------------------------------------------

## Output

### Single IP Example

    Organization: Google LLC
    ASN: AS15169
    Country: US
    Classification: datacenter
    Threat Score: 30/100

### Range Summary Example

    Total IPs: 14
    Datacenter: 8 (57.1%)
    Residential: 4 (28.6%)
    Business: 2 (14.3%)
    Threat Levels: low=10, medium=4, high=0
    Top Countries: US=12, CA=2

------------------------------------------------------------------------

## Classification Types

-   **datacenter** -- Cloud/hosting providers (AWS, GCP, DigitalOcean)\
-   **residential** -- Home ISPs (Comcast, Verizon, AT&T)\
-   **mobile** -- Cellular carriers (T-Mobile, Vodafone)\
-   **vpn** -- VPN services (NordVPN, ExpressVPN)\
-   **proxy** -- Proxy/anonymizer services (Tor, public proxies)\
-   **business** -- Enterprise or corporate networks

------------------------------------------------------------------------

## Threat Scoring

-   Proxy: 70 pts\
-   VPN: 50 pts\
-   Datacenter: 30 pts\
-   Residential/Mobile/Business: 0 pts

**Levels**:\
- Low (0--29)\
- Medium (30--59)\
- High (60--100)

------------------------------------------------------------------------

## JSON Report Example

``` json
{
  "metadata": {
    "generated_at": "2025-08-20T12:34:56.789",
    "tool_version": "1.0",
    "total_ips_analyzed": 50
  },
  "summary": {
    "classification_breakdown": {"datacenter": 20, "residential": 25, "business": 5},
    "threat_level_distribution": {"low": 30, "medium": 20, "high": 0},
    "top_countries": {"US": 35, "CA": 10, "UK": 5}
  },
  "results": [
    {
      "ip": "8.8.8.8",
      "asn": "AS15169",
      "organization": "Google LLC",
      "classification": "datacenter",
      "threat_score": 30
    }
  ]
}
```

------------------------------------------------------------------------

## Terraform Integration

``` bash
# Generate config
python ip_analyzer.py --terraform

# Deploy
cd terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

**Supports:**\
- AWS: VPC, EC2, security groups\
- GCP: VPC, Compute Engine, firewall rules

------------------------------------------------------------------------

## Performance & Limits

-   Default delay: 0.1s between API calls\
-   Large ranges capped at 50 IPs\
-   Results cached for 24h\
-   IPInfo free tier: 50,000 requests/month

------------------------------------------------------------------------

## Troubleshooting

-   **Missing token**: Check `config.json`\
-   **Rate limit errors**: Increase `rate_limit_delay` or lower
    `max_workers`\
-   **Timeouts on large ranges**: Use smaller CIDRs\
-   **Debugging**: Add `--verbose`

------------------------------------------------------------------------

## Project Structure

    ip-analysis-utility/
    ├── ip_analyzer.py
    ├── terraform_infrastructure.py
    ├── config.json
    ├── requirements.txt
    ├── README.md
    ├── reports/
    ├── terraform/
    └── ip_analysis.db (auto)

------------------------------------------------------------------------

## License

MIT License -- see `LICENSE`.


