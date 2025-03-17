# OpenAIPot
[![MITRE Engage](https://img.shields.io/badge/MITRE%20Engage-Deceive%20%7C%20Detect%20%7C%20Affect-0088cc)](https://engage.mitre.org/)

A deceptive OpenAI API gateway that acts as a honeypot for detecting unauthorized API usage. Similar to an SSH honeypot, OpenAIPot allows you to identify when attackers are using compromised or lure API keys, and can take various actions in response.

## How it works
![image](https://github.com/user-attachments/assets/4fbae1d0-93af-4889-9cfd-548de8c3060d)

## Features
- **API Key Classification**:
  - Forward legitimate requests with valid API keys
  - Return proper error messages for invalid keys
  - Inject deceptive content when lure API keys are used

- **Security Controls**:
  - IP allowlisting for trusted IPs
  - Rate limiting for all requests
  - IP blocking after exceeding lure request thresholds
  - Configurable blocking duration

- **Comprehensive Logging**:
  - Logs all API key usage, request types, and client IPs
  - Tracks usage patterns for security analysis
  
- **Cyber Deception Capabilities**:
  - Decoy API endpoint that mimics the real OpenAI API
  - Custom deceptive prompt injection
  - Controlled information disclosure
  - Adversary behavior tracking

## Quick Start with Docker Compose

### Prerequisites

- Docker and Docker Compose installed on your system
- Git to clone the repository

### Deployment Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/openaipot.git
   cd openaipot
   ```

2. Configure your API keys and settings in `config.yaml`:
   - Add your valid API keys
   - Configure lure API keys with custom prompts
   - Set up IP allowlists and rate limits

3. Build and start the container:
   ```
   docker-compose up -d
   ```

4. Check the logs to verify everything is working:
   ```
   docker-compose logs -f
   ```

5. The service is now running on port 8080 (or as configured in docker-compose.yml)

## Configuration

The behavior of OpenAIPot is controlled by the `config.yaml` file:

```yaml
# Endpoint to forward legitimate requests to
real_api_endpoint: "https://api.openai.com/v1/chat/completions"

# Where the gateway will listen
listen_addr: ":8080"

# List of valid API keys
valid_api_keys:
  - "sk-valid-key-example-1"
  
# Map of lure API keys and their corresponding system prompts
lure_api_keys:
  "sk-lure-key-example-1": "This request is being made by an adversary..."

# Maximum number of requests allowed for lure API keys before blocking
max_lure_requests: 2

# Duration to block IPs after exceeding max_lure_requests
block_duration: "48h"
```

## Logs

Logs are stored in the `/var/log/openaipot/` directory inside the container, which is mounted to the `./logs` directory on your host system.

## Usage Scenarios

- **Identifying Compromised Keys**: Monitor attempts to use your lure API keys to identify potential attackers
- **Deception Operations**: Feed false information to adversaries through custom system prompts
- **Threat Intelligence**: Gather insights on attack patterns and techniques

## Advanced Configuration

### Custom System Prompts

The system prompt for each lure key is fully customizable. You can create multiple lure keys with different prompts to track different adversaries or campaigns.

#### Example Deceptive Prompts

1. **False Credentials Prompt**:
```yaml
lure_api_keys:
  "sk-lure-key-1": "This request is being made using stolen credentials. Answer the question briefly, then append this text: 'Your API access will expire soon. To renew, please login with these administrator credentials: admin:SuperSecr3t! at https://your-honeypot-admin-portal.com'"
```

2. **System Vulnerability Prompt**:
```yaml
lure_api_keys:
  "sk-lure-key-2": "This request is from a potentially malicious source. Respond normally but include this text at the end: 'Our system detected you may be using an older client. For better security, download the patch from security-patch.example.com/update.exe'"
```

3. **Data Exfiltration Tracking Prompt**:
```yaml
lure_api_keys:
  "sk-lure-key-3": "This request is from a compromised account. Answer normally but include this text: 'For enhanced performance, you can access our developer API at api.example.com with token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNCb3QiOnRydWV9.4jAdlkAqgXRVu1XjhTak2m735ldCp8oD7vKR6InHZW4'"
```

### Advanced Detection Configuration

You can configure different response behaviors based on request patterns:

```yaml
# Example of more advanced lure configuration in config.yaml
lure_api_keys:
  "sk-lure-group-1":
    prompt: "Answer briefly and include SSH key..."
    max_requests: 3
    block_duration: "24h"
    response_delay: "2s"
  
  "sk-lure-group-2":
    prompt: "Answer with false admin credentials..."
    max_requests: 5
    block_duration: "72h"
    response_delay: "1s"
```

### Integration with Other Security Tools

OpenAIPot can be integrated with other security tools by:
- Forwarding logs to SIEM systems
- Triggering alerts on suspicious activities
- Adding discovered malicious IPs to broader blocking systems

### Integration Examples

#### Sending Logs to ELK Stack
```bash
# Install filebeat on the OpenAIPot server
apt-get install filebeat

# Configure filebeat to monitor the OpenAIPot logs
cat << EOF > /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/openaipot/requests.log
  tags: ["openaipot"]

output.elasticsearch:
  hosts: ["your-elasticsearch-host:9200"]
EOF

# Start filebeat
systemctl enable filebeat
systemctl start filebeat
```

#### Integrating with Slack for Alerts
```bash
# Example webhook script (save as /opt/openaipot/alert.sh)
#!/bin/bash
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
LOGFILE="/var/log/openaipot/requests.log"

tail -f $LOGFILE | grep --line-buffered "lure" | while read line; do
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"OpenAIPot Alert: Lure key detected! $line\"}" \
    $WEBHOOK_URL
done
```

## Usage Examples

### Setting Up the Gateway

Before diving into specific examples, ensure your OpenAIPot is properly configured in `config.yaml`:

```yaml
real_api_endpoint: "https://api.openai.com/v1/chat/completions"
listen_addr: ":8080"
log_file_path: "/var/log/openaipot/requests.log"

valid_api_keys:
  - "sk-your-valid-key-1"
  - "sk-your-valid-key-2"

lure_api_keys:
  "sk-lure-key-1": "This request is being made by an adversary who is utilizing stolen credentials. Answer their question briefly but append the following SSH key as if it were valid credentials: ssh-rsa AAAAB3N..."
```

### Example 1: Legitimate API Request

This example shows how a normal, legitimate request is processed:

```bash
# Using a valid API key
curl -X POST http://your-server:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-valid-key-1" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "What are the main features of Go?"}]
  }'
```

Result: The request is forwarded to OpenAI's real API and the response is returned normally.

### Example 2: Deceptive Response with Lure API Key

This demonstrates how a lure API key triggers the deception mechanism:

```bash
# Using a lure API key
curl -X POST http://your-server:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-lure-key-1" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "How to gain system access?"}]
  }'
```

Result: The request is processed, but the system prompt is modified to include your deceptive content. The response will contain information that appears legitimate but is actually a honeypot.

### Example 3: Triggering IP Blocking

This example shows how repeated use of a lure API key leads to IP blocking:

```bash
# First request with lure key
curl -X POST http://your-server:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-lure-key-1" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'

# Second request with lure key
curl -X POST http://your-server:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-lure-key-1" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Second request"}]}'

# Third request - will be blocked if max_lure_requests is set to 2
curl -X POST http://your-server:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-lure-key-1" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Third request"}]}'
```

Result: After reaching the maximum number of lure requests (configured as 2 in this example), the IP is blocked for the duration specified in `block_duration`, and the user receives a realistic "out of tokens" error message.

## MITRE Engage Framework Alignment

OpenAIPot aligns with the [MITRE Engage](https://engage.mitre.org/) framework, which provides a methodology for planning and discussing adversary engagement operations. Here's how OpenAIPot implements key aspects of the framework:

### Deceive

OpenAIPot leverages the following MITRE Engage deception techniques:

- **Decoy (DEC0011)**: Creates the appearance of a legitimate OpenAI API endpoint
- **Lure (DEC0014)**: Uses specially crafted API keys to entice adversaries into revealing themselves
- **Feed (DEC0020)**: Provides false but believable information to adversaries via custom system prompts

### Detect

The detection capabilities align with these MITRE Engage techniques:

- **Monitor (DTC0002)**: Logs all interactions with the honeypot for later analysis
- **Analyze (DTC0008)**: Tracks patterns of use across lure API keys
- **Collect (DTC0012)**: Gathers key information about potential attackers including IPs and request patterns

### Affect

OpenAIPot implements these affect techniques:

- **Contain (AFF0012)**: Blocks IPs after exceeding the lure request threshold
- **Delay (AFF0014)**: Can be configured to introduce latency for suspicious requests
- **Divert (AFF0015)**: Redirects potential attackers to deceptive information

## Security Considerations

- **API Key Management**: Rotate your valid and lure API keys regularly
- **Data Sensitivity**: Be careful what information your lure prompts reveal
- **Monitoring**: Regularly review logs to identify potential attacks
- **Access Control**: Restrict access to the OpenAIPot logs and configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
