package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// Config holds the gateway configuration
type Config struct {
	RealAPIEndpoint  string            `yaml:"real_api_endpoint"`
	ListenAddr       string            `yaml:"listen_addr"`
	LogFilePath      string            `yaml:"log_file_path"`
	ValidAPIKeys     []string          `yaml:"valid_api_keys"`
	LureAPIKeys      map[string]string `yaml:"lure_api_keys"` // map[apiKey]systemPrompt
	MaxLureRequests  int               `yaml:"max_lure_requests"`
	BlockDuration    time.Duration     `yaml:"block_duration"`
	Allowlist        []*net.IPNet      `yaml:"allowlist"`
	RateLimits       RateLimitConfig   `yaml:"rate_limits"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxRequests int           `yaml:"max_requests"`
	Duration    time.Duration `yaml:"duration"`
}

// RequestCounter tracks API requests
type RequestCounter struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

var (
	config          Config
	lureRequestsMap = make(map[string]int)          // map[ip]requestCount
	blockedIPs      = make(map[string]time.Time)    // map[ip]blockExpiryTime
	rateLimitMap    = make(map[string]RequestCounter)
	mutex           = &sync.Mutex{}
)

// OpenAIRequest represents a request to the OpenAI API
type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// Message represents a message in an OpenAI request
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIErrorResponse represents an OpenAI API error response
type OpenAIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func main() {
	configFilePath := "config.yaml" // Path to your config file

	err := loadConfig(configFilePath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	http.HandleFunc("/v1/chat/completions", handleChatCompletions)

	log.Printf("Starting LLM API Gateway on %s", config.ListenAddr)
	log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
}

func loadConfig(filePath string) error {
	// Load the config file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var rawConfig struct {
		RealAPIEndpoint  string            `yaml:"real_api_endpoint"`
		ListenAddr       string            `yaml:"listen_addr"`
		LogFilePath      string            `yaml:"log_file_path"`
		ValidAPIKeys     []string          `yaml:"valid_api_keys"`
		LureAPIKeys      map[string]string `yaml:"lure_api_keys"`
		MaxLureRequests  int               `yaml:"max_lure_requests"`
		BlockDuration    string            `yaml:"block_duration"`
		Allowlist        []string          `yaml:"allowlist"`
		RateLimits       struct {
			Enabled     bool   `yaml:"enabled"`
			MaxRequests int    `yaml:"max_requests"`
			Duration    string `yaml:"duration"`
		} `yaml:"rate_limits"`
	}

	err = yaml.Unmarshal(data, &rawConfig)
	if err != nil {
		return err
	}

	// Convert string durations to time.Duration
	blockDuration, err := time.ParseDuration(rawConfig.BlockDuration)
	if err != nil {
		return fmt.Errorf("invalid block duration: %v", err)
	}

	rateLimitDuration, err := time.ParseDuration(rawConfig.RateLimits.Duration)
	if err != nil {
		return fmt.Errorf("invalid rate limit duration: %v", err)
	}

	config.RealAPIEndpoint = rawConfig.RealAPIEndpoint
	config.ListenAddr = rawConfig.ListenAddr
	config.LogFilePath = rawConfig.LogFilePath
	config.ValidAPIKeys = rawConfig.ValidAPIKeys
	config.LureAPIKeys = rawConfig.LureAPIKeys
	config.MaxLureRequests = rawConfig.MaxLureRequests
	config.BlockDuration = blockDuration
	config.RateLimits.Enabled = rawConfig.RateLimits.Enabled
	config.RateLimits.MaxRequests = rawConfig.RateLimits.MaxRequests
	config.RateLimits.Duration = rateLimitDuration

	// Parse allowlist
	for _, cidr := range rawConfig.Allowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				log.Printf("Invalid IP range: %s", cidr)
			} else {
				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
			}
		}
		config.Allowlist = append(config.Allowlist, ipNet)
	}

	return nil
}

func isAllowlisted(ip string) bool {
	for _, ipNet := range config.Allowlist {
		if ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func isBlocked(ip string) bool {
	mutex.Lock()
	defer mutex.Unlock()

	if blockTime, ok := blockedIPs[ip]; ok {
		if time.Now().Before(blockTime) {
			return true
		}
		// Block expired, remove from map
		delete(blockedIPs, ip)
	}
	return false
}

func logRequest(apiKey, ip, requestType string, req *OpenAIRequest) {
	f, err := os.OpenFile(config.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	requestContent := ""
	if req != nil && len(req.Messages) > 0 {
		requestContent = req.Messages[len(req.Messages)-1].Content
	}

	logEntry := fmt.Sprintf(
		"%s - Type: %s, IP: %s, API Key: %s, Content: %s\n",
		time.Now().Format(time.RFC3339),
		requestType,
		ip,
		apiKey,
		requestContent,
	)

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
}

// Check if API key is in lure keys map
func isLureAPIKey(apiKey string) (string, bool) {
    // First print the key to debug
    log.Printf("Checking if key is a lure key: %s", apiKey)
    
    // Debug: print all lure keys for comparison
    for lureKey := range config.LureAPIKeys {
        log.Printf("Available lure key: %s", lureKey)
    }
    
    // Check if this key exists in our lure keys map
    if systemPrompt, exists := config.LureAPIKeys[apiKey]; exists {
        return systemPrompt, true
    }
    return "", false
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
    // Extract client IP
    ip, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        ip = r.RemoteAddr
    }

    // Check if IP is allowlisted
    if isAllowlisted(ip) {
        log.Printf("IP %s is allowlisted, forwarding request normally", ip)
        forwardRequest(w, r, false, "")
        return
    }

    // Check if IP is blocked
    if isBlocked(ip) {
        log.Printf("IP %s is blocked, returning error", ip)
        returnError(w, "Rate limit exceeded. Please try again later.", "rate_limit_exceeded", 429)
        return
    }

    // Extract API key from Authorization header
    apiKey := r.Header.Get("Authorization")
    if apiKey == "" {
        returnError(w, "Missing API key", "invalid_request_error", 401)
        return
    }
    
    // Remove "Bearer " prefix if present
    if len(apiKey) > 7 && apiKey[:7] == "Bearer " {
        apiKey = apiKey[7:]
    }

    // Debug information - print the API key
    log.Printf("Processing request with API key: %s", apiKey)

    // Read the request body to log and possibly modify it
    var reqBody []byte
    if r.Body != nil {
        reqBody, err = ioutil.ReadAll(r.Body)
        if err != nil {
            log.Printf("Error reading request body: %v", err)
            returnError(w, "Invalid request body", "invalid_request_error", 400)
            return
        }
        // Create a new io.ReadCloser from the bytes so it can be read again
        r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
    }

    // Parse the request for logging purposes
    var openAIReq OpenAIRequest
    if len(reqBody) > 0 {
        if err := json.Unmarshal(reqBody, &openAIReq); err != nil {
            log.Printf("Error parsing request body: %v", err)
            // Continue anyway, as we may just want to log the raw request
        }
    }

    // Check if it's a lure API key FIRST, before checking valid keys
    if lurePrompt, isLure := isLureAPIKey(apiKey); isLure {
        mutex.Lock()
        lureRequestsMap[ip]++
        requestCount := lureRequestsMap[ip]
        mutex.Unlock()

        log.Printf("Lure API key detected from IP %s (request %d/%d)", ip, requestCount, config.MaxLureRequests)
        logRequest(apiKey, ip, "lure", &openAIReq)

        if requestCount >= config.MaxLureRequests {
            // Block the IP
            mutex.Lock()
            blockedIPs[ip] = time.Now().Add(config.BlockDuration)
            mutex.Unlock()

            log.Printf("IP %s has reached max lure requests, blocking for %v", ip, config.BlockDuration)
            returnError(w, "You've exhausted your API token credits. Please purchase additional credits to continue using the API.", "insufficient_quota", 429)
            return
        }

        // Modify the system prompt and forward
        forwardRequest(w, r, true, lurePrompt)
        return
    }

    // Check if API key is valid (only if it's not a lure key)
    if isValidAPIKey(apiKey) {
        log.Printf("Valid API key from IP %s, forwarding request", ip)
        logRequest(apiKey, ip, "valid", &openAIReq)
        forwardRequest(w, r, false, "")
        return
    }

    // Invalid API key (not valid and not a lure key)
    log.Printf("Invalid API key from IP %s", ip)
    logRequest(apiKey, ip, "invalid", &openAIReq)
    returnError(w, "Invalid API key provided", "invalid_request_error", 401)
}

func isValidAPIKey(apiKey string) bool {
	for _, key := range config.ValidAPIKeys {
		if key == apiKey {
			return true
		}
	}
	return false
}

func forwardRequest(w http.ResponseWriter, r *http.Request, modifyPrompt bool, lurePrompt string) {
    // Create a new request to forward to the real API
    clientReq, err := http.NewRequest(r.Method, config.RealAPIEndpoint, r.Body)
    if err != nil {
        log.Printf("Error creating forward request: %v", err)
        returnError(w, "Internal server error", "server_error", 500)
        return
    }

    // Copy request headers
    for name, values := range r.Header {
        for _, value := range values {
            clientReq.Header.Add(name, value)
        }
    }

    // If this is a lure request, we need to use a valid API key
    if modifyPrompt && lurePrompt != "" {
        // Use the first valid API key instead of the lure key
        if len(config.ValidAPIKeys) > 0 {
            log.Printf("Replacing lure API key with valid key for OpenAI request")
            // Replace the Authorization header
            clientReq.Header.Set("Authorization", "Bearer " + config.ValidAPIKeys[0])
        } else {
            log.Printf("ERROR: No valid API keys configured, cannot forward lure request")
            returnError(w, "Internal server error", "server_error", 500)
            return
        }

        // Read the original request body
        var reqBody []byte
        if r.Body != nil {
            reqBody, err = ioutil.ReadAll(r.Body)
            if err != nil {
                log.Printf("Error reading request body: %v", err)
                returnError(w, "Internal server error", "server_error", 500)
                return
            }
        }

        // Parse the request
        var openAIReq OpenAIRequest
        if err := json.Unmarshal(reqBody, &openAIReq); err != nil {
            log.Printf("Error parsing request body: %v", err)
            returnError(w, "Internal server error", "server_error", 500)
            return
        }

        // Add or modify the system message
        hasSystemMsg := false
        for i, msg := range openAIReq.Messages {
            if msg.Role == "system" {
                openAIReq.Messages[i].Content = lurePrompt
                hasSystemMsg = true
                break
            }
        }

        if !hasSystemMsg {
            // Prepend a system message
            openAIReq.Messages = append([]Message{{Role: "system", Content: lurePrompt}}, openAIReq.Messages...)
        }

        // Re-encode the modified request
        modifiedBody, err := json.Marshal(openAIReq)
        if err != nil {
            log.Printf("Error encoding modified request: %v", err)
            returnError(w, "Internal server error", "server_error", 500)
            return
        }

        // Use the modified body in the forward request
        clientReq.Body = ioutil.NopCloser(bytes.NewBuffer(modifiedBody))
        clientReq.ContentLength = int64(len(modifiedBody))
        clientReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(modifiedBody)))
    }

    // Send the request to the real API
    client := &http.Client{}
    resp, err := client.Do(clientReq)
    if err != nil {
        log.Printf("Error forwarding request: %v", err)
        returnError(w, "Internal server error", "server_error", 500)
        return
    }
    defer resp.Body.Close()

    // Copy response headers
    for name, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(name, value)
        }
    }
    w.WriteHeader(resp.StatusCode)

    // Copy response body
    io.Copy(w, resp.Body)
}

func returnError(w http.ResponseWriter, message, errorType string, statusCode int) {
	resp := OpenAIErrorResponse{}
	resp.Error.Message = message
	resp.Error.Type = errorType
	resp.Error.Code = errorType

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}