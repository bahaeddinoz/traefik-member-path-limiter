package main

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
)

type Config struct {
    OutputHeader string `json:"outputHeader,omitempty"`
}

func CreateConfig() *Config {
    return &Config{
        OutputHeader: "X-Rate-Limit-Key",
    }
}

type MemberPathLimiter struct {
    next         http.Handler
    name         string
    outputHeader string
}

type JWTClaims struct {
    Member string `json:"member"`
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    return &MemberPathLimiter{
        next:         next,
        name:         name,
        outputHeader: config.OutputHeader,
    }, nil
}

func (m *MemberPathLimiter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    memberID := m.extractMemberFromJWT(req)
    endpoint := m.extractEndpointFromPath(req.URL.Path)
    
    if memberID != "" && endpoint != "" {
        rateLimitKey := fmt.Sprintf("%s:%s", memberID, endpoint)
        req.Header.Set(m.outputHeader, rateLimitKey)
    }
    
    m.next.ServeHTTP(rw, req)
}

func (m *MemberPathLimiter) extractMemberFromJWT(req *http.Request) string {
    authHeader := req.Header.Get("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        return ""
    }
    
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return ""
    }
    
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return ""
    }
    
    var claims JWTClaims
    if err := json.Unmarshal(payload, &claims); err != nil {
        return ""
    }
    
    return claims.Member
}

func (m *MemberPathLimiter) extractEndpointFromPath(path string) string {
    cleanPath := strings.TrimPrefix(path, "/api/v1")
    pathSegments := strings.Split(strings.Trim(cleanPath, "/"), "/")
    
    if len(pathSegments) > 0 && pathSegments[0] != "" {
        return pathSegments[0]
    }
    
    return "unknown"
}