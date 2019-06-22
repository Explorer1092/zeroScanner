/*
host
*/
package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/lib/dnscache"
)

var (
	resolver             *dnscache.Resolver
	usernames, passwords []string
)

func init() {
	var err error
	usernames, err = util.ReadLines("ssh_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("ssh_password")
	if err != nil {
		panic(err)
	}
}

func InitDnsCache(dnsResolver *dnscache.Resolver) {
	resolver = dnsResolver
}

func Verify(params engine.Params) (result engine.Result) {
	host := params.ParsedTarget.Hostname()
	if params.Hosts != "" {
		host = params.Hosts
	}
	var err error
	host, err = resolver.FetchOneString(host)
	if err != nil {
		return
	}
	port := params.ParsedTarget.Port()
	if port == "" {
		port = "22"
	}

	params.ParsedTarget.Host = host + ":" + port

	config := new(ssh.ClientConfig)
	config.SetDefaults()
	config.Timeout = time.Second * 5
	config.Ciphers = append(config.Ciphers, "aes256-cbc", "aes128-cbc", "3des-cbc", "aes256-cbc", "des-cbc")
	config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	for _, password := range passwords {
		for _, username := range usernames {
			config.User = username
			config.Auth = []ssh.AuthMethod{ssh.Password(password)}

			client, err := sshDial("tcp", params.ParsedTarget.Host, config)
			if err != nil {
				if strings.Contains(err.Error(), "unable to authenticate") {
					if util.IsPublic(host) {
						result.Vul = true
						result.VulUrl = params.ParsedTarget.Host
						result.VulInfo = "SSH对外"
						result.Level = engine.VulMiddleLevel
					}
				} else if sshClosed(err.Error()) {
					result.Stop = 24
					return
				} else {
					result.Err = err.Error()
					return
				}
			} else {
				client.Close()
				result.Vul = true
				result.VulUrl = params.ParsedTarget.Host
				result.Extend = fmt.Sprintf("[%s][%s]", username, password)
				result.VulInfo = "SSH弱口令"
				result.Level = engine.VulHighLevel
				return
			}
		}
	}
	return
}

func sshDial(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}
	if config.Timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(config.Timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshClosed(text string) bool {
	return strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "connection timed out") ||
		strings.Contains(text, "closed by the remote host") ||
		strings.Contains(text, "handshake failed") ||
		strings.Contains(text, "refused it") ||
		strings.Contains(text, "no route to host") ||
		strings.Contains(text, "connection refused") ||
		strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "network is unreachable")
}

func main() {
	InitDnsCache(dnscache.New(time.Hour * 36))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://localhost/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
