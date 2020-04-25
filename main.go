package main

import (
	"encoding/json"
	"log"
	"os"
	"net/http"
	"strings"

	"github.com/kancers/waf-cf-ipset/waf"
)

const (
	TargetService string = "CLOUDFRONT"
	URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

type AWSIPRange struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix string `json:"ip_prefix"`
		Region   string `json:"region"`
		Service  string `json:"service"`
	} `json:"prefixes"`
}

func main() {

	log.Println("start!!!")

	id := os.Getenv("IPSETID")
	if id == "" {
		log.Fatal("missing env IPSETID")
	}

	req, _ := http.NewRequest("GET", URL, nil)

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	var ipRange AWSIPRange
	if err := decodeBody(resp, &ipRange); err != nil {
		log.Fatal(err)
	}

	cfIP := ipRange.filterIPAddressesFromService(TargetService)
	wafClient := waf.NewClient(id)

	// Adding IP match conditions
	if err := wafClient.InsertIPSet(cfIP); err != nil {
		log.Fatal(err)
	}

	var useIP []string
	useIP, err = wafClient.GetIPSet()
	if err != nil {
		log.Fatal(err)
	}

	// Removing unused IP match conditions
	if err := wafClient.DeleteIPSet(strings.Join(cfIP, "|"), useIP); err != nil {
		log.Fatal(err)
	}

	log.Println("done!!!")
}

func decodeBody(resp *http.Response, out interface{}) error {
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	return decoder.Decode(out)
}

func (a *AWSIPRange) filterIPAddressesFromService (service string) []string {
	var ips []string
	for _, prefix := range a.Prefixes {
		if prefix.Service == service {
			ips = append(ips, prefix.IPPrefix)
		}
	}
	return ips
}

