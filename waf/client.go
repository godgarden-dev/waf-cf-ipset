package waf

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional"
)

const (
	CiderMaskSupportMin int = 16
	CiderMaskSupportMax int = 32
)

type Client struct {
	ipSetID string
	service *wafregional.WAFRegional
}

// NewClient はWAF Regionalクライアントを返します
func NewClient(id string) *Client {
	svc := wafregional.New(session.New(&aws.Config{
		Region: aws.String("ap-northeast-1"),
	}))

	return &Client{ipSetID: id, service: svc}
}

func (c *Client) getChangeToken() (string, error) {
	input := &waf.GetChangeTokenInput{}
	token, err := c.service.GetChangeToken(input)
	if err != nil {
		return "", err
	}

	return *token.ChangeToken, nil
}

// GetIPSet はIP match conditionsのIPリストを返します
func (c *Client) GetIPSet() ([]string, error) {
	input := &waf.GetIPSetInput{
		IPSetId: aws.String(c.ipSetID),
	}

	ipSets, err := c.service.GetIPSet(input)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ipSet := range ipSets.IPSet.IPSetDescriptors {
		ips = append(ips, *ipSet.Value)
	}

	fmt.Println(ips)
	return ips, nil
}

func deleteIPList(s string, useIps []string) []*waf.IPSetUpdate {
	ipSet := []*waf.IPSetUpdate{}
	for _, ip := range useIps {
		if strings.Contains(s, ip) {
			continue
		}

		ipSet = append(ipSet, &waf.IPSetUpdate{
			Action: aws.String(waf.ChangeActionDelete),
			IPSetDescriptor: &waf.IPSetDescriptor{
				Type:  aws.String(wafregional.IPSetDescriptorTypeIpv4),
				Value: aws.String(ip),
			},
		})
	}
	return ipSet
}

// DeleteIPSet はIP match conditionsから未使用なIPを削除します
func (c *Client) DeleteIPSet(s string, ipSets[]string) error {

	updates := deleteIPList(s, ipSets)

	if len(updates) == 0 {
		log.Println("delete ip set field size of 0")
		return nil
	}

	token, err := c.getChangeToken()
	if err != nil {
		return err
	}

	input := &waf.UpdateIPSetInput{
		ChangeToken: aws.String(token),
		IPSetId:     aws.String(c.ipSetID),
		Updates:     updates,
	}

	_, err = c.service.UpdateIPSet(input)
	if err := checkErr(err); err != nil {
		return err
	}

	return nil
}

// InsertIPSet はIP match conditionsに追加します
func (c *Client) InsertIPSet(ips []string) error {

	if len(ips) == 0 {
		return errors.New("insert ip set field size of 0")
	}

	updates := []*waf.IPSetUpdate{}

	token, err := c.getChangeToken()
	if err != nil {
		return err
	}

	for _, ip := range ips {
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			return err
		}

		// WAFが /16 〜 /32のアドレス範囲までしかサポートしていない
		// https://dev.classmethod.jp/cloud/aws/waf-new-features-queryargs-cidr/
		mask, _ := ipNet.Mask.Size()
		if mask < CiderMaskSupportMin || mask > CiderMaskSupportMax {
			continue
		}

		updates = append(updates, &waf.IPSetUpdate{
			Action: aws.String(waf.ChangeActionInsert),
			IPSetDescriptor: &waf.IPSetDescriptor{
				Type:  aws.String(wafregional.IPSetDescriptorTypeIpv4),
				Value: aws.String(ip),
			},
		})
	}

	input := &waf.UpdateIPSetInput{
		ChangeToken: aws.String(token),
		IPSetId:     aws.String(c.ipSetID),
		Updates:     updates,
	}

	_, err = c.service.UpdateIPSet(input)
	if err := checkErr(err); err != nil {
		return err
	}

	return nil
}

func checkErr(err error) error {
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case wafregional.ErrCodeWAFStaleDataException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFStaleDataException)
			case wafregional.ErrCodeWAFInternalErrorException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFInternalErrorException)
			case wafregional.ErrCodeWAFInvalidAccountException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFInvalidAccountException)
			case wafregional.ErrCodeWAFInvalidOperationException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFInvalidOperationException)
			case wafregional.ErrCodeWAFInvalidParameterException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFInvalidParameterException)
			case wafregional.ErrCodeWAFNonexistentContainerException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFNonexistentContainerException)
			case wafregional.ErrCodeWAFNonexistentItemException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFNonexistentItemException)
			case wafregional.ErrCodeWAFReferencedItemException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFReferencedItemException)
			case wafregional.ErrCodeWAFLimitsExceededException:
				return  errors.Wrap(err, wafregional.ErrCodeWAFLimitsExceededException)
			default:
				return err
			}
		}
		return err
	}
	return nil
}
