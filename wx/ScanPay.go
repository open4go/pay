package wx

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/open4go/r2id"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"
)

// 相关文档
// https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=5_4
// https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=9_10&index=1
// https://products.aspose.app/barcode/zh-hans/scanqr#/recognized

const (
	MicroPayApi = "https://api.mch.weixin.qq.com/pay/micropay"
)

const xmlPayRequestParamsTemplate = `
<xml>
	<appid><![CDATA[%s]]></appid>
	<auth_code><![CDATA[%s]]></auth_code>
	<body><![CDATA[%s]]></body>
	<mch_id><![CDATA[%s]]></mch_id>
	<nonce_str><![CDATA[%s]]></nonce_str>
	<out_trade_no><![CDATA[%s]]></out_trade_no>
	<spbill_create_ip><![CDATA[%s]]></spbill_create_ip>
	<total_fee><![CDATA[%d]]></total_fee>
	<device_info>%s</device_info>
	<sign_type>MD5</sign_type>
	<sign>%s</sign>
</xml>
`

// renderData 渲染支付参数
func renderData(appid, code, body, mch, nonce, trade, ip, sign, device string, fee int64) string {
	return fmt.Sprintf(
		xmlPayRequestParamsTemplate,
		appid,
		code,
		body,
		mch,
		nonce,
		trade,
		ip,
		fee,
		device,
		sign,
	)
}

// RequestParams 请求参数结构体
type RequestParams struct {
	AppID          string `xml:"appid,omitempty"`
	MchID          string `xml:"mch_id,omitempty"`
	DeviceInfo     string `xml:"device_info,omitempty"`
	NonceStr       string `xml:"nonce_str,omitempty"`
	Sign           string `xml:"sign,omitempty"`
	SignType       string `xml:"sign_type,omitempty"`
	Body           string `xml:"body,omitempty"`
	Detail         string `xml:"detail,omitempty"`
	Attach         string `xml:"attach,omitempty"`
	OutTradeNo     string `xml:"out_trade_no,omitempty"`
	TotalFee       int64  `xml:"total_fee,omitempty"`
	FeeType        string `xml:"fee_type,omitempty"`
	SpbillCreateIP string `xml:"spbill_create_ip,omitempty"`
	GoodsTag       string `xml:"goods_tag,omitempty"`
	LimitPay       string `xml:"limit_pay,omitempty"`
	TimeStart      string `xml:"time_start,omitempty"`
	TimeExpire     string `xml:"time_expire,omitempty"`
	Receipt        string `xml:"receipt,omitempty"`
	AuthCode       string `xml:"auth_code,omitempty"`
	ProfitSharing  string `xml:"profit_sharing,omitempty"`
	SceneInfo      string `xml:"scene_info,omitempty"`
}

// SignStruct 签名结构体
type SignStruct struct {
	AppID          string `xml:"appid,omitempty"`
	MchID          string `xml:"mch_id,omitempty"`
	DeviceInfo     string `xml:"device_info,omitempty"`
	NonceStr       string `xml:"nonce_str,omitempty"`
	Body           string `xml:"body,omitempty"`
	Detail         string `xml:"detail,omitempty"`
	Attach         string `xml:"attach,omitempty"`
	OutTradeNo     string `xml:"out_trade_no,omitempty"`
	TotalFee       int64  `xml:"total_fee,omitempty"`
	SpbillCreateIP string `xml:"spbill_create_ip,omitempty"`
	AuthCode       string `xml:"auth_code,omitempty"`
	SignType       string `xml:"sign_type,omitempty"`
}

type PayResult struct {
	XMLName       xml.Name `xml:"xml"`
	ReturnCode    string   `xml:"return_code"`
	ReturnMsg     string   `xml:"return_msg"`
	AppID         string   `xml:"appid"`
	MchID         string   `xml:"mch_id"`
	DeviceInfo    string   `xml:"device_info"`
	NonceStr      string   `xml:"nonce_str"`
	Sign          string   `xml:"sign"`
	ResultCode    string   `xml:"result_code"`
	OpenID        string   `xml:"openid"`
	IsSubscribe   string   `xml:"is_subscribe"`
	TradeType     string   `xml:"trade_type"`
	BankType      string   `xml:"bank_type"`
	TotalFee      int      `xml:"total_fee"`
	CouponFee     int      `xml:"coupon_fee"`
	FeeType       string   `xml:"fee_type"`
	TransactionID string   `xml:"transaction_id"`
	OutTradeNo    string   `xml:"out_trade_no"`
	Attach        string   `xml:"attach"`
	TimeEnd       string   `xml:"time_end"`
}

// GenerateSign 签名生成算法
func GenerateSign(signStruct SignStruct, apiKey string) string {
	var signSlice []string
	signSlice = append(signSlice, fmt.Sprintf("appid=%s", signStruct.AppID))
	signSlice = append(signSlice, fmt.Sprintf("body=%s", signStruct.Body))
	signSlice = append(signSlice, fmt.Sprintf("sign_type=%s", signStruct.SignType))
	signSlice = append(signSlice, fmt.Sprintf("device_info=%s", signStruct.DeviceInfo))
	signSlice = append(signSlice, fmt.Sprintf("mch_id=%s", signStruct.MchID))
	signSlice = append(signSlice, fmt.Sprintf("nonce_str=%s", signStruct.NonceStr))
	signSlice = append(signSlice, fmt.Sprintf("out_trade_no=%s", signStruct.OutTradeNo))
	signSlice = append(signSlice, fmt.Sprintf("spbill_create_ip=%s", signStruct.SpbillCreateIP))
	signSlice = append(signSlice, fmt.Sprintf("total_fee=%d", signStruct.TotalFee))
	signSlice = append(signSlice, fmt.Sprintf("auth_code=%s", signStruct.AuthCode))
	sort.Strings(signSlice)
	signStr := strings.Join(signSlice, "&") + "&key=" + apiKey

	// 默认签名类型为MD5
	h := md5.New()
	h.Write([]byte(signStr))
	sign := hex.EncodeToString(h.Sum(nil))
	return strings.ToUpper(sign)
}

type ScanPayClient struct {
	AppId      string
	MchID      string
	APIKeyV2   string
	DeviceInfo string
}

// buildRequestParams 构建请求参数
func (sp *ScanPayClient) buildRequestParams(body, code string, fee int64) RequestParams {
	return RequestParams{
		AppID:          sp.AppId,
		MchID:          sp.MchID,
		DeviceInfo:     sp.DeviceInfo,
		NonceStr:       r2id.GenerateRandomString(32),
		Body:           body,
		OutTradeNo:     r2id.GenerateOutTradeNo(),
		TotalFee:       fee,
		SpbillCreateIP: "8.8.8.8",
		SignType:       "MD5",
		// AuthCode 扫码枪读取的支付二维码
		AuthCode: code,
	}
}

// SendRequest 发送请求
func (sp *ScanPayClient) sendRequest(params RequestParams) (*PayResult, error) {
	// 生成签名
	signStruct := SignStruct{
		AppID:      params.AppID,
		MchID:      params.MchID,
		DeviceInfo: params.DeviceInfo,
		NonceStr:   params.NonceStr,
		Body:       params.Body,
		//Detail:         params.Detail,
		Attach:         params.Attach,
		OutTradeNo:     params.OutTradeNo,
		TotalFee:       params.TotalFee,
		SpbillCreateIP: params.SpbillCreateIP,
		AuthCode:       params.AuthCode,
		SignType:       params.SignType,
	}
	sign := GenerateSign(signStruct, sp.APIKeyV2)
	reqBody := renderData(
		params.AppID,
		params.AuthCode,
		params.Body,
		params.MchID,
		params.NonceStr,
		params.OutTradeNo,
		params.SpbillCreateIP,
		sign,
		params.DeviceInfo,
		params.TotalFee,
	)

	req, err := http.NewRequest("POST", MicroPayApi, bytes.NewBuffer([]byte(reqBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Debugf("wx pay resp: %s", string(body))

	// 解析返回的结构
	result := &PayResult{}
	err = xml.Unmarshal(body, &result)
	if err != nil {
		log.Errorf("Error decoding XML: %v\n", err)
		return nil, err
	}

	log.Debugf("Return Code: %s\n", result.ReturnCode)
	log.Debugf("Return Message: %s\n", result.ReturnMsg)
	return result, nil
}

func (sp *ScanPayClient) Pay(body, code string, fee int64) (*PayResult, error) {

	params := sp.buildRequestParams(body, code, fee)
	res, err := sp.sendRequest(params)
	if err != nil {
		log.Errorf("Error:%v", err)
		return nil, err
	}
	return res, nil
}

func NewScanPay(appID, mchID, apiKey, deviceInfo string) *ScanPayClient {
	return &ScanPayClient{
		appID,
		mchID,
		apiKey,
		deviceInfo,
	}
}
