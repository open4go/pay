package wx

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/open4go/r2id"
	"io/ioutil"
	"net/http"
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
	TotalFee       int    `xml:"total_fee,omitempty"`
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
	TotalFee       int    `xml:"total_fee,omitempty"`
	SpbillCreateIP string `xml:"spbill_create_ip,omitempty"`
	AuthCode       string `xml:"auth_code,omitempty"`
}

// GenerateSign 签名生成算法
func GenerateSign(signStruct SignStruct, apiKey string) string {
	var signSlice []string
	signSlice = append(signSlice, fmt.Sprintf("appid=%s", signStruct.AppID))
	//signSlice = append(signSlice, fmt.Sprintf("attach=%s", signStruct.Attach))
	signSlice = append(signSlice, fmt.Sprintf("body=%s", signStruct.Body))
	signSlice = append(signSlice, fmt.Sprintf("device_info=%s", signStruct.DeviceInfo))
	signSlice = append(signSlice, fmt.Sprintf("mch_id=%s", signStruct.MchID))
	signSlice = append(signSlice, fmt.Sprintf("nonce_str=%s", signStruct.NonceStr))
	//signSlice = append(signSlice, fmt.Sprintf("out_trade_no=%s", signStruct.OutTradeNo))
	//signSlice = append(signSlice, fmt.Sprintf("spbill_create_ip=%s", signStruct.SpbillCreateIP))
	//signSlice = append(signSlice, fmt.Sprintf("total_fee=%d", signStruct.TotalFee))
	//signSlice = append(signSlice, fmt.Sprintf("auth_code=%s", signStruct.AuthCode))
	//sort.Strings(signSlice)
	signStr := strings.Join(signSlice, "&") + "&key=" + apiKey

	fmt.Println("st-->", signStr)

	// 默认签名类型为MD5
	h := md5.New()
	h.Write([]byte(signStr))
	sign := hex.EncodeToString(h.Sum(nil))
	return strings.ToUpper(sign)
}

// BuildRequestParams 构建请求参数
func BuildRequestParams() RequestParams {
	return RequestParams{
		// TODO 当前的appid是小程序的，有可能是导致签名错误的原因
		AppID:          "wx265399cdd2753331",
		MchID:          "1525274081",
		DeviceInfo:     "macbook",
		NonceStr:       r2id.GenerateRandomString(32),
		Body:           "image形象店-深圳腾大- QQ公仔",
		OutTradeNo:     r2id.GenerateOutTradeNo(),
		TotalFee:       888,
		SpbillCreateIP: "8.8.8.8",
		// AuthCode 扫码枪读取的支付二维码
		AuthCode: "132882375849305673",
	}
}

// SendRequest 发送请求
func SendRequest(params RequestParams) error {
	// 生成签名
	signStruct := SignStruct{
		AppID:          params.AppID,
		MchID:          params.MchID,
		DeviceInfo:     params.DeviceInfo,
		NonceStr:       params.NonceStr,
		Body:           params.Body,
		Detail:         params.Detail,
		Attach:         params.Attach,
		OutTradeNo:     params.OutTradeNo,
		TotalFee:       params.TotalFee,
		SpbillCreateIP: params.SpbillCreateIP,
		AuthCode:       params.AuthCode,
	}
	sign := GenerateSign(signStruct, "Huanglijiguiliuluosifen199409277")

	// 设置请求参数
	params.Sign = sign
	params.SignType = "MD5" // 默认签名类型为MD5

	xmlBody, err := xml.Marshal(params)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", MicroPayApi, bytes.NewBuffer(xmlBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("---->", string(body), err)
	return nil
}

func Demo() {
	params := BuildRequestParams()
	err := SendRequest(params)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
