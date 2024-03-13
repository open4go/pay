package wx

import (
	"context"
	"crypto/rsa"
	"github.com/open4go/log"
	"github.com/open4go/req5rsp/rsp"
	"github.com/wechatpay-apiv3/wechatpay-go/core"
	"github.com/wechatpay-apiv3/wechatpay-go/core/option"
	"github.com/wechatpay-apiv3/wechatpay-go/services/payments/jsapi"
)

type Client struct {
	Ctx                        context.Context
	WxClient                   *core.Client
	AppID                      string
	MchID                      string
	MchCertificateSerialNumber string
	MchAPIv3Key                string
	Callback                   string
	MchPrivateKey              *rsa.PrivateKey
}

// NewClient 创建新的客户端
func NewClient(ctx context.Context,
	mchID string,
	mchCertificateSerialNumber string,
	mchAPIv3Key string,
	mchPrivateKey *rsa.PrivateKey) (*Client, error) {

	// 使用商户私钥等初始化 client，并使它具有自动定时获取微信支付平台证书的能力
	opts := []core.ClientOption{
		option.WithWechatPayAutoAuthCipher(
			mchID,
			mchCertificateSerialNumber,
			mchPrivateKey,
			mchAPIv3Key),
	}

	client, err := core.NewClient(ctx, opts...)
	if err != nil {
		log.Log().WithField("mchID", mchID).
			WithField("mchCertificateSerialNumber", mchCertificateSerialNumber).
			WithField("mchAPIv3Key", mchAPIv3Key).Error(err)
		return nil, err
	}

	c := &Client{
		Ctx:                        ctx,
		WxClient:                   client,
		MchID:                      mchID,
		MchCertificateSerialNumber: mchCertificateSerialNumber,
		MchAPIv3Key:                mchAPIv3Key,
		MchPrivateKey:              mchPrivateKey,
	}

	return c, nil
}

func (p *Client) Pay(amount int64, tradeNo, desc, payer string) (*rsp.WxPayPrepare, error) {
	//	下单
	svc2 := jsapi.JsapiApiService{Client: p.WxClient}
	// 得到prepay_id，以及调起支付所需的参数和签名
	resp, result, err := svc2.PrepayWithRequestPayment(p.Ctx,
		jsapi.PrepayRequest{
			Appid:       core.String(p.AppID),
			Mchid:       core.String(p.MchID),
			Description: core.String(desc),
			OutTradeNo:  core.String(tradeNo),
			Attach:      core.String("自定义数据说明"),
			NotifyUrl:   core.String(p.Callback),
			Amount: &jsapi.Amount{
				Total: core.Int64(amount),
			},
			Payer: &jsapi.Payer{
				Openid: core.String(payer),
			},
		},
	)

	if err != nil {
		log.Log().WithField("status", result.Response.StatusCode).
			WithField("rsp", resp).WithField("result", result).
			Info("call prepay failed")
		return nil, err
	}

	if result.Response.StatusCode != 200 {
		log.Log().WithField("status", result.Response.StatusCode).
			WithField("rsp", resp).WithField("result", result).
			Info("call prepay failed result.Response.StatusCode is no ok")
		return nil, err
	}
	log.Log().WithField("status", result.Response.StatusCode).
		WithField("rsp", resp).WithField("callback_url", p.Callback).
		Info("after prepay call")
	response := &rsp.WxPayPrepare{}
	response.PrepayID = *resp.PrepayId
	response.Appid = *resp.Appid
	response.NonceStr = *resp.NonceStr
	response.Package = *resp.Package
	response.Sign = *resp.PaySign
	response.PartnerID = "wx"
	response.Timestamp = *resp.TimeStamp
	response.OrderID = tradeNo
	return response, nil
}
