package wx

import (
	"os"
	"testing"
)

func TestScanPayClient_Pay(t *testing.T) {

	sp := NewScanPay(
		os.Getenv("APP_ID"),
		os.Getenv("MCH_ID"),
		os.Getenv("API_KEY"),
		os.Getenv("DEVICE"),
	)
	type fields struct {
		AppId      string
		MchID      string
		APIKeyV2   string
		DeviceInfo string
	}
	type args struct {
		body string
		code string
		fee  int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"test scan pay",
			fields{
				sp.AppId,
				sp.MchID,
				sp.APIKeyV2,
				sp.DeviceInfo,
			},
			args{
				"测试扫码支付-商品无名",
				"133966267395295060" +
					"" +
					"", // 手机支付二维码
				1, // 以分为单位，因此最小值是1
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := &ScanPayClient{
				AppId:      tt.fields.AppId,
				MchID:      tt.fields.MchID,
				APIKeyV2:   tt.fields.APIKeyV2,
				DeviceInfo: tt.fields.DeviceInfo,
			}
			if err := sp.Pay(tt.args.body, tt.args.code, tt.args.fee); (err != nil) != tt.wantErr {
				t.Errorf("Pay() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
