// Here is an example of a gggpay sdk
using gggpay;

// docs : https://doc.gggpay.org/docs/quickstart/setup
// payment-method: https://doc.gggpay.org/docs/appendix/payment-method
// dictionary : https://doc.gggpay.org/docs/appendix/dictionary

// initialize this configuration
// verNo GGGPay Api Version Number, default: v1
// apiUrl GGGPay Api Url
// appId in developer settings : App Id
// key in developer settings : Key
// secret in developer settings : secret
// serverPubKey in developer settings : Server Public Key
// privateKey in developer settings : Private Key
gggpayCfg.init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey);

// Here is an example of a deposit 
// return deposit result: code=1,message=,transactionId=12817291,paymentUrl=https://www.xxxx...
Dictionary<String, String> depositResult = gggpaySdk.deposit("10001", 1.06M, "MYR", "TNG_MY", "GGGPay Test", "gggpay@hotmail.com", "0123456789");
Console.WriteLine("{" + string.Join(",", depositResult) + "}");

// Here is an example of a withdraw
// return withdraw result: code=1,message=,transactionId=12817291
Dictionary<String, String> withdrawResult = gggpaySdk.withdraw("10013", 1.06M, "MYR", "CIMB", "GGGPay Test", "234719327401231","", "gggpay@hotmail.com", "0123456789");
Console.WriteLine("{" + string.Join(",", withdrawResult) + "}");

// Here is an example of a detail
// return detail result:code=1,message=,transactionId=,amount=,fee=
Dictionary<String, String> detailResult = gggpaySdk.detail("10854", 1);
Console.WriteLine("{" + string.Join(",", detailResult) + "}");

// Decrypt the encrypted information in the callback
String jsonstr = gggpaySdk.symDecrypt("encryptedData .........");
Console.WriteLine("{" + string.Join(",", jsonstr) + "}");