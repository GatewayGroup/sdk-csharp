// Here is an example of a gggpay sdk
using gggpay;

// initialize this configuration
// apiUrl GGGPay Api Url
// appId in developer settings : App Id
// key in developer settings : Key
// secret in developer settings : secret
// serverPubKey in developer settings : Server Public Key
// privateKey in developer settings : Private Key
gggpayCfg.init(apiUrl, appId, key, secret, serverPubKey, privateKey);

// Here is an example of a recharge 
// return recharge result: code=1,message=,transactionId=12817291,paymentUrl=https://www.xxxx...
Dictionary<String, String> rechargeResult = gggpaySdk.recharge("10001", 1.06M, "MYR", "TNG_MY", "GGGPay Test", "gggpay@hotmail.com", "0123456789");

// Here is an example of a withdraw
// return withdraw result: code=1,message=,transactionId=12817291
Dictionary<String, String> withdrawResult = gggpaySdk.withdraw("10013", 1.06M, "MYR", "CIMB", "GGGPay Test", "234719327401231","", "gggpay@hotmail.com", "0123456789");

// Here is an example of a detail
// return detail result:code=1,message=,transactionId=,amount=,fee=
Dictionary<String, String> detailResult = gggpaySdk.detail("10024", 2);

// out
Console.WriteLine("{" + string.Join(",", rechargeResult) + "}");
Console.WriteLine("{" + string.Join(",", withdrawResult) + "}");
Console.WriteLine("{" + string.Join(",", detailResult) + "}");
