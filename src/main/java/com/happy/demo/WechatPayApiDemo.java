package com.happy.demo;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 微信支付V3 API调用示例
 */
public class WechatPayApiDemo {
    private static final Logger log = LoggerFactory.getLogger(WechatPayApiDemo.class);

    // 配置参数（替换为你的实际信息）
    private static final String MCHID = "1616437306"; // 替换为真实商户号
    private static final String SERIAL_NO = "4D98AEF9383C7DB687AA9011190F68857195A0DD"; // 替换为真实证书序列号
    private static final String PRIVATE_KEY_PATH = "apiclient_test_key.pem"; // 私钥文件路径
    private static final String PRIVATE_KEY_P12_PATH = "apiclient_cert_1616437306.p12"; // 私钥文件路径
    private static final String WECHAT_PAY_API_HOST = "https://api.mch.weixin.qq.com";

    public static void main(String[] args) {
        // 1. 初始化私钥（全局只需要初始化一次）
        WechatPayV3P12SignUtil.initPrivateKeyFromP12(PRIVATE_KEY_P12_PATH,MCHID);

        // 2. 调用查询投诉接口示例
        String mchid = "";
        String result = queryComplaints(mchid);
        log.info("投诉查询结果：{}", result);
    }

    /**
     * 查询退款接口（GET请求示例）
     * 接口文档：https://pay.weixin.qq.com/doc/v3/merchant/4012533431
     * @param mchid 商户号
     * @return 接口返回结果
     */
    public static String queryComplaints(String mchid) {
        // 拼接请求路径（带Path参数）
        String urlPath = "/v3/merchant-service/complaints-v2?limit=5&offset=10&begin_date=2025-12-15&end_date=2026-01-01&complainted_mchid="+mchid;
        String fullUrl = WECHAT_PAY_API_HOST + urlPath;

        // 初始化HTTP客户端
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // 构建GET请求
            HttpGet httpGet = new HttpGet(fullUrl);

            // 生成签名并设置请求头
            String[] signResult = WechatPayV3P12SignUtil.generateSign("GET", urlPath, "", MCHID, SERIAL_NO);
            httpGet.setHeader("Authorization", signResult[0]);
            httpGet.setHeader("Content-Type", "application/json");
            httpGet.setHeader("Accept", "application/json");

            // 执行请求
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                HttpEntity entity = response.getEntity();
                String responseStr = EntityUtils.toString(entity, "UTF-8");

                // 处理响应
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == 200) {
                    log.info("接口调用成功");
                    return responseStr;
                } else {
                    log.error("接口调用失败，状态码：{}，响应内容：{}", statusCode, responseStr);
                    throw new RuntimeException("接口调用失败，状态码：" + statusCode);
                }
            }
        } catch (Exception e) {
            log.error("查询投诉接口调用异常", e);
            throw new RuntimeException("查询投诉失败", e);
        }
    }

}
