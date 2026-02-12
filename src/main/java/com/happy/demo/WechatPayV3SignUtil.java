package com.happy.demo;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.UUID;

/**
 * 微信支付V3签名工具类
 */
public class WechatPayV3SignUtil {
    private static final Logger log = LoggerFactory.getLogger(WechatPayV3SignUtil.class);
    // SHA256withRSA签名算法
    private static final String SIGN_ALGORITHMS = "SHA256withRSA";
    // 私钥对象（全局复用，避免重复加载）
    private static PrivateKey privateKey;

    /**
     * 初始化私钥（项目启动时调用一次即可）
     * @param privateKeyPath 私钥文件路径（如classpath:private_key.pem）
     */
    public static void initPrivateKey(String privateKeyPath) {
        try (InputStream inputStream = WechatPayV3SignUtil.class.getClassLoader().getResourceAsStream(privateKeyPath)) {
            if (inputStream == null) {
                throw new RuntimeException("私钥文件不存在：" + privateKeyPath);
            }
            // 读取私钥内容并去除首尾标识
            byte[] keyBytes = new byte[inputStream.available()];
            inputStream.read(keyBytes);
            String privateKeyStr = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            // 解析PKCS8格式私钥
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyStr));
            privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            log.info("微信支付私钥初始化成功");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("微信支付私钥初始化失败", e);
            throw new RuntimeException("私钥初始化失败", e);
        }
    }

    /**
     * 生成微信支付V3签名
     * @param method HTTP请求方法（GET/POST/PUT/DELETE）
     * @param url 请求路径（如/v3/merchant/xxxx）
     * @param body 请求体（GET请求传空字符串）
     * @param mchid 商户号
     * @param serialNo 商户证书序列号
     * @return 包含Authorization头、时间戳、随机串的数组：[0]Authorization, [1]timestamp, [2]nonceStr
     */
    public static String[] generateSign(String method, String url, String body, String mchid, String serialNo) {
        // 1. 生成时间戳和随机串
        long timestamp = System.currentTimeMillis() / 1000;
        String nonceStr = UUID.randomUUID().toString().replace("-", "");

        // 2. 构造签名串（严格按文档要求的格式，每行一个参数，最后必须换行）
        String signStr = String.format("%s\n%s\n%d\n%s\n%s\n",
                method, url, timestamp, nonceStr, body);
        log.debug("构造的签名串：\n{}", signStr);

        // 3. SHA256withRSA签名并Base64编码
        String signature;
        try {
            Signature sign = Signature.getInstance(SIGN_ALGORITHMS);
            sign.initSign(privateKey);
            sign.update(signStr.getBytes(StandardCharsets.UTF_8));
            byte[] signBytes = sign.sign();
            signature = Base64.encodeBase64String(signBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error("签名生成失败", e);
            throw new RuntimeException("签名生成失败", e);
        }

        // 4. 构造Authorization请求头
        String authorization = String.format("WECHATPAY2-SHA256-RSA2048 mchid=\"%s\",nonce_str=\"%s\",timestamp=\"%d\",serial_no=\"%s\",signature=\"%s\"",
                mchid, nonceStr, timestamp, serialNo, signature);

        return new String[]{authorization, String.valueOf(timestamp), nonceStr};
    }
}