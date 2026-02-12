package com.happy.demo;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.UUID;

/**
 * 兼容P12证书的微信支付V3签名工具类
 */
public class WechatPayV3P12SignUtil {
    private static final Logger log = LoggerFactory.getLogger(WechatPayV3P12SignUtil.class);
    private static final String SIGN_ALGORITHMS = "SHA256withRSA";
    private static PrivateKey privateKey;

    /**
     * 从P12证书初始化私钥（替代之前的PEM文件初始化）
     * @param p12Path p12证书路径（如classpath:apiclient_cert.p12）
     * @param p12Password p12密码（微信支付默认是商户号）
     */
    public static void initPrivateKeyFromP12(String p12Path, String p12Password) {
        try (InputStream inputStream = WechatPayV3SignUtil.class.getClassLoader().getResourceAsStream(p12Path)) {
            if (inputStream == null) {
                throw new RuntimeException("P12证书文件不存在：" + p12Path);
            }
            // 加载PKCS12格式的密钥库
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(inputStream, p12Password.toCharArray());

            // 提取私钥（p12中默认的别名一般是"1"，若不对可自行调整）
            String alias = keyStore.aliases().nextElement();
            privateKey = (PrivateKey) keyStore.getKey(alias, p12Password.toCharArray());
            log.info("从P12证书提取私钥成功，别名：{}", alias);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            log.error("从P12证书提取私钥失败", e);
            throw new RuntimeException("P12证书初始化失败", e);
        }
    }

    // 以下generateSign方法与之前完全一致，无需修改
    public static String[] generateSign(String method, String url, String body, String mchid, String serialNo) {
        long timestamp = System.currentTimeMillis() / 1000;
        String nonceStr = UUID.randomUUID().toString().replace("-", "");

        String signStr = String.format("%s\n%s\n%d\n%s\n%s\n",
                method, url, timestamp, nonceStr, body);
        log.debug("构造的签名串：\n{}", signStr);

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

        String authorization = String.format("WECHATPAY2-SHA256-RSA2048 mchid=\"%s\",nonce_str=\"%s\",timestamp=\"%d\",serial_no=\"%s\",signature=\"%s\"",
                mchid, nonceStr, timestamp, serialNo, signature);

        return new String[]{authorization, String.valueOf(timestamp), nonceStr};
    }
}