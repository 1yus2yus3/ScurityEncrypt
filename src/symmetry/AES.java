package symmetry;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.stream.IntStream;

/**
 * @date: 2018/09/10 14:16
 * @description:
 */
public class AES {
    /**
     * 生成密钥
     * @throws Exception
     */
    public static byte[] initKey() throws Exception{
        //密钥生成器
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //初始化密钥生成器
        //默认128，获得无政策权限后可用192或256
        keyGen.init(128);
        //生成密钥
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 加密
     * @throws Exception
     */
    public static byte[] encryptAES(byte[] data, byte[] key) throws Exception{
        //恢复密钥
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        //Cipher完成加密
        Cipher cipher = Cipher.getInstance("AES");
        //根据密钥对cipher进行初始化
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //加密
        byte[] encrypt = cipher.doFinal(data);

        return encrypt;
    }
    /**
     * 解密
     */
    public static byte[] decryptAES(byte[] data, byte[] key) throws Exception{
        //恢复密钥生成器
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        //Cipher完成解密
        Cipher cipher = Cipher.getInstance("AES");
        //根据密钥对cipher进行初始化
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plain = cipher.doFinal(data);
        return plain;
    }

    public static void main(String[] args) throws Exception {

        String DATA = "THIS IS HELLO WORLD!";
        //获得密钥
        byte[] aesKey = initKey();
        System.out.println("AES 密钥 : "+Base64.encode(aesKey));
        //加密
        byte[] encrypt = encryptAES(DATA.getBytes(), aesKey);
        System.out.println(" AES 加密 : ");

        //解密
        byte[] plain = decryptAES(encrypt, aesKey);
        System.out.println(DATA + " AES 解密 : " + new String(plain));
    }
}