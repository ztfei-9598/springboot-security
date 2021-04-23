package com.springboot.security.controller;

import com.google.code.kaptcha.Producer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * 返回验证码图片的接口
 *
 * @author zhangtengfei
 * @date 2021/4/23 16:06
 */
@RestController
public class VerifyCodeController {

    @Autowired
    Producer producer;

    @GetMapping("/vc.jpg")
    public void getVerifyCode(HttpServletResponse resp, HttpSession session) throws IOException {
        resp.setContentType("image/jpeg");
        String text = producer.createText();
        System.out.println("text: " + text);
        /**
         * 验证码设置到session中 之后进行比较
         */
        session.setAttribute("verify_code", text);
        BufferedImage image = producer.createImage(text);
        try (ServletOutputStream out = resp.getOutputStream()) {
            ImageIO.write(image, "jpg", out);
        }
    }
}
