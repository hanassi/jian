[+] /home/ec2-user/app/jian/src/main/java/com/example/jian/controller/CustomErrorController.java
package com.example.jian.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    // 모든 에러는 /error로 매핑됨
    @RequestMapping("/error")
    public String handleError() {
        return "error/customErrorPage"; // templates/error/customErrorPage.html
    }
}

