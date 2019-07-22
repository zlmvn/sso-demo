package com.zjcy.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SsoDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoDemoApplication.class, args);
    }

    @RequestMapping("/")
    public String index() {
        return "index success";
    }

    @RequestMapping("/hello")
    public String hello() {
        return "hello welcome sso";
    }

    @RequestMapping("/security")
    public String security() {
        return "security";
    }

    @RequestMapping("/authorize")
    public String authorize() {
        return "安全验证";

    }
}
